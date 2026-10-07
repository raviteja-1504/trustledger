/**
 * Container hardening checks beyond containerDockerfile.ts / containerCompose.ts: end-of-life base images,
 * TLS verification turned off during the build, world-writable files, disabled seccomp/AppArmor, and
 * datastore ports published on every host interface.
 *
 * End-of-life is judged against the scan date, from each project's published support schedule, so an image
 * that was fine last year is reported once its release stops receiving security fixes.
 */
import type { ScanIndicator } from "./scanner";
import { appsecHit } from "./appsecRules";
import { extractFromImageRefs, isDockerfileContent } from "./containerDockerfile";
import { isComposeContent } from "./containerCompose";
import { parseYamlDocuments, get, items, entries, str, type CNode } from "./iac/configTree";

/** End of security support (YYYY-MM-DD), from each project's official release schedule. */
const EOL: Record<string, Record<string, string>> = {
  node: { "10": "2021-04-30", "12": "2022-04-30", "13": "2020-06-01", "14": "2023-04-30", "15": "2021-06-01", "16": "2023-09-11", "17": "2022-06-01", "18": "2025-04-30", "19": "2023-06-01", "20": "2026-04-30", "21": "2024-06-01", "22": "2027-04-30", "23": "2025-06-01", "24": "2028-04-30" },
  python: { "2": "2020-01-01", "2.7": "2020-01-01", "3.5": "2020-09-30", "3.6": "2021-12-23", "3.7": "2023-06-27", "3.8": "2024-10-07", "3.9": "2025-10-31", "3.10": "2026-10-31", "3.11": "2027-10-31", "3.12": "2028-10-31" },
  php: { "5": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30", "7.3": "2021-12-06", "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31" },
  ruby: { "2.5": "2021-03-31", "2.6": "2022-03-31", "2.7": "2023-03-31", "3.0": "2024-04-23", "3.1": "2025-03-26", "3.2": "2026-03-31" },
  alpine: { "3.12": "2022-05-01", "3.13": "2022-11-01", "3.14": "2023-05-01", "3.15": "2023-11-01", "3.16": "2024-05-23", "3.17": "2024-11-22", "3.18": "2025-05-09", "3.19": "2025-11-01", "3.20": "2026-04-01", "3.21": "2026-11-01" },
  ubuntu: { "14.04": "2019-04-30", "16.04": "2021-04-30", "18.04": "2023-05-31", "20.04": "2025-05-31", "22.04": "2027-06-01", "24.04": "2029-05-31" },
  debian: { "8": "2020-06-30", "jessie": "2020-06-30", "9": "2022-06-30", "stretch": "2022-06-30", "10": "2024-06-30", "buster": "2024-06-30", "11": "2026-08-31", "bullseye": "2026-08-31", "12": "2028-06-30", "bookworm": "2028-06-30" },
  centos: { "6": "2020-11-30", "7": "2024-06-30", "8": "2021-12-31" },
};
/** Debian codenames that appear as variant suffixes of language images (node:16-buster, python:3.9-stretch). */
const DEBIAN_CODENAMES = ["jessie", "stretch", "buster", "bullseye", "bookworm"];

export interface EolVerdict { product: string; version: string; eol: string }

/** The end-of-life release a FROM reference uses, if it is past its end of support on `now`. */
export function eolOf(ref: string, now: Date = new Date()): EolVerdict | null {
  const noDigest = ref.split("@")[0];
  const slash = noDigest.lastIndexOf("/");
  const repoAndTag = noDigest.slice(slash + 1);
  const [repo, tag = ""] = repoAndTag.split(":");
  const image = repo.toLowerCase();
  const product = image === "openjdk" ? null : image in EOL ? image : null;
  const candidates: EolVerdict[] = [];
  if (product && tag) {
    const table = EOL[product];
    const t = tag.toLowerCase();
    // Longest matching version key: "3.10" before "3.1", "16" from "16-alpine".
    const keys = Object.keys(table).sort((a, b) => b.length - a.length);
    const key = keys.find(k => t === k || t.startsWith(`${k}.`) || t.startsWith(`${k}-`) || t.startsWith(`${k}_`));
    if (key) candidates.push({ product, version: key, eol: table[key] });
  }
  // A language image on an EOL Debian base: node:18-buster.
  const code = DEBIAN_CODENAMES.find(c => new RegExp(`(?:^|[-_.])${c}(?:$|[-_.])`).test(tag.toLowerCase()));
  if (code && product !== "debian") candidates.push({ product: "debian", version: code, eol: EOL.debian[code] });
  const today = now.toISOString().slice(0, 10);
  const expired = candidates.filter(c => c.eol <= today).sort((a, b) => a.eol.localeCompare(b.eol));
  return expired[0] ?? null;
}

export function findDockerfileEolBaseImage(content: string, now: Date = new Date()): ScanIndicator[] {
  if (!isDockerfileContent(content)) return [];
  const out: ScanIndicator[] = [];
  for (const { ref, line } of extractFromImageRefs(content)) {
    const v = eolOf(ref, now);
    if (!v) continue;
    const years = (now.getTime() - Date.parse(v.eol)) / (365.25 * 24 * 3600 * 1000);
    out.push(appsecHit("container-eol-base-image", line,
      `${ref} uses ${v.product} ${v.version}, out of security support since ${v.eol}.`,
      { confidence: 90, severity: years >= 1 ? "high" : "medium" }));
  }
  return out;
}

const INSECURE_DOWNLOAD_RE = /\bcurl\b[^\n]*\s(?:-k|--insecure)\b|\bcurl\b[^\n]*\s-[a-zA-Z]*k[a-zA-Z]*\b|\bwget\b[^\n]*--no-check-certificate|\bpip3?\b[^\n]*--trusted-host\b|\bnpm\s+config\s+set\s+strict-ssl\s+false|\bgit\s+config\b[^\n]*http\.sslVerify\s+false|GIT_SSL_NO_VERIFY=(?:1|true)|NODE_TLS_REJECT_UNAUTHORIZED=0|\byarn\s+config\s+set\s+strict-ssl\s+false/i;
const WORLD_WRITABLE_RE = /\bchmod\s+(?:-R\s+)?(?:0?777|a\+w|o\+w)\b/;

/** Dockerfile instruction lines joined across `\` continuations, with the line each starts on. */
function instructions(content: string): Array<{ text: string; line: number }> {
  const out: Array<{ text: string; line: number }> = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const start = i;
    // Test/strip only the newest physical line and join once: re-testing and re-copying the growing text on every
    // continuation was quadratic for a long `RUN a \` chain.
    const parts: string[] = [];
    let cur = lines[i];
    while (/\\\s*$/.test(cur) && i + 1 < lines.length) { parts.push(cur.replace(/\\\s*$/, " ")); cur = lines[++i]; }
    parts.push(cur);
    out.push({ text: parts.join(""), line: start + 1 });
  }
  return out;
}

export function findDockerfileBuildRisks(content: string): ScanIndicator[] {
  if (!isDockerfileContent(content)) return [];
  const out: ScanIndicator[] = [];
  for (const ins of instructions(content)) {
    if (!/^\s*(?:RUN|ENV|ARG)\b/i.test(ins.text)) continue;
    if (INSECURE_DOWNLOAD_RE.test(ins.text)) {
      out.push(appsecHit("container-insecure-download", ins.line, "A build step disables TLS certificate verification.", { confidence: 90 }));
    }
    if (/^\s*RUN\b/i.test(ins.text) && WORLD_WRITABLE_RE.test(ins.text)) {
      out.push(appsecHit("container-world-writable", ins.line, "A build step makes files world-writable.", { confidence: 90 }));
    }
  }
  return out;
}

const DATASTORE_PORTS: Record<number, string> = { 5432: "PostgreSQL", 3306: "MySQL", 1433: "SQL Server", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 5984: "CouchDB", 11211: "Memcached", 9042: "Cassandra", 8086: "InfluxDB", 5672: "RabbitMQ", 2379: "etcd" };

/** The published (host) side of a Compose port mapping, or null when it binds only to loopback / isn't published. */
function publishedOnAllInterfaces(spec: string): number | null {
  const s = spec.replace(/\/(?:tcp|udp)$/, "");
  const parts = s.split(":");
  if (parts.length < 2) return null;                                  // "5432" alone: container port, random host port -- still exposed
  const container = Number(parts[parts.length - 1]);
  const hostIp = parts.length === 3 ? parts[0] : "";
  if (/^(?:127\.\d+\.\d+\.\d+|localhost|\[?::1\]?)$/.test(hostIp)) return null;
  return container;
}

export function findComposeRuntimeRisks(content: string): ScanIndicator[] {
  if (!isComposeContent(content)) return [];
  const out: ScanIndicator[] = [];
  for (const doc of parseYamlDocuments(content)) {
    for (const svc of entries(get(doc, "services"))) {
      const s: CNode = svc.node;
      for (const opt of items(get(s, "security_opt"))) {
        const v = str(opt) ?? "";
        if (/^(?:seccomp|apparmor)[:=]unconfined$/i.test(v.replace(/\s/g, ""))) {
          out.push(appsecHit("container-compose-security-opt-disabled", opt.line, `Service '${svc.key}' sets security_opt ${v}.`, { confidence: 95 }));
        }
      }
      for (const p of items(get(s, "ports"))) {
        const spec = p.kind === "scalar" ? p.value : p.kind === "map" && str(get(p, "published")) ? `${str(get(p, "host_ip")) ?? ""}:${str(get(p, "published"))}:${str(get(p, "target"))}`.replace(/^:/, "") : "";
        const port = spec ? publishedOnAllInterfaces(spec) : null;
        if (port && DATASTORE_PORTS[port]) {
          out.push(appsecHit("container-compose-exposed-datastore", p.line, `Service '${svc.key}' publishes ${DATASTORE_PORTS[port]} (${spec}) on every host interface.`, { confidence: 85 }));
        }
      }
    }
  }
  return out;
}
