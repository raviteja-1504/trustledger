/**
 * Dockerfile misconfiguration detectors — Container security phase.
 *
 * Same regex/line-window style as iacTerraform.ts/iacKubernetes.ts, not a
 * real Dockerfile parser. Every check no-ops unless isDockerfileContent()
 * confirms the file actually contains a FROM instruction — required because
 * ingestion (scannableFiles.ts's isDockerfilePath) only narrows by filename
 * convention, not content.
 *
 * Multi-stage builds: findDockerfileRunsAsRoot scopes itself to the LAST
 * build stage (the one that actually ships) via lastStageStart() below,
 * since a USER instruction in an earlier throwaway build stage says nothing
 * about the final image. Every other check here intentionally does NOT
 * stage-scope itself (an unpinned base image, a remote ADD, a piped shell
 * script, or a baked-in secret in ANY stage is worth flagging on its own
 * terms, not just in the final stage) — a deliberate, check-by-check
 * decision, not an oversight.
 *
 * Registered via detectorRegistry (see containerDetectors.ts), not
 * scanner.ts's core inline array.
 */

import type { ScanIndicator } from "./scanner";

const FROM_RE = /^\s*FROM\s+\S+/i;

export function isDockerfileContent(content: string): boolean {
  return content.split("\n").some(line => FROM_RE.test(line));
}

/** Index of the LAST `FROM` line — multi-stage builds ship only their final
 * stage, so a hardening check scoped to "what actually ships" should only
 * look from there onward. */
function lastStageStart(lines: string[]): number {
  let start = 0;
  lines.forEach((line, i) => { if (FROM_RE.test(line)) start = i; });
  return start;
}

// ── container-runs-as-root ───────────────────────────────────────────────

const USER_RE = /^\s*USER\s+(\S+)/i;

export function findDockerfileRunsAsRoot(content: string): ScanIndicator[] {
  const lines = content.split("\n");
  if (!lines.some(l => FROM_RE.test(l))) return [];
  const stageStart = lastStageStart(lines);
  const stageLines = lines.slice(stageStart);

  let lastUserLine = -1;
  let lastUserValue = "";
  stageLines.forEach((line, i) => {
    const m = USER_RE.exec(line);
    if (m) { lastUserLine = stageStart + i; lastUserValue = m[1]; }
  });

  if (lastUserLine === -1) {
    return [{
      id: "container-runs-as-root", label: "Container Runs As Root", severity: "medium", line: stageStart + 1, confidence: 70,
      detail: "No USER instruction found in the final build stage — the container runs as root (UID 0) by default. Add a USER instruction before the final CMD/ENTRYPOINT.",
    }];
  }
  const normalized = lastUserValue.split(":")[0];
  if (normalized === "root" || normalized === "0") {
    return [{
      id: "container-runs-as-root", label: "Container Runs As Root", severity: "medium", line: lastUserLine + 1, confidence: 85,
      detail: `USER ${lastUserValue} explicitly runs the final build stage as root — switch to a non-root user.`,
    }];
  }
  return [];
}

// ── container-unpinned-base-image ────────────────────────────────────────

const FROM_IMAGE_RE = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+\S+)?/i;
const AS_RE = /\s+AS\s+(\S+)/i;

/** Real registry image references from every FROM line -- `scratch` and
 * references to an earlier AS-aliased build stage (not a real registry
 * image) are excluded. Shared with dependencyScan.ts's base-image CVE
 * lookup (Decision 2) so both features agree on what counts as "a base
 * image this Dockerfile actually pulls," not two independently-maintained
 * extraction regexes. One entry per FROM line, in file order (a
 * multi-stage build's several base images are ALL returned, not just the
 * final stage's -- unlike findDockerfileRunsAsRoot, which deliberately
 * scopes to the final stage only, every stage's base image is equally
 * real and equally worth a CVE lookup). */
export function extractFromImageRefs(content: string): Array<{ ref: string; line: number }> {
  const lines = content.split("\n");
  if (!lines.some(l => FROM_RE.test(l))) return [];

  const stageNames = new Set<string>();
  lines.forEach(line => {
    const m = AS_RE.exec(line);
    if (m) { const stageName = m[1]; stageNames.add(stageName.toLowerCase()); }
  });

  const refs: Array<{ ref: string; line: number }> = [];
  lines.forEach((line, i) => {
    const m = FROM_IMAGE_RE.exec(line);
    if (!m) return;
    const ref = m[1];
    if (ref.toLowerCase() === "scratch") return;
    if (stageNames.has(ref.toLowerCase())) return;
    refs.push({ ref, line: i + 1 });
  });
  return refs;
}

export function findDockerfileUnpinnedBaseImage(content: string): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  extractFromImageRefs(content).forEach(({ ref, line: i }) => {
    const afterLastSlash = ref.split("/").pop() ?? ref;
    const hasPin = afterLastSlash.includes(":") || afterLastSlash.includes("@");
    if (!hasPin) {
      found.push({
        id: "container-unpinned-base-image", label: "Unpinned Base Image", severity: "low", line: i, confidence: 65,
        detail: `Base image '${ref}' has no tag or digest — defaults to ':latest', a mutable reference that can silently change what gets built.`,
      });
    } else if (ref.endsWith(":latest")) {
      found.push({
        id: "container-unpinned-base-image", label: "Unpinned Base Image", severity: "low", line: i, confidence: 65,
        detail: `Base image '${ref}' is pinned to the mutable ':latest' tag — pin to a specific version or digest instead.`,
      });
    }
  });
  return found;
}

// ── container-add-remote-url ─────────────────────────────────────────────

const ADD_REMOTE_RE = /^\s*ADD\s+(?:--\S+\s+)*(https?:\/\/\S+)/i;

export function findDockerfileRemoteAdd(content: string): ScanIndicator[] {
  if (!isDockerfileContent(content)) return [];
  return content.split("\n").flatMap((line, i) => {
    const m = ADD_REMOTE_RE.exec(line);
    return m ? [{
      id: "container-add-remote-url", label: "ADD From Remote URL", severity: "medium" as const, line: i + 1, confidence: 80,
      detail: `ADD fetches '${m[1]}' directly into the image with no integrity check — use COPY with a locally-verified file, or curl/wget with checksum verification in a RUN step instead.`,
    }] : [];
  });
}

// ── container-piped-shell-exec ───────────────────────────────────────────

const PIPED_SHELL_RE = /^\s*RUN\s+.*\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i;

export function findDockerfilePipedShellExec(content: string): ScanIndicator[] {
  if (!isDockerfileContent(content)) return [];
  return content.split("\n").flatMap((line, i) => PIPED_SHELL_RE.test(line) ? [{
    id: "container-piped-shell-exec", label: "Unverified Remote Script Execution", severity: "high" as const, line: i + 1, confidence: 80,
    detail: "Pipes a remote script directly into a shell (curl|sh / wget|bash) with no integrity verification — download the script first, verify its checksum/signature, then execute it.",
  }] : []);
}

// ── container-hardcoded-secret ───────────────────────────────────────────

const SECRET_NAME_RE = /(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)/i;
const ENV_ARG_ASSIGN_RE = /^\s*(ENV|ARG)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=?\s*["']?([^\s"']{4,})["']?\s*$/i;

export function findDockerfileHardcodedSecret(content: string): ScanIndicator[] {
  if (!isDockerfileContent(content)) return [];
  const found: ScanIndicator[] = [];
  content.split("\n").forEach((line, i) => {
    const m = ENV_ARG_ASSIGN_RE.exec(line);
    if (!m) return;
    const [, instr, name, value] = m;
    if (!SECRET_NAME_RE.test(name)) return;
    if (/^\$\{?\w+\}?$/.test(value)) return; // a variable reference, not a literal value
    found.push({
      id: "container-hardcoded-secret", label: "Hardcoded Secret in Dockerfile", severity: "high", line: i + 1, confidence: 75,
      detail: `${instr.toUpperCase()} ${name} bakes a credential-shaped value directly into the image/build history — pass secrets via BuildKit's --secret mount or a runtime environment variable instead.`,
    });
  });
  return found;
}

// ── container-sensitive-file-copy ────────────────────────────────────────

const SENSITIVE_COPY_RE = /^\s*(?:COPY|ADD)\s+(?:--\S+\s+)*(\S*(?:\.env\S*|\.pem|\.key|id_rsa\S*|\.p12|\.pfx|credentials(?:\.json)?)\S*)/i;

export function findDockerfileSensitiveCopy(content: string): ScanIndicator[] {
  if (!isDockerfileContent(content)) return [];
  return content.split("\n").flatMap((line, i) => {
    const m = SENSITIVE_COPY_RE.exec(line);
    return m ? [{
      id: "container-sensitive-file-copy", label: "Sensitive File Copied Into Image", severity: "high" as const, line: i + 1, confidence: 70,
      detail: `Copies '${m[1]}' into the image — credential/key files baked into a layer persist in the image history even if later deleted. Add a .dockerignore entry and pass secrets at runtime instead.`,
    }] : [];
  });
}

// ── container-exposed-sensitive-port ─────────────────────────────────────

const EXPOSE_RE = /^\s*EXPOSE\s+(\d+)/i;
const SENSITIVE_PORTS: Record<string, string> = { "22": "SSH", "23": "Telnet", "3389": "RDP" };

export function findDockerfileExposedSensitivePort(content: string): ScanIndicator[] {
  if (!isDockerfileContent(content)) return [];
  return content.split("\n").flatMap((line, i) => {
    const m = EXPOSE_RE.exec(line);
    const label = m ? SENSITIVE_PORTS[m[1]] : undefined;
    return m && label ? [{
      id: "container-exposed-sensitive-port", label: "Sensitive Port Exposed", severity: "low" as const, line: i + 1, confidence: 60,
      detail: `EXPOSE ${m[1]} advertises the ${label} port from the container — verify this is intentional; management ports like this are rarely meant to be reachable from outside the host.`,
    }] : [];
  });
}
