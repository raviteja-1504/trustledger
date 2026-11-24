/**
 * docker-compose.yml misconfiguration detectors — Container security phase.
 *
 * Same regex/line-window style as iacKubernetes.ts, not a real YAML parser
 * (no YAML parsing dependency exists in this repo — see iacKubernetes.ts's
 * own docblock for why that's a deliberate, not accidental, choice). Every
 * check no-ops unless isComposeContent() confirms the file has a top-level
 * `services:` key — the one key every Compose file is required to have —
 * required because ingestion (scannableFiles.ts's isDockerComposePath) only
 * narrows by filename convention, not content.
 *
 * findComposeDockerSocketMount has no Kubernetes equivalent: a Kubernetes
 * pod spec has no direct analog of "bind-mount the container runtime's own
 * control socket into a container" the way a Compose/Docker volume does, so
 * this is a genuinely new check, not a port of an existing one.
 *
 * Registered via detectorRegistry (see containerDetectors.ts), not
 * scanner.ts's core inline array.
 */

import type { ScanIndicator } from "./scanner";

export function isComposeContent(content: string): boolean {
  return /^services:\s*$/m.test(content);
}

// ── container-compose-privileged ─────────────────────────────────────────

const PRIVILEGED_RE = /^\s*privileged:\s*true\b/;

export function findComposePrivileged(content: string): ScanIndicator[] {
  if (!isComposeContent(content)) return [];
  return content.split("\n").flatMap((line, i) => PRIVILEGED_RE.test(line) ? [{
    id: "container-compose-privileged", label: "Privileged Container", severity: "critical" as const, line: i + 1, confidence: 90,
    detail: "Service runs in privileged mode, granting it near-full access to the host — remove `privileged: true` and grant specific capabilities instead.",
  }] : []);
}

// ── container-compose-docker-socket-mount ────────────────────────────────

const DOCKER_SOCK_RE = /\/var\/run\/docker\.sock/;

// Images / service names that require docker.sock by design and whose mount
// is therefore intentional, not a misconfiguration. Suppressed entirely.
const DOCKER_MANAGER_IMAGE_RE = /\b(?:localstack(?:\/localstack)?|portainer(?:\/portainer)?|rancher(?:\/rancher)?|watchtower|dokku|dagger(?:io\/engine)?|jenkins(?:\/jenkins)?|teamcity|buildkite[/-]agent|gitlab[/-]runner|drone(?:\/drone)?|harbor[/-](?:core|registry|jobservice)|verdaccio|nexus|ctop|lazydocker|docker[/-]gc|docker[/-]registry|docker\.io\/library\/docker|dind|docker:dind|gcr\.io\/kaniko|moby(?:\/buildkit)?|buildkitd|earthly(?:\/earthly)?)\b/i;
// Service names that imply a CI/build role and intentionally need docker.sock
const DOCKER_MANAGER_SERVICE_NAME_RE = /\b(?:localstack|docker|dind|ci|runner|build|agent|registry|portainer|rancher|watchtower)\b/i;

/** Walk backward from line `i` through `lines` to find the service's image
 *  value and inferred service name, stopping once we reach a dedent that
 *  indicates a sibling service or the top-level `services:` key. */
function composeServiceContextAt(lines: string[], i: number): { image: string; serviceName: string } {
  const mountIndent = (lines[i].match(/^(\s*)/)?.[1].length) ?? 0;
  let image = "";
  let serviceName = "";
  for (let j = i - 1; j >= 0 && j >= i - 40; j--) {
    const l = lines[j];
    const indent = (l.match(/^(\s*)/)?.[1].length) ?? 0;
    // image: localstack/localstack
    if (!image && /^\s*image\s*:\s*\S/.test(l)) {
      image = (l.match(/^\s*image\s*:\s*["']?([^\s"'#]+)/) ?? [])[1] ?? "";
    }
    // Service name: a non-empty YAML key at indent 2-4 that is a parent of the volume line
    if (!serviceName && indent < mountIndent - 4 && /^\s+\w[\w-]*\s*:\s*$/.test(l)) {
      serviceName = (l.match(/^\s+(\w[\w-]*)\s*:/) ?? [])[1] ?? "";
    }
    // Once we've found both or hit the services: key, stop
    if (l.trim() === "services:" || (image && serviceName)) break;
  }
  return { image, serviceName };
}

export function findComposeDockerSocketMount(content: string): ScanIndicator[] {
  if (!isComposeContent(content)) return [];
  const lines = content.split("\n");
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!DOCKER_SOCK_RE.test(line)) continue;
    // Skip commented-out mounts
    if (/^\s*#/.test(line)) continue;
    const { image, serviceName } = composeServiceContextAt(lines, i);
    // Known Docker management tools that legitimately need docker.sock
    if (DOCKER_MANAGER_IMAGE_RE.test(image) || DOCKER_MANAGER_SERVICE_NAME_RE.test(serviceName)) continue;
    found.push({
      id: "container-compose-docker-socket-mount", label: "Docker Socket Mounted Into Container", severity: "critical" as const, line: i + 1, confidence: 90,
      detail: "Mounts the host's Docker socket into the container — this grants the container root-equivalent control over the host (it can launch new privileged containers, read any file via a bind mount, etc). Avoid mounting docker.sock unless this service is a trusted, isolated CI/deployment agent.",
    });
  }
  return found;
}

// ── container-compose-host-namespace ─────────────────────────────────────

const HOST_NAMESPACE_MODE_RE = /^\s*(network_mode|pid|ipc):\s*["']?host["']?\s*$/i;

export function findComposeHostNamespace(content: string): ScanIndicator[] {
  if (!isComposeContent(content)) return [];
  const found: ScanIndicator[] = [];
  content.split("\n").forEach((line, i) => {
    const m = HOST_NAMESPACE_MODE_RE.exec(line);
    if (m) {
      const key = m[1];
      found.push({
        id: "container-compose-host-namespace", label: "Host Namespace Access", severity: "high", line: i + 1, confidence: 85,
        detail: `Service shares the host's ${key.toLowerCase() === "network_mode" ? "network" : key} namespace, weakening the isolation between this container and the node it runs on.`,
      });
    }
  });
  return found;
}

// ── container-compose-dangerous-capability ───────────────────────────────

const CAP_ADD_HEADER_RE = /^\s*cap_add:\s*$/i;
const DANGEROUS_CAP_RE = /^\s*-\s*["']?(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE)["']?\s*$/i;

export function findComposeDangerousCapability(content: string): ScanIndicator[] {
  if (!isComposeContent(content)) return [];
  const lines = content.split("\n");
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = DANGEROUS_CAP_RE.exec(lines[i]);
    if (!m) continue;
    const windowStart = Math.max(0, i - 5);
    if (!lines.slice(windowStart, i).some(l => CAP_ADD_HEADER_RE.test(l))) continue;
    found.push({
      id: "container-compose-dangerous-capability", label: "Dangerous Linux Capability", severity: "high", line: i + 1, confidence: 80,
      detail: `Service adds the '${m[1]}' capability, expanding its privileges well beyond the container default set.`,
    });
  }
  return found;
}

// ── container-compose-hardcoded-secret ───────────────────────────────────

const ENVIRONMENT_HEADER_RE = /^\s*environment:\s*$/i;
const ENV_ITEM_RE = /^\s*(?:-\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*["']?(\S+?)["']?\s*$/;
const SECRET_NAME_RE = /(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)/i;

export function findComposeHardcodedSecret(content: string): ScanIndicator[] {
  if (!isComposeContent(content)) return [];
  const lines = content.split("\n");
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = ENV_ITEM_RE.exec(lines[i]);
    if (!m) continue;
    const [, name, value] = m;
    if (!SECRET_NAME_RE.test(name)) continue;
    if (/^\$\{?\w+\}?$/.test(value)) continue; // a variable reference, not a literal value
    const windowStart = Math.max(0, i - 10);
    if (!lines.slice(windowStart, i).some(l => ENVIRONMENT_HEADER_RE.test(l))) continue;
    found.push({
      id: "container-compose-hardcoded-secret", label: "Hardcoded Secret in Compose File", severity: "high", line: i + 1, confidence: 70,
      detail: `environment: ${name} sets a credential-shaped value directly in the compose file — use env_file, Docker secrets, or an external secret manager instead.`,
    });
  }
  return found;
}

// ── container-compose-unpinned-image ─────────────────────────────────────

const IMAGE_RE = /^\s*image:\s*["']?([^\s"']+)["']?\s*$/;

export function findComposeUnpinnedImage(content: string): ScanIndicator[] {
  if (!isComposeContent(content)) return [];
  const lines = content.split("\n");
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = IMAGE_RE.exec(lines[i]);
    if (!m) continue;
    const ref = m[1];
    const afterLastSlash = ref.split("/").pop() ?? ref;
    const hasPin = afterLastSlash.includes(":") || afterLastSlash.includes("@");
    if (!hasPin) {
      found.push({
        id: "container-compose-unpinned-image", label: "Unpinned Container Image", severity: "low", line: i + 1, confidence: 65,
        detail: `Image '${ref}' has no tag or digest — defaults to ':latest', a mutable reference that can silently change what gets deployed.`,
      });
    } else if (ref.endsWith(":latest")) {
      found.push({
        id: "container-compose-unpinned-image", label: "Unpinned Container Image", severity: "low", line: i + 1, confidence: 65,
        detail: `Image '${ref}' is pinned to the mutable ':latest' tag — pin to a specific version or digest instead.`,
      });
    }
  }
  return found;
}
