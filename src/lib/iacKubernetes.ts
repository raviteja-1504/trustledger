/**
 * Kubernetes manifest misconfiguration detectors — IaC security Phase 3.
 *
 * Same regex/line-window style as iacTerraform.ts, not a real YAML parser.
 * Every check below no-ops unless isKubernetesManifest() confirms the file
 * actually looks like a K8s manifest (top-level apiVersion + kind) --
 * required because ingestion (scannableFiles.ts's isLikelyK8sManifestPath)
 * only narrows by path/name convention, not content, so a false-positive
 * intake match (an unrelated YAML file that happens to live under a
 * "deploy/" directory) still shouldn't fire any of these.
 *
 * Deliberately scoped to explicit-bad-value checks only, never
 * absence-of-a-hardening-flag (e.g. flags `runAsUser: 0` present, never
 * "no runAsNonRoot: true found anywhere") -- with no real per-pod/
 * per-container block scoping in this first pass, an absence check would
 * risk misattributing across a multi-container manifest (flagging pod A for
 * a hardening flag that's actually set on container B, just elsewhere in
 * the same file). A future phase with real per-container scoping could
 * safely add absence checks; this one can't yet.
 *
 * Accepted simplification for multi-document (`---`-separated) files: if
 * ANY document in the file looks like a K8s manifest, the WHOLE file is
 * treated as inspectable, rather than scoping each check to its own
 * document. Documented, not silently assumed.
 *
 * Registered via detectorRegistry (see iacDetectors.ts), not scanner.ts's
 * core inline array.
 */

import type { ScanIndicator } from "./scanner";

export function isKubernetesManifest(content: string): boolean {
  return /^apiVersion:\s*\S+/m.test(content) && /^kind:\s*\S+/m.test(content);
}

// ── iac-privileged-container ─────────────────────────────────────────────────

const PRIVILEGED_RE = /^\s*privileged:\s*true\b/;

export function findPrivilegedContainer(content: string): ScanIndicator[] {
  if (!isKubernetesManifest(content)) return [];
  return content.split("\n").flatMap((line, i) => PRIVILEGED_RE.test(line) ? [{
    id: "iac-privileged-container", label: "Privileged Container", severity: "critical" as const, line: i + 1, confidence: 90,
    detail: "Container runs in privileged mode, granting it near-full access to the host — remove `privileged: true` and grant specific capabilities instead.",
  }] : []);
}

// ── iac-container-run-as-root ─────────────────────────────────────────────────

const RUN_AS_ROOT_RE = /^\s*(?:runAsUser:\s*0\b|runAsNonRoot:\s*false\b)/;

export function findContainerRunAsRoot(content: string): ScanIndicator[] {
  if (!isKubernetesManifest(content)) return [];
  return content.split("\n").flatMap((line, i) => RUN_AS_ROOT_RE.test(line) ? [{
    id: "iac-container-run-as-root", label: "Container Runs As Root", severity: "medium" as const, line: i + 1, confidence: 80,
    detail: "Container security context explicitly allows running as root (UID 0) — set runAsNonRoot: true and a non-zero runAsUser.",
  }] : []);
}

// ── iac-host-namespace-access ─────────────────────────────────────────────────

const HOST_NAMESPACE_RE = /^\s*host(Network|PID|IPC):\s*true\b/;

export function findHostNamespaceAccess(content: string): ScanIndicator[] {
  if (!isKubernetesManifest(content)) return [];
  const found: ScanIndicator[] = [];
  content.split("\n").forEach((line, i) => {
    const m = HOST_NAMESPACE_RE.exec(line);
    if (m) found.push({
      id: "iac-host-namespace-access", label: "Host Namespace Access", severity: "high", line: i + 1, confidence: 85,
      detail: `Pod shares the host's ${m[1]} namespace, weakening the isolation between this container and the node it runs on.`,
    });
  });
  return found;
}

// ── iac-dangerous-capability ──────────────────────────────────────────────────

const CAPABILITIES_HEADER_RE = /^\s*(?:capabilities:|add:)/;
const DANGEROUS_CAP_RE = /^\s*-\s*(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE)\b/;

export function findDangerousCapability(content: string): ScanIndicator[] {
  if (!isKubernetesManifest(content)) return [];
  const lines = content.split("\n");
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = DANGEROUS_CAP_RE.exec(lines[i]);
    if (!m) continue;
    const windowStart = Math.max(0, i - 5);
    if (!lines.slice(windowStart, i).some(l => CAPABILITIES_HEADER_RE.test(l))) continue;
    found.push({
      id: "iac-dangerous-capability", label: "Dangerous Linux Capability", severity: "high", line: i + 1, confidence: 80,
      detail: `Container adds the '${m[1]}' capability, expanding its privileges well beyond the container default set.`,
    });
  }
  return found;
}

// ── iac-unpinned-image-tag ────────────────────────────────────────────────────

const IMAGE_RE = /^\s*image:\s*["']?([^\s"']+)["']?\s*$/;

export function findUnpinnedImageTag(content: string): ScanIndicator[] {
  if (!isKubernetesManifest(content)) return [];
  const lines = content.split("\n");
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = IMAGE_RE.exec(lines[i]);
    if (!m) continue;
    const ref = m[1];
    const afterLastSlash = ref.split("/").pop() ?? ref;
    const hasPin = afterLastSlash.includes(":") || afterLastSlash.includes("@"); // tag or digest
    if (!hasPin) {
      found.push({
        id: "iac-unpinned-image-tag", label: "Unpinned Container Image Tag", severity: "low", line: i + 1, confidence: 65,
        detail: `Image '${ref}' has no tag or digest — defaults to ':latest', a mutable reference that can silently change what gets deployed.`,
      });
    } else if (ref.endsWith(":latest")) {
      found.push({
        id: "iac-unpinned-image-tag", label: "Unpinned Container Image Tag", severity: "low", line: i + 1, confidence: 65,
        detail: `Image '${ref}' is pinned to the mutable ':latest' tag — pin to a specific version or digest instead.`,
      });
    }
  }
  return found;
}
