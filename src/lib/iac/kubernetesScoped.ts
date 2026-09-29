/**
 * Kubernetes checks that need to know WHICH pod and container a setting belongs to -- the absence checks
 * iacKubernetes.ts deliberately left out ("no per-container scoping in this first pass"). configTree gives
 * each document's real structure, so a hardening flag set on container B never excuses container A, and a
 * pod-level securityContext is correctly inherited by every container.
 *
 * Covers every workload kind (Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob), plus RBAC,
 * Secret and Ingress resources. Helm templates work: directive lines are skipped by the reader, and a value
 * that is a `{{ ... }}` template is never judged (it's decided at render time).
 */
import type { ScanIndicator } from "../scanner";
import { appsecHit } from "../appsecRules";
import { parseYamlDocuments, get, path, str, bool, items, strings, entries, entryLine, isTemplatedNode, HELM_TEMPLATE_KEY, type CNode } from "./configTree";

const WORKLOAD_KINDS = new Set(["Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob"]);
const SECRET_NAME_RE = /(?:^|_)(?:PASS(?:WORD|WD)?|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?)(?:_|$)/i;
const DANGEROUS_HOST_PATHS = /^\/(?:$|etc\b|root\b|proc\b|sys\b|boot\b|var\/run\/docker\.sock|run\/docker\.sock|var\/run\/containerd|run\/containerd|var\/lib\/kubelet|var\/lib\/docker|dev\b)/;

const isTemplated = (v: string | undefined) => !!v && v.includes("{{");

function podSpecOf(doc: CNode, kind: string): CNode | undefined {
  if (kind === "Pod") return get(doc, "spec");
  if (kind === "CronJob") return path(doc, "spec", "jobTemplate", "spec", "template", "spec");
  return path(doc, "spec", "template", "spec");
}

function checkWorkload(doc: CNode, kind: string, name: string, out: ScanIndicator[]) {
  const pod = podSpecOf(doc, kind);
  if (!pod) return;
  const podSc = get(pod, "securityContext");
  const podNonRoot = bool(get(podSc, "runAsNonRoot")) === true || Number(str(get(podSc, "runAsUser")) ?? "0") > 0;
  const containers = [...items(get(pod, "containers")), ...items(get(pod, "initContainers"))];

  const podScTemplated = isTemplatedNode(podSc) || isTemplatedNode(pod);
  for (const c of containers) {
    if (c.kind !== "map") continue;
    // A container whose own keys are partly rendered from values (`{{- include ... }}`) can't be judged by
    // what is absent from the template.
    if (c.entries.some(e => e.key === HELM_TEMPLATE_KEY)) continue;
    const cname = str(get(c, "name")) ?? "container";
    const where = `${kind} '${name}', container '${isTemplated(cname) ? "(templated)" : cname}'`;
    const sc = get(c, "securityContext");
    const scTemplated = isTemplatedNode(sc);
    const privileged = bool(get(sc, "privileged")) === true;   // reported by iac-privileged-container already

    const ape = get(sc, "allowPrivilegeEscalation");
    if (!scTemplated && !privileged && bool(ape) !== false && !isTemplated(str(ape))) {
      out.push(appsecHit("iac-k8s-privilege-escalation", ape?.line ?? sc?.line ?? c.line,
        `${where} does not set allowPrivilegeEscalation: false.`, { confidence: 80 }));
    }
    const nonRoot = bool(get(sc, "runAsNonRoot"));
    const uid = str(get(sc, "runAsUser"));
    const containerNonRoot = nonRoot === true || (uid !== undefined && Number(uid) > 0);
    const explicitlyRoot = nonRoot === false || uid === "0";              // iac-container-run-as-root covers these
    if (!scTemplated && !podScTemplated && !privileged && !containerNonRoot && !podNonRoot && !explicitlyRoot && !isTemplated(uid)) {
      // Anchored on the image: without runAsNonRoot the IMAGE's default user decides (and a distinct line
      // keeps this from folding into allowPrivilegeEscalation's finding, which shares its CWE).
      out.push(appsecHit("iac-k8s-missing-run-as-non-root", entryLine(c, "image") ?? sc?.line ?? c.line,
        `${where} does not require a non-root user (runAsNonRoot / runAsUser) in its own or the pod's securityContext.`, { confidence: 70 }));
    }
    const ro = get(sc, "readOnlyRootFilesystem");
    if (!scTemplated && bool(ro) !== true && !isTemplated(str(ro))) {
      out.push(appsecHit("iac-k8s-writable-root-fs", ro?.line ?? sc?.line ?? c.line, `${where} has a writable root filesystem.`, { confidence: 70 }));
    }
    const limits = path(c, "resources", "limits");
    const res = get(c, "resources");
    if (!isTemplatedNode(res) && !isTemplatedNode(limits) && !(get(limits, "memory") && get(limits, "cpu"))) {
      const missing = ["cpu", "memory"].filter(k => !get(limits, k));
      out.push(appsecHit("iac-k8s-missing-resource-limits", res?.line ?? c.line, `${where} has no ${missing.join("/")} limit.`, { confidence: 75 }));
    }
    for (const e of items(get(c, "env"))) {
      const envName = str(get(e, "name"));
      const value = get(e, "value");
      const v = str(value);
      if (!envName || !SECRET_NAME_RE.test(envName) || !v || isTemplated(v) || v.startsWith("$(")) continue;
      if (/^(?:true|false|\d{1,6}|changeme|null|none|)$/i.test(v)) continue;
      out.push(appsecHit("iac-k8s-secret-in-env", value!.line, `${where}: env ${envName} has a literal value in the manifest.`, { confidence: 85 }));
    }
  }

  for (const v of items(get(pod, "volumes"))) {
    const hp = get(v, "hostPath");
    if (!hp) continue;
    const p = str(get(hp, "path")) ?? str(hp) ?? "";
    if (isTemplated(p)) continue;
    const dangerous = DANGEROUS_HOST_PATHS.test(p);
    out.push(appsecHit("iac-k8s-host-path-volume", entryLine(v, "hostPath") ?? v.line,
      `${kind} '${name}' mounts host path '${p || "?"}' from the node${dangerous ? " -- a path that gives control of the node" : ""}.`,
      { confidence: 85, severity: dangerous ? "high" : "medium" }));
  }
}

function checkRbac(doc: CNode, kind: string, name: string, out: ScanIndicator[]) {
  if (kind === "Role" || kind === "ClusterRole") {
    for (const rule of items(get(doc, "rules"))) {
      const verbs = strings(get(rule, "verbs"));
      const resources = strings(get(rule, "resources"));
      if (!verbs.includes("*") && !resources.includes("*")) continue;
      const what = [verbs.includes("*") ? "all verbs" : "", resources.includes("*") ? "all resources" : ""].filter(Boolean).join(" on ");
      out.push(appsecHit("iac-k8s-rbac-wildcard", rule.line, `${kind} '${name}' grants ${what}${kind === "ClusterRole" ? " cluster-wide" : ""}.`, { confidence: 90 }));
    }
  }
  if ((kind === "ClusterRoleBinding" || kind === "RoleBinding") && str(path(doc, "roleRef", "name")) === "cluster-admin") {
    const subjects = items(get(doc, "subjects")).map(s => str(get(s, "name")) ?? "").filter(Boolean);
    if (subjects.length && subjects.every(s => s.startsWith("system:"))) return;
    out.push(appsecHit("iac-k8s-cluster-admin-binding", entryLine(get(doc, "roleRef"), "name") ?? doc.line,
      `${kind} '${name}' grants cluster-admin to ${subjects.join(", ") || "its subjects"}.`, { confidence: 90 }));
  }
}

function checkSecret(doc: CNode, name: string, out: ScanIndicator[]) {
  for (const key of ["data", "stringData"]) {
    const block = get(doc, key);
    const literal = entries(block).find(e => {
      const v = str(e.node);
      return !!v && !isTemplated(v) && v.length >= 4 && !/^(?:changeme|placeholder|<.*>|\$\{.*\}|x+)$/i.test(v);
    });
    if (literal) {
      out.push(appsecHit("iac-k8s-committed-secret", literal.line,
        `Secret '${name}' commits a literal value for '${literal.key}' (${key}).`, { confidence: 85 }));
      return;
    }
  }
}

function checkIngress(doc: CNode, name: string, out: ScanIndicator[]) {
  const spec = get(doc, "spec");
  if (!spec || get(spec, "tls")) return;
  const annotations = entries(path(doc, "metadata", "annotations")).map(e => `${e.key}=${str(e.node) ?? ""}`).join(" ");
  if (/ssl-redirect=["']?true|force-ssl-redirect=["']?true|certificate-arn|ssl-cert|pre-shared-cert|managed-certificates/i.test(annotations)) return;
  out.push(appsecHit("iac-k8s-ingress-no-tls", spec.line, `Ingress '${name}' defines no tls section.`, { confidence: 65 }));
}

/** All scoped Kubernetes findings for one manifest file. */
export function scanKubernetesScoped(content: string): ScanIndicator[] {
  const out: ScanIndicator[] = [];
  for (const doc of parseYamlDocuments(content)) {
    const kind = str(get(doc, "kind"));
    if (!kind || !str(get(doc, "apiVersion"))) continue;
    const rawName = str(path(doc, "metadata", "name"));
    const name = !rawName ? kind : isTemplated(rawName) ? "(templated)" : rawName;
    if (WORKLOAD_KINDS.has(kind)) checkWorkload(doc, kind, name, out);
    else if (kind === "Secret") checkSecret(doc, name, out);
    else if (kind === "Ingress") checkIngress(doc, name, out);
    checkRbac(doc, kind, name, out);
  }
  return out;
}
