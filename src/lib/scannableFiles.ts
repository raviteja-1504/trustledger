// ── Files webhook handlers fetch content for and pass to the scanner ──────────
//
// Source files (by extension) get AI/secrets/vuln analysis. Dependency
// manifests (matched by full filename, regardless of extension) carry no AI
// content but are parsed (via depAnalysis.ts's manifest parsers) by both
// /dependencies (CVE/OSV + non-CVE risk matching, see dependencyScan.ts)
// and /phantom-deps (live npm/PyPI existence check) — so they must also be
// fetched, or those pages have nothing to parse and show 0.

export const SCANNABLE_EXTS = new Set([
  "py", "ts", "tsx", "js", "jsx", "rb", "go", "rs",
  "java", "kt", "cs", "php", "cpp", "c", "swift",
  // .csproj -- C#'s dependency manifest (PackageReference elements, parsed by
  // depAnalysis.ts's parseCsproj). Project-specific filenames (MyApp.csproj), unlike
  // package.json/go.mod's fixed basenames, so this needs the extension allowlist rather than
  // MANIFEST_BASENAMES below.
  "csproj",
  // XML (Spring/servlet config -- XXE-relevant, and often carries hardcoded
  // DB credentials) and .properties (Java's native key=value config format,
  // which the secrets detector's generic word=value patterns already cover)
  // were previously never fetched at all by any automated ingestion path,
  // hiding entire classes of Java-specific findings regardless of detector
  // quality.
  "xml", "properties",
  // Razor views -- where C#'s Html.Raw()/Response.Write() XSS escape
  // hatches predominantly live, not in .cs code-behind. Without this, the
  // C# XSS detector would rarely see real code.
  "cshtml",
  // Terraform -- unambiguous extension, safe to blanket-allow (see
  // iacTerraform.ts). .yaml/.yml are deliberately NOT here: that extension
  // is also CI config, Helm values, app config, etc. across every existing
  // scanned repo -- isLikelyK8sManifestPath() below is the narrower gate
  // for those, so this doesn't newly flood every repo's next scan.
  "tf", "tfvars",
]);

const MANIFEST_BASENAMES = new Set([
  "package.json", "requirements.txt", "go.mod",
  // Java/Kotlin dependency manifests -- previously never fetched, so
  // Maven/Gradle projects never had their dependencies parsed at all.
  "pom.xml", "build.gradle", "build.gradle.kts",
  // PHP's dependency manifest (parsed by depAnalysis.ts's parseComposerJson) -- previously never
  // fetched, so PHP projects (this codebase's own 6th first-class taint-engine language) never had
  // their dependencies parsed at all, same gap Java/Kotlin had before the entry above closed it.
  "composer.json",
]);

// Kubernetes manifests are plain .yaml/.yml -- indistinguishable by
// extension alone from CI config, Helm values, app config, etc. Rather than
// blanket-allow every YAML file in every scanned repo (a real behavior
// change with real cost/noise consequences for existing customers), this
// scopes intake to common IaC conventions: a hinting directory name, or a
// manifest basename that matches a well-known Kubernetes kind. A real
// manifest that follows neither convention is a documented, accepted miss
// (see iacKubernetes.ts's docblock) -- the same recall-for-blast-radius
// tradeoff this codebase already makes elsewhere.
const IAC_YAML_PATH_HINTS = /(^|\/)(k8s|kubernetes|manifests?|deploy(ments?)?|charts?|helm|kustomize|overlays|base)\//i;
const IAC_YAML_NAME_HINTS = /^(deployment|service|ingress|configmap|secret|statefulset|daemonset|cronjob|job|namespace|role|rolebinding|clusterrole|clusterrolebinding|networkpolicy|pvc|persistentvolume|hpa|kustomization|values)[-._a-z0-9]*\.ya?ml$/i;

export function isLikelyK8sManifestPath(path: string): boolean {
  const basename = path.split("/").pop() ?? "";
  const ext = basename.split(".").pop()?.toLowerCase() ?? "";
  if (ext !== "yaml" && ext !== "yml") return false;
  return IAC_YAML_PATH_HINTS.test(path) || IAC_YAML_NAME_HINTS.test(basename);
}

// Dockerfile/docker-compose.yml -- Container security phase. `Dockerfile`
// has no extension at all (LANG_MAP in scanner.ts is purely extension-keyed,
// so this also backs detectLanguage()'s basename branch, not just ingestion
// here), and `docker-compose.yml` is YAML -- same ambiguity problem
// isLikelyK8sManifestPath above solves for Kubernetes manifests, but
// Compose's conventional basenames are unambiguous enough for a direct
// name-pattern match rather than needing a directory-hint regex too.
const DOCKERFILE_NAME_RE = /^dockerfile(\.[\w.-]+)?$/i;
const DOCKERFILE_EXT_RE = /\.dockerfile$/i;
const DOCKER_COMPOSE_NAME_RE = /^(?:docker-)?compose(\.[\w.-]+)?\.ya?ml$/i;

export function isDockerfilePath(path: string): boolean {
  const basename = path.split("/").pop() ?? "";
  return DOCKERFILE_NAME_RE.test(basename) || DOCKERFILE_EXT_RE.test(basename);
}

export function isDockerComposePath(path: string): boolean {
  const basename = path.split("/").pop() ?? "";
  return DOCKER_COMPOSE_NAME_RE.test(basename);
}

export function isScannablePath(path: string): boolean {
  const basename = path.split("/").pop() ?? "";
  if (MANIFEST_BASENAMES.has(basename)) return true;
  if (isLikelyK8sManifestPath(path)) return true;
  if (isDockerfilePath(path)) return true;
  if (isDockerComposePath(path)) return true;
  const ext = basename.split(".").pop()?.toLowerCase() ?? "";
  return SCANNABLE_EXTS.has(ext);
}
