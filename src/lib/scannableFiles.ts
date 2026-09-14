// ── Files webhook handlers fetch content for and pass to the scanner ──────────
//
// Source files (by extension) get AI/secrets/vuln analysis. Dependency
// manifests (matched by full filename, regardless of extension) carry no AI
// content but are parsed by depAnalysis (see src/lib/scanner.ts) to populate
// the phantom-dependency and risky-package checks — so they must also be
// fetched, or dep_report stays null and those pages show 0.

export const SCANNABLE_EXTS = new Set([
  "py", "ts", "tsx", "js", "jsx", "rb", "go", "rs",
  "java", "kt", "cs", "php", "cpp", "c", "swift",
  // XML (Spring/servlet config -- XXE-relevant, and often carries hardcoded
  // DB credentials) and .properties (Java's native key=value config format,
  // which the secrets detector's generic word=value patterns already cover)
  // were previously never fetched at all by any automated ingestion path,
  // hiding entire classes of Java-specific findings regardless of detector
  // quality.
  "xml", "properties",
]);

const MANIFEST_BASENAMES = new Set([
  "package.json", "requirements.txt", "go.mod",
  // Java/Kotlin dependency manifests -- previously never fetched, so
  // dep_report was always null for Maven/Gradle projects.
  "pom.xml", "build.gradle", "build.gradle.kts",
]);

export function isScannablePath(path: string): boolean {
  const basename = path.split("/").pop() ?? "";
  if (MANIFEST_BASENAMES.has(basename)) return true;
  const ext = basename.split(".").pop()?.toLowerCase() ?? "";
  return SCANNABLE_EXTS.has(ext);
}

// ── File classification (whole-repo scanning) ──────────────────────────────
// isScannablePath above answers a binary "fetch this or not" question, which
// is all the PR/webhook paths ever needed (GitHub already narrows to the
// files a PR touched). A whole-repo scan instead has to decide, across every
// path in a tree that can run into the thousands, what's worth spending an
// API call and an analyzeFile() pass on -- so it needs real categories, not
// just yes/no.

export type FileCategory =
  | "source" | "dependency_manifest" | "config"
  | "generated" | "vendored" | "binary" | "unknown";

const BINARY_EXTS = new Set([
  "png","jpg","jpeg","gif","ico","svg","webp","bmp","tiff",
  "woff","woff2","ttf","eot","otf",
  "mp3","mp4","wav","avi","mov","webm",
  "zip","tar","gz","jar","war","ear","7z","rar",
  "pdf","doc","docx","xls","xlsx","ppt","pptx",
  "exe","dll","so","dylib","class","pyc","o","a",
]);

const CONFIG_EXTS = new Set(["yaml","yml","json","toml","ini","env","properties","conf","xml"]);

// Path segments that mark vendored/third-party or build-output trees --
// scanning these produces the exact false-positive-and-noise problem
// documented in scanner.ts's looksMinified/codeCategory handling, and at
// whole-repo scale (thousands of files) fetching them at all is wasted API
// budget on code this repo's authors didn't write and can't fix here.
const VENDORED_PATH_RE = /(?:^|\/)(?:node_modules|vendor|vendors|bower_components|third[-_]?party|\.git)\//i;
const GENERATED_PATH_RE = /(?:^|\/)(?:dist|build|target|out|coverage|generated|\.next|\.nuxt|__generated__)\//i;
const GENERATED_NAME_RE = /[.-]min\.(?:js|css)$|\.min\.js$|\.bundle\.js$|\.pb\.(?:ts|js|go)$|\.g\.dart$/i;

export function classifyFile(path: string): FileCategory {
  const basename = path.split("/").pop() ?? "";
  const ext      = basename.split(".").pop()?.toLowerCase() ?? "";

  if (MANIFEST_BASENAMES.has(basename)) return "dependency_manifest";
  if (VENDORED_PATH_RE.test(path))      return "vendored";
  if (GENERATED_PATH_RE.test(path) || GENERATED_NAME_RE.test(basename)) return "generated";
  if (BINARY_EXTS.has(ext))             return "binary";
  if (SCANNABLE_EXTS.has(ext))          return "source";
  if (CONFIG_EXTS.has(ext))             return "config";
  return "unknown";
}

// A whole-repo scan fetches content for these categories only. "config"
// (yaml/json/etc beyond the xml/properties already folded into
// SCANNABLE_EXTS) is deliberately excluded for now -- the scanner has no
// detectors that meaningfully analyse arbitrary YAML/JSON/TOML content yet,
// so fetching it would just spend API budget for no analytical value.
export function isRepoScanCandidate(path: string): boolean {
  const cat = classifyFile(path);
  return cat === "source" || cat === "dependency_manifest";
}

// Hard caps for a whole-repo scan -- see repo-scan-worker. Keeps a single
// job bounded regardless of how large the target repository is.
export const REPO_SCAN_MAX_FILES     = 400;
export const REPO_SCAN_MAX_FILE_BYTES = 400_000;
