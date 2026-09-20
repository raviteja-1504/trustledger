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
]);

const MANIFEST_BASENAMES = new Set([
  "package.json", "requirements.txt", "go.mod",
  // Java/Kotlin dependency manifests -- previously never fetched, so
  // Maven/Gradle projects never had their dependencies parsed at all.
  "pom.xml", "build.gradle", "build.gradle.kts",
]);

export function isScannablePath(path: string): boolean {
  const basename = path.split("/").pop() ?? "";
  if (MANIFEST_BASENAMES.has(basename)) return true;
  const ext = basename.split(".").pop()?.toLowerCase() ?? "";
  return SCANNABLE_EXTS.has(ext);
}
