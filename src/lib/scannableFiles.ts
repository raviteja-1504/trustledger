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
]);

const MANIFEST_BASENAMES = new Set([
  "package.json", "requirements.txt", "go.mod",
]);

export function isScannablePath(path: string): boolean {
  const basename = path.split("/").pop() ?? "";
  if (MANIFEST_BASENAMES.has(basename)) return true;
  const ext = basename.split(".").pop()?.toLowerCase() ?? "";
  return SCANNABLE_EXTS.has(ext);
}
