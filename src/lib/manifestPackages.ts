import { parsePackageJson, parseRequirementsTxt, parseGoMod } from "./depAnalysis";

export interface ManifestPackage {
  name:    string;
  version: string;
  source:  string;  // repo
  aiPr:    boolean;
}

/** Minimal shape this needs — deliberately narrower than the app's full
 *  ScanResult so it can run server-side too without fabricating unused fields. */
interface ScanForManifest {
  repo: string;
  files: { file_path: string; content?: string | null; ai_percentage: number }[];
}

// Extract every dependency declared in a package.json / requirements.txt / go.mod
// across a set of scans — used by /dependencies (CVE/typosquat matching) and
// /phantom-deps (live npm/PyPI existence check).
export function collectManifestPackages(scans: ScanForManifest[]): ManifestPackage[] {
  const out: ManifestPackage[] = [];
  const seen = new Set<string>();
  for (const scan of scans) {
    for (const file of scan.files) {
      if (!file.content) continue;
      const name = file.file_path.toLowerCase();
      const refs = name.endsWith("package.json")     ? parsePackageJson(file.content)
                 : name.endsWith("requirements.txt")  ? parseRequirementsTxt(file.content)
                 : name.endsWith("go.mod")            ? parseGoMod(file.content)
                 : [];
      for (const ref of refs) {
        const key = `${ref.name}|${scan.repo}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ name: ref.name, version: ref.version, source: scan.repo, aiPr: file.ai_percentage > 0.4 });
      }
    }
  }
  return out;
}
