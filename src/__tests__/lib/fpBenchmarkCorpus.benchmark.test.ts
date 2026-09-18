import fs from "fs";
import path from "path";
import { runScan, AI_SIGNAL_IDS } from "@/lib/scanner";
import { extractSecurityFindings, diffAgainstBaseline, formatNoiseReport } from "@/lib/fpBenchmark";
import { FP_BASELINE } from "@/lib/fpBenchmarkBaseline";

// Scanning all of src/ (250+ files) through the real scanner takes ~30s --
// well over jest's 5000ms default. A local override, not a jest.config.js
// change, matching how this test stays inside the normal npm test/CI flow
// like bigRepoScan.test.ts/scanner.benchmark.test.ts already do.
jest.setTimeout(90_000);

const ROOT = path.resolve(__dirname, "../../..");
const SRC = path.join(ROOT, "src");

// fpBenchmark.ts/fpBenchmarkBaseline.ts are the benchmark harness/data
// itself, not application source being benchmarked -- excluded for the same
// reason __tests__ is. Confirmed necessary, not precautionary: the baseline
// file's own `reason` text quotes representative vulnerable-looking
// snippets (e.g. "new URL(req.url)") to explain each entry, and the
// regex-based ssrf/ldap-injection detectors match that quoted documentation
// text exactly like they'd match real code -- the identical "keyword
// self-reference" false-positive class already catalogued for
// ast.ts/vulnCatalog.ts elsewhere in this baseline.
const EXCLUDED_FILES = new Set(["fpBenchmark.ts", "fpBenchmarkBaseline.ts"]);

function collectSourceFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "__tests__" || entry.name === "node_modules") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectSourceFiles(full, acc);
    } else if (
      /\.(ts|tsx)$/.test(entry.name) && !/\.test\.(ts|tsx)$/.test(entry.name) &&
      !/\.d\.ts$/.test(entry.name) && !EXCLUDED_FILES.has(entry.name)
    ) {
      acc.push(full);
    }
  }
  return acc;
}

describe("false-positive benchmark — src/ self-scan against the checked-in baseline", () => {
  it("produces no new, unreviewed security findings and no stale baseline entries", () => {
    const absPaths = collectSourceFiles(SRC);
    const scanFiles = absPaths.map(f => ({
      path: "src" + f.slice(SRC.length).replace(/\\/g, "/"),
      content: fs.readFileSync(f, "utf-8"),
    }));

    const result = runScan({
      repo: "self/fp-benchmark", pr_number: 1, commit_sha: "abc1234", branch: "main",
      files: scanFiles,
    });

    const lineTextByFile = new Map(scanFiles.map(f => [f.path, f.content.split("\n")]));
    const live = extractSecurityFindings(result.files, lineTextByFile, AI_SIGNAL_IDS);

    // Informational -- printed unconditionally, even on a clean pass, so the
    // current noise floor stays visible in CI logs over time. The hard gate
    // below is really "no NEW unreviewed noise," not "zero findings."
    // eslint-disable-next-line no-console
    console.log(formatNoiseReport(live));

    const { newFindings, staleEntries } = diffAgainstBaseline(live, FP_BASELINE);

    if (newFindings.length > 0) {
      const detail = newFindings.map(f =>
        `  [${f.severity}] ${f.id} ${f.file}:${f.line ?? "?"} (hash ${f.lineHash}): ${f.detail}`,
      ).join("\n");
      throw new Error(
        `${newFindings.length} new, unreviewed security finding(s) not present in FP_BASELINE:\n${detail}\n\n` +
        `Either fix the underlying code/detector, or add an entry to src/lib/fpBenchmarkBaseline.ts with a real reason.`,
      );
    }

    if (staleEntries.length > 0) {
      const detail = staleEntries.map(e =>
        `  [${e.severity}] ${e.id} ${e.file}:${e.line} (hash ${e.lineHash}): ${e.reason}`,
      ).join("\n");
      throw new Error(
        `${staleEntries.length} stale baseline entr(y/ies) in src/lib/fpBenchmarkBaseline.ts no longer match a live finding:\n${detail}\n\n` +
        `Either the finding was fixed (remove the entry), or the surrounding line changed enough that its hash no longer matches (re-verify and update the hash).`,
      );
    }
  });
});
