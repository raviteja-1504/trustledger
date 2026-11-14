import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPythonTaintEngine(); }, 120_000);

const base = { repo: "o/r", pr_number: 1, commit_sha: "abc" };
const py = (n: number) => `import os\nfrom flask import request\n\ndef h${n}():\n    name = request.args.get("n")\n    os.system("ls " + name)\n`;
const files = Array.from({ length: 4 }, (_, i) => ({ path: `app/h${i}.py`, content: py(i) }));

describe("scan time budget", () => {
  it("a spent budget degrades to pattern checks, reports it in health and does not cache the cut-short result", () => {
    const out = runScan({ ...base, files, time_budget_ms: 1, cache_namespace: "t" });
    expect(out.files).toHaveLength(4);                              // every file is still in the result
    expect(out.health?.gap_counts["time-budget"] ?? 0).toBeGreaterThan(0);
    expect(out.health?.status).toBe("degraded");
    const cut = out.health!.gaps.filter(g => g.reason === "time-budget").map(g => g.file);
    for (const p of cut) expect(out.file_cache?.[p]).toBeUndefined(); // a rescan must redo them, not replay the shallow result
  });

  it("no budget, or a generous one, analyses everything", () => {
    for (const time_budget_ms of [undefined, 600_000]) {
      const out = runScan({ ...base, files, time_budget_ms, cache_namespace: "t" });
      expect(out.health?.gap_counts["time-budget"] ?? 0).toBe(0);
      expect(Object.keys(out.file_cache ?? {})).toHaveLength(4);
    }
  });
});
