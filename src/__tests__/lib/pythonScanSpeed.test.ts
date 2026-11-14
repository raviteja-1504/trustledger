/**
 * @jest-environment node
 *
 * A large Python file must not scan in quadratic time. semgrep's own cli/src/semgrep/app/scans.py (765 lines) took 220 seconds, because two
 * caches in the Python engine were keyed by a tree-sitter node object, and tree-sitter returns a NEW object on every access: they never hit, so
 * each call site re-walked its whole function, class and file. Now they are keyed by the parse tree and node id.
 */
import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

jest.setTimeout(120_000);
beforeAll(async () => { await warmPythonTaintEngine(); }, 120_000);

/** A module of N methods, each reading a field object, a local object and an imported module: the shapes that hit the three whole-tree walks. */
function bigModule(n: number): string {
  const lines = ["import os", "import json", "from app import helpers", "", "class Repo:", "    def find(self, k):", "        return k", "", "class Service:", "    def __init__(self, repo: Repo):", "        self.repo = repo", ""];
  for (let i = 0; i < n; i++) {
    lines.push(
      `    def op${i}(self, key, other):`,
      `        r = Repo()`,
      `        a = r.find(key)`,
      `        b = self.repo.find(other)`,
      `        c = helpers.load(a)`,
      `        d = os.path.join("x", str(b))`,
      `        return json.dumps({"a": a, "b": b, "c": c, "d": d})`,
      ``,
    );
  }
  return lines.join("\n");
}

describe("scanning a large Python file", () => {
  it("time grows with the size of the file, not its square: 4x the file takes well under 16x the time", () => {
    const time = (n: number) => {
      const t0 = Date.now();
      runScan({ repo: "t", pr_number: 1, commit_sha: "abc123", branch: "main", files: [{ path: "svc.py", content: bigModule(n) }] });
      return Date.now() - t0;
    };
    time(10);                                         // warm-up: parser and engine start-up are not part of the measurement
    const small = time(40), large = time(160);        // ~330 lines and ~1,300 lines
    // linear is about 4x; quadratic is about 16x. A ratio is steady under machine load, unlike an absolute time.
    expect(large / Math.max(small, 200)).toBeLessThan(10);
  });

  it("the result does not depend on the caches: the same finding with and without a long file around it", () => {
    const vulnerable = `from flask import request\nimport sqlite3\n\ndef find():\n    q = request.args.get("q")\n    sqlite3.connect("a.db").execute("SELECT * FROM t WHERE n = '" + q + "'")\n`;
    const alone = runScan({ repo: "t", pr_number: 1, commit_sha: "abc123", branch: "main", files: [{ path: "a.py", content: vulnerable }] });
    const padded = runScan({ repo: "t", pr_number: 1, commit_sha: "abc123", branch: "main", files: [{ path: "a.py", content: vulnerable + "\n" + bigModule(30) }] });
    const ids = (o: typeof alone) => o.files[0].indicators.filter(i => i.id === "sql-injection").map(i => i.line);
    expect(ids(alone)).toEqual([6]);
    expect(ids(padded)).toEqual([6]);
  });
});
