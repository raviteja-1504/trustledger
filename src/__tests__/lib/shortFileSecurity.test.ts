/**
 * A file under 50 characters has too little text for the AI-style signals, but it is still code: the security checks
 * must run on it. analyzeFile used to return an empty result for it, so one dangerous line was reported clean.
 */
import { runScan } from "@/lib/scanner";

const scan = (path: string, content: string) =>
  runScan({ repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main", files: [{ path, content }] }).files[0];

describe("short files are still scanned for security problems", () => {
  it.each([
    ["eval-exec", "a.js", "eval(req.query.x)"],
    ["xss", "b.js", "res.send(req.query.name)"],
    ["hardcoded-secret", "c.py", 'password = "hunter2hunter2"'],
    ["command-injection", "d.py", "os.system(input())"],
  ])("%s in a %s one-liner is reported", (id, path, code) => {
    expect(code.length).toBeLessThan(50);
    const f = scan(path, code);
    expect(f.risk_indicators).toContain(id);
    expect(f.risk_score).toBe("CRITICAL");
  });

  it("they still get no AI score: there is too little text for it to mean anything", () => {
    const f = scan("a.js", "eval(req.query.x)");
    expect(f.ai_percentage).toBe(0);
    expect(f.scan_quality).toBe(0);
    expect(f.explained_signals).toEqual([]);
  });

  it("a harmless short file is LOW, and reports its real line count", () => {
    const f = scan("f.js", "const x = 1;");
    expect(f.risk_score).toBe("LOW");
    expect(f.line_count).toBe(1);
  });

  it("an empty or whitespace-only file is still just empty", () => {
    for (const c of ["", "   \n\n  "]) expect(scan("g.js", c)).toMatchObject({ risk_score: "LOW", risk_indicators: [], line_count: 0 });
  });

  it("a short file with a finding is counted as unknown (not human) in the AI share, and does not dilute it", () => {
    const long = Array.from({ length: 60 }, (_, i) => `export const value${i} = ${i};`).join("\n");
    const alone = runScan({ repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main", files: [{ path: "src/a.js", content: long }] });
    const withTiny = runScan({ repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main", files: [{ path: "src/a.js", content: long }, { path: "src/t.js", content: "eval(req.query.x)" }] });
    expect(withTiny.ai_attribution!.unknown_loc).toBe(1);
    expect(withTiny.ai_attribution!.estimated_ai_percentage).toBeCloseTo(alone.ai_attribution!.estimated_ai_percentage, 10);
    expect(withTiny.overall_risk).toBe("CRITICAL");
  });
});
