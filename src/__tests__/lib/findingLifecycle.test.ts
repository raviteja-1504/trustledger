import { findingStatus, fixedSincePrevious, unsuppressed, isActive, summarize, type TriageDecision } from "@/lib/findingLifecycle";
import { summarizeHealth, describeHealth } from "@/lib/scanHealth";
import { runScan, calculateRisk, CURRENT_ENGINE_VERSION } from "@/lib/scanner";

const NOW = new Date("2026-09-30T12:00:00Z");
const decision = (over: Partial<TriageDecision> = {}): TriageDecision =>
  ({ status: "accepted", reason: "internal tool", expires_at: null, set_by_email: "r@x.dev", set_at: "2026-09-01T00:00:00Z", ...over });

describe("finding lifecycle", () => {
  const history = { previous: new Set(["A", "B"]), earlier: new Set(["C"]) };
  const none = new Map<string, TriageDecision>();

  it("new / existing / reopened from the PR's own history", () => {
    expect(findingStatus("A", history, none, NOW)).toBe("existing");
    expect(findingStatus("Z", history, none, NOW)).toBe("new");
    expect(findingStatus("C", history, none, NOW)).toBe("reopened");      // gone last push, back now
    expect(findingStatus("A", { previous: null, earlier: new Set() }, none, NOW)).toBe("new");   // first scan of the PR
    expect(findingStatus(undefined, history, none, NOW)).toBe("existing"); // legacy finding without identity
  });

  it("an active decision wins; an expired one reads as reopened", () => {
    expect(findingStatus("A", history, new Map([["A", decision()]]), NOW)).toBe("accepted");
    expect(findingStatus("Z", history, new Map([["Z", decision({ status: "false_positive" })]]), NOW)).toBe("false_positive");
    expect(findingStatus("A", history, new Map([["A", decision({ expires_at: "2026-09-29T00:00:00Z" })]]), NOW)).toBe("reopened");
    expect(isActive(decision({ expires_at: "2026-10-01T00:00:00Z" }), NOW)).toBe(true);
    expect(isActive(undefined, NOW)).toBe(false);
  });

  it("fixed = in the previous scan, gone now, and its file was rescanned", () => {
    const previousFiles = [
      { file_path: "a.ts", indicators: [{ id: "sql-injection", label: "SQLi", line: 3, fingerprint: "A" }, { id: "xss", label: "XSS", fingerprint: "B" }] },
      { file_path: "untouched.ts", indicators: [{ id: "xss", label: "XSS", fingerprint: "U" }] },
    ];
    const fixed = fixedSincePrevious(previousFiles, new Set(["B"]), new Set(["a.ts"]));
    expect(fixed.map(f => f.fingerprint)).toEqual(["A"]);                 // U's file wasn't in this scan: unknown, not fixed
    expect(fixed[0]).toMatchObject({ file_path: "a.ts", line: 3, id: "sql-injection" });
  });

  it("suppression removes only actively-decided findings from gating", () => {
    const inds = [{ id: "x", fingerprint: "A" }, { id: "y", fingerprint: "B" }, { id: "z" }];
    const t = new Map([["A", decision()], ["B", decision({ expires_at: "2026-01-01T00:00:00Z" })]]);
    expect(unsuppressed(inds, t, NOW).map(i => i.id)).toEqual(["y", "z"]);
    expect(summarize(["new", "new", "accepted", "reopened"], 3)).toEqual({ new: 2, existing: 0, reopened: 1, accepted: 1, false_positive: 0, fixed: 3 });
  });

  it("an accepted HIGH finding no longer makes its file HIGH", () => {
    const f = runScan({ repo: "t", pr_number: 1, commit_sha: "a", files: [{ path: "src/r.ts", content: `app.get("/u", (req, res) => db.query("SELECT * FROM u WHERE id = " + req.query.id));\n` }] }).files[0];
    expect(["HIGH", "CRITICAL"]).toContain(f.risk_score);
    const t = new Map(f.indicators.filter(i => i.fingerprint).map(i => [i.fingerprint!, decision()]));
    expect(["HIGH", "CRITICAL"]).not.toContain(calculateRisk(unsuppressed(f.indicators, t), f.ai_percentage));
  });
});

describe("scan health and telemetry", () => {
  it("statuses: complete, partial (by-design limits), degraded (engine or content missing)", () => {
    expect(summarizeHealth([], "6.5").status).toBe("complete");
    expect(summarizeHealth([{ file: "big.ts", language: "typescript", reason: "too-large" }], "6.5").status).toBe("partial");
    const d = summarizeHealth([
      { file: "big.ts", language: "typescript", reason: "too-large" },
      { file: "a.py", language: "python", reason: "engine-unavailable" },
    ], "6.5");
    expect(d.status).toBe("degraded");
    expect(d.gaps[0].reason).toBe("engine-unavailable");                  // actionable gaps first
    expect(d.engines_unavailable).toEqual(["python"]);
    expect(describeHealth(d)).toContain("Python data-flow engine wasn't loaded yet");
  });

  it("a Python file scanned before the engine loads is reported, not silently weakened (the cold-start case)", () => {
    // This test file never warms the tree-sitter engines, exactly like a cold serverless instance.
    const r = runScan({ repo: "t", pr_number: 1, commit_sha: "a", files: [
      { path: "app/views.py", content: `def v(request):\n    cursor.execute("SELECT * FROM u WHERE id = " + request.GET["id"])\n` },
      { path: "src/ok.ts", content: `export const x = 1;\n` },
    ] });
    expect(r.health?.status).toBe("degraded");
    expect(r.health?.gaps).toEqual([{ file: "app/views.py", language: "python", reason: "engine-unavailable" }]);
    expect(r.health?.engine_version).toBe(CURRENT_ENGINE_VERSION);
  });

  it("too-large and minified files are partial coverage; missing content is degraded", () => {
    const big = Array.from({ length: 5100 }, (_, i) => `export const v${i} = ${i};`).join("\n");
    const minified = "var a=1;".repeat(200);
    const r = runScan({ repo: "t", pr_number: 1, commit_sha: "a", missing_content_paths: ["src/gone.ts"], files: [
      { path: "src/big.ts", content: big }, { path: "src/app.min.js", content: minified },
    ] });
    expect(Object.fromEntries(r.health!.gaps.map(g => [g.file, g.reason]))).toEqual({
      "src/big.ts": "too-large", "src/app.min.js": "minified-or-generated", "src/gone.ts": "content-unavailable",
    });
    expect(r.health?.status).toBe("degraded");
  });

  it("telemetry: phases add up, slowest files listed, reused files counted", () => {
    const files = [{ path: "src/a.ts", content: `export const a = 1;\n` }, { path: "src/b.ts", content: `export const b = 2;\n` }];
    const first = runScan({ repo: "t", pr_number: 1, commit_sha: "a", files });
    const t = first.telemetry!;
    expect(t.files_analyzed).toBe(2);
    expect(t.cross_file_ms + t.per_file_ms + t.post_ms).toBe(t.total_ms);
    expect(t.slowest.map(s => s.file).sort()).toEqual(["src/a.ts", "src/b.ts"]);
    const again = runScan({ repo: "t", pr_number: 1, commit_sha: "a", files, prev_results: first.file_cache });
    expect(again.telemetry).toMatchObject({ files_analyzed: 0, files_reused: 2 });
  });
});

describe("engine warm-up", () => {
  it("resolves ready once every engine loads, and the scan is then complete", async () => {
    const { ensureTaintEngines } = await import("@/lib/engineWarmup");
    const w = await ensureTaintEngines(60000);
    expect(w.ready).toBe(true);
    const r = runScan({ repo: "t", pr_number: 1, commit_sha: "a", files: [{ path: "app/views.py", content: `def v(request):\n    return 1\n` }] });
    expect(r.health?.status).toBe("complete");
  }, 90000);
});
