/**
 * The AI percentage answers one question -- was this code AI-written? -- from evidence about that. These tests pin
 * what must NOT move it: security findings that exist in human code too, a suspicious git history, a big commit, an AI
 * tool's config file in the repo. They are reported as context, never added to the score.
 */
import { analyzeGitProvenance } from "@/lib/gitProvenance";
import {
  runScan, computeAIPercentage, buildExplainedSignals, CONTEXT_SIGNALS, type ScanInput,
} from "@/lib/scanner";

const lineCount = (s: string) => s.split("\n").length;
const score = (code: string) => computeAIPercentage(code, "typescript", lineCount(code)).score;

// A file with ordinary AI-style documentation, so the amplifying (secondary) signals have something to amplify.
const file = (a: string) => `/**
 * Validates the user input and returns a structured result.
 * @param input - The input to validate
 * @returns The validation result
 */
export async function validateUserInput(input: UserInput): Promise<ValidationResult> {
  // Validate the input data before processing
  if (!input) {
    throw new Error("Input is required");
  }
  // Process the user data and return the result
  const result = await processUserData(input);
  ${a}
  return { success: true, data: result };
}

/**
 * Handles the request and returns a response.
 * @param request - The incoming request
 * @returns The handler response
 */
export async function handleRequest(request: Request): Promise<Response> {
  // Validate the request before handling it
  if (!request) {
    throw new Error("Request is required");
  }
  const result = await processRequestData(request);
  return { success: true, data: result };
}
`;

describe("findings that say nothing about authorship do not change the AI score", () => {
  it("a hardcoded-credential / admin bypass (backdoor-detection) in a file does not make it look more AI-written", () => {
    const withBackdoor = file(`if (user === "admin" && password === "hunter22") { grant(); }`);
    // Same text with the two patterns broken by one letter each, so the line counts and tokens match.
    const without = file(`if (usex === "admin" && passwxrd === "hunter22") { grant(); }`);
    const a = computeAIPercentage(withBackdoor, "typescript", lineCount(withBackdoor));
    expect(a.fired.some(f => f.id === "backdoor-detection")).toBe(true);                 // still detected and reported
    expect(Math.abs(score(withBackdoor) - score(without))).toBeLessThan(0.002);
  });

  it("calls to APIs that do not exist (hallucinated-api) do not either", () => {
    const hall = file("Array.isEmpty(x); Object.isEmpty(y); String.isEmpty(z); data.validateAndSave(q); data.parseAndReturn(w);");
    const ok = file("Array.isEmptx(x); Object.isEmptx(y); String.isEmptx(z); data.validatexAndSave(q); data.parsexAndReturn(w);");
    expect(computeAIPercentage(hall, "typescript", lineCount(hall)).fired.some(f => f.id === "hallucinated-api")).toBe(true);
    expect(Math.abs(score(hall) - score(ok))).toBeLessThan(0.002);
  });

  it("the context signals are the ones that are authorship-neutral", () => {
    expect([...CONTEXT_SIGNALS].sort()).toEqual(["backdoor-detection", "hallucinated-api", "style-drift"]);
  });
});

describe("the explanation only credits signals that fed the score", () => {
  const fired = [
    { id: "comment-phrasing", value: 0.8, leak: 0.8 },      // CORE
    { id: "doc-coverage", value: 0.6, leak: 0.5 },          // SECONDARY
    { id: "nesting-depth", value: 0.9, leak: 0.4 },         // STYLE
    { id: "backdoor-detection", value: 0.85, leak: 0.85 },  // CONTEXT
    { id: "style-drift", value: 0.7, leak: 0.65 },          // CONTEXT
  ];
  const explained = buildExplainedSignals(fired, 0.6);
  const by = (id: string) => explained.find(s => s.id === id)!;

  it("style and context signals are shown with tier and value but contribute nothing", () => {
    expect(by("nesting-depth")).toMatchObject({ tier: "STYLE", contribution: 0, value: 0.9 });
    expect(by("backdoor-detection")).toMatchObject({ tier: "CONTEXT", contribution: 0 });
    expect(by("style-drift")).toMatchObject({ tier: "CONTEXT", contribution: 0 });
  });

  it("the signals that fed the score share all of it", () => {
    const shared = by("comment-phrasing").contribution + by("doc-coverage").contribution;
    expect(shared).toBeCloseTo(0.6, 1);
    expect(by("comment-phrasing").contribution).toBeGreaterThan(by("doc-coverage").contribution);
  });

  it("with only style signals fired, nothing is credited", () => {
    const only = buildExplainedSignals([{ id: "nesting-depth", value: 0.9, leak: 0.4 }], 0.5);
    expect(only.map(s => s.contribution)).toEqual([0]);
  });

  it("sorts what contributed first", () => {
    expect(explained.slice(0, 2).map(s => s.id)).toEqual(["comment-phrasing", "doc-coverage"]);
  });
});

describe("repository-level evidence: no flat boosts, no provenance risk as AI evidence", () => {
  const code = file("");
  const base = (over: Partial<ScanInput> = {}): ScanInput => ({
    repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main",
    files: [{ path: "src/feature.ts", content: code }],
    ...over,
  });
  // The documented weights, so the test fails if anything else is added on top.
  const weighted = (e: { code_evidence: number; pr_evidence: number; git_evidence: number; baseline_evidence: number; tool_evidence: number }) =>
    e.code_evidence * 0.25 + e.pr_evidence * 0.25 + e.git_evidence * 0.25 + e.baseline_evidence * 0.15 + e.tool_evidence * 0.10;

  it("the combined evidence is exactly the weighted sum, even for a 1,500-line single commit", () => {
    const r = runScan(base({ pr_metadata: { additions: 1500, deletions: 10, commits: 1, changed_files: 3 } }));
    const e = r.evidence_breakdown;
    expect(e.combined).toBeCloseTo(Math.min(1, weighted(e)), 10);
    expect(e.boosts.join(" ")).toContain("Unusual: 1500 lines in a single commit");
    expect(e.boosts.join(" ")).not.toContain("High-confidence");
  });

  it("an AI tool's config file in the repo adds only its normal weight, with no extra 0.15 -- even when the code looks AI-written", () => {
    // Strong code evidence (a leaked preamble is a core signal), so the old "tooling AND code > 0.40" boost would apply.
    const strong = `// Here is the implementation of the handler. Certainly! This function will validate the input.
${code}`;
    const r = runScan(base({ files: [{ path: "src/feature.ts", content: strong }, { path: ".cursorrules", content: "use tabs" }], all_file_paths: ["src/feature.ts", ".cursorrules"] }));
    const e = r.evidence_breakdown;
    expect(r.ai_tooling.length).toBeGreaterThan(0);
    expect(e.code_evidence).toBeGreaterThan(0.40);
    expect(e.combined).toBeCloseTo(Math.min(1, weighted(e)), 10);
  });

  it("a suspicious git history (unsigned, odd authors) does not raise git evidence", () => {
    const log = [
      "1111111111111111111111111111111111111111|Mallory|m@a.example|1700000000|N|fix thing",
      "2222222222222222222222222222222222222222|Mallory|m@b.example|1700000100|N|fix other thing",
      "3333333333333333333333333333333333333333|Mallory|m@c.example|1700000200|N|more changes",
    ].join("\n");
    expect(analyzeGitProvenance(log).overallRiskScore).toBeGreaterThan(0);               // the history IS risky...
    const r = runScan(base({ git_log: log }));
    expect(r.evidence_breakdown.git_evidence).toBe(0);                                   // ...and says nothing about AI
    expect(r.git_provenance?.overallRiskScore).toBeGreaterThan(0);                       // still reported on its own
  });

  it("commits that say an AI tool wrote them do count, in proportion", () => {
    const log = [
      "1111111111111111111111111111111111111111|Ana|ana@a.example|1700000000|G|Generated by Copilot: add handler",
      "2222222222222222222222222222222222222222|Ana|ana@a.example|1700000100|G|fix typo in readme",
    ].join("\n");
    const r = runScan(base({ git_log: log }));
    expect(r.evidence_breakdown.git_evidence).toBeCloseTo(0.5, 5);                       // 1 of 2 commits
  });

  it("no git history leaves git evidence at 0 (unknown), not at a human or AI verdict", () => {
    expect(runScan(base()).evidence_breakdown.git_evidence).toBe(0);
  });
});

describe("the code evidence is the share of analysed SOURCE, not diluted by files nobody wrote", () => {
  const src = file("");
  const run = (extra: Array<{ path: string; content: string }>) => runScan({
    repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main",
    files: [{ path: "src/feature.ts", content: src }, ...extra],
  });
  const lines = (n: number) => Array.from({ length: n }, (_, i) => `    "pkg${i}": "1.0.${i}",`).join("\n");

  it("a 5,000-line lockfile and a generated file do not lower the code evidence", () => {
    const alone = run([]);
    const diluted = run([
      { path: "package-lock.json", content: lines(5000) },
      { path: "src/generated/api.generated.ts", content: Array.from({ length: 2000 }, (_, i) => `export const g${i} = ${i};`).join("\n") },
    ]);
    expect(alone.evidence_breakdown.code_evidence).toBeGreaterThan(0.1);
    expect(diluted.evidence_breakdown.code_evidence).toBeCloseTo(alone.evidence_breakdown.code_evidence, 10);
    expect(diluted.total_ai_percentage).toBeCloseTo(alone.total_ai_percentage, 10);
    expect(diluted.ai_attribution!.excluded_loc).toBeGreaterThan(5000);
  });

  it("a file too short to analyse does not count as human either", () => {
    const alone = run([]);
    const withTiny = run([{ path: "src/tiny.ts", content: "export const x = 1;\nexport const y = 2;" }]);
    expect(withTiny.evidence_breakdown.code_evidence).toBeCloseTo(alone.evidence_breakdown.code_evidence, 10);
    expect(withTiny.ai_attribution!.unknown_loc).toBeGreaterThan(0);
  });
});
