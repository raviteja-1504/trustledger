import { buildEvidenceGroups, GROUP_WEIGHTS, LINGUISTIC_SIGNAL_IDS, type EvidenceGroupsInput } from "@/lib/aiEvidenceGroups";
import { summarizeAIAttribution } from "@/lib/aiAttributionSummary";
import { runScan } from "@/lib/scanner";

/** `unknownLines` of source in files of 20 lines or fewer (too short to judge). */
const analysis = (loc: number, p: number, unknownLines = 0) =>
  summarizeAIAttribution([
    { file_path: "a.ts", line_count: loc, ai_percentage: p },
    ...Array.from({ length: Math.ceil(unknownLines / 20) }, (_, i) => ({ file_path: `t${i}.ts`, line_count: Math.min(20, unknownLines - i * 20), ai_percentage: 0 })),
  ], () => false);

const base = (over: Partial<EvidenceGroupsInput> = {}): EvidenceGroupsInput => ({
  codeEvidence: 0.6, analysis: analysis(500, 0.6),
  files: [{ line_count: 500, explained_signals: [{ id: "comment-phrasing", value: 0.7 }, { id: "nesting-depth", value: 0.9 }], watermarks: [] }],
  pr: { applicable: false, score: 0, notes: [] }, git: { applicable: false, score: 0, aiCommits: 0, totalCommits: 0 },
  baseline: { applicable: false, score: 0, reasons: [] }, tools: [], toolScore: 0, mixedAuthorship: false, ...over,
});
const group = (r: ReturnType<typeof buildEvidenceGroups>, id: string) => r.groups.find(g => g.id === id)!;

describe("groups", () => {
  it("reports all seven kinds of evidence, each with what it cannot show", () => {
    const r = buildEvidenceGroups(base());
    expect(r.groups.map(g => g.id)).toEqual(["direct_provenance", "code_structure", "linguistic_patterns", "code_evolution", "tool_metadata", "developer_baseline", "pr_context"]);
    for (const g of r.groups) expect(g.limitations.length).toBeGreaterThan(0);
  });

  it("shows the blend's weights, and none for the groups that are context only", () => {
    const r = buildEvidenceGroups(base());
    expect(r.groups.map(g => g.weight)).toEqual([0, 0.25, 0, 0.25, 0.10, 0.15, 0.25]);
    expect(GROUP_WEIGHTS.code_structure + GROUP_WEIGHTS.pr_context + GROUP_WEIGHTS.code_evolution + GROUP_WEIGHTS.developer_baseline + GROUP_WEIGHTS.tool_metadata).toBeCloseTo(1, 10);
  });

  it("a group with no data is not applicable and scores 0: missing evidence is not a human verdict", () => {
    const r = buildEvidenceGroups(base());
    for (const id of ["code_evolution", "tool_metadata", "developer_baseline", "pr_context", "direct_provenance"]) {
      expect(group(r, id)).toMatchObject({ applicable: false, score: 0, confidence: "none", evidence: [] });
    }
  });

  it("code structure carries the code evidence and says what it rests on", () => {
    const g = group(buildEvidenceGroups(base()), "code_structure");
    expect(g).toMatchObject({ applicable: true, score: 0.6 });
    expect(g.evidence[0]).toBe("60% of 500 analysed source lines look AI-written by file score");
  });

  it("names the lines it could not include", () => {
    const g = group(buildEvidenceGroups(base({ analysis: analysis(500, 0.6, 80) })), "code_structure");
    expect(g.limitations.join(" ")).toContain("80 lines in files too short to judge");
  });

  it("wording evidence uses only the wording signals, weighted by file size", () => {
    expect(LINGUISTIC_SIGNAL_IDS.has("comment-phrasing")).toBe(true);
    expect(LINGUISTIC_SIGNAL_IDS.has("nesting-depth")).toBe(false);
    const g = group(buildEvidenceGroups(base({ files: [
      { line_count: 300, explained_signals: [{ id: "comment-phrasing", value: 1 }], watermarks: [] },
      { line_count: 100, explained_signals: [{ id: "nesting-depth", value: 1 }], watermarks: [] },    // style: ignored
    ] })), "linguistic_patterns");
    expect(g.score).toBeCloseTo(0.75, 5);                                                          // 300·1 + 100·0 over 400
    expect(g.evidence[0]).toBe("Formulaic comment, message or documentation wording in 1 file");
    expect(g.weight).toBe(0);
  });

  it("files too short to analyse do not count towards wording evidence, in either direction", () => {
    const g = group(buildEvidenceGroups(base({ files: [
      { line_count: 400, explained_signals: [{ id: "comment-phrasing", value: 0.2 }], watermarks: [] },
      { line_count: 20, explained_signals: [{ id: "comment-phrasing", value: 1 }], watermarks: [] },      // too short: ignored
    ] })), "linguistic_patterns");
    expect(g.score).toBeCloseTo(0.2, 5);
    const onlyTiny = group(buildEvidenceGroups(base({ files: [{ line_count: 20, explained_signals: [{ id: "comment-phrasing", value: 1 }], watermarks: [] }] })), "linguistic_patterns");
    expect(onlyTiny).toMatchObject({ applicable: false, score: 0 });
  });

  it("watermarks are provenance-like but not authenticated, and say so", () => {
    const g = group(buildEvidenceGroups(base({ files: [{ line_count: 100, explained_signals: [], watermarks: [{}] }] })), "direct_provenance");
    expect(g).toMatchObject({ applicable: true, confidence: "medium" });
    expect(g.limitations.join(" ")).toContain("No authenticated generation record");
    expect(g.limitations.join(" ")).toContain("copy-pasting");
  });

  it("git history counts only commits that name an AI tool, and says it reads messages only", () => {
    const g = group(buildEvidenceGroups(base({ git: { applicable: true, score: 0.5, aiCommits: 1, totalCommits: 2 } })), "code_evolution");
    expect(g).toMatchObject({ applicable: true, score: 0.5, confidence: "medium" });
    expect(g.evidence).toEqual(["1 of 2 commits name an AI tool in the message"]);
    expect(group(buildEvidenceGroups(base({ git: { applicable: true, score: 0, aiCommits: 0, totalCommits: 3 } })), "code_evolution").confidence).toBe("low");
  });

  it("tool config is low confidence and says it does not show authorship", () => {
    const g = group(buildEvidenceGroups(base({ tools: ["Cursor"], toolScore: 0.35 })), "tool_metadata");
    expect(g).toMatchObject({ applicable: true, confidence: "low", evidence: ["Found: Cursor"] });
    expect(g.limitations[0]).toContain("not that this code came from it");
  });
});

describe("confidence is separate from likelihood", () => {
  const level = (o: Partial<EvidenceGroupsInput>) => buildEvidenceGroups(base(o)).confidence;

  it("nothing analysed: no confidence at all", () => {
    const c = level({ analysis: summarizeAIAttribution([{ file_path: "t.ts", line_count: 5, ai_percentage: 1 }], () => false), codeEvidence: 1 });
    expect(c.level).toBe("none");
    expect(c.reasons[0]).toContain("No source file was long enough");
  });

  it("a high percentage on a small analysed share is LOW confidence", () => {
    const c = level({ codeEvidence: 0.95, analysis: analysis(100, 0.95, 900) });          // 10% coverage
    expect(c.level).toBe("low");
    expect(c.reasons[0]).toBe("10% of the source code could be analysed.");
  });

  it("good coverage but only the code's own style is MEDIUM, and says nothing else can confirm it", () => {
    const c = level({});
    expect(c.level).toBe("medium");
    expect(c.reasons.join(" ")).toContain("Only the code's own style supports the number");
  });

  it("good coverage plus history or author evidence is HIGH", () => {
    const withGit = level({ git: { applicable: true, score: 0.5, aiCommits: 1, totalCommits: 2 } });
    expect(withGit.level).toBe("high");
    expect(withGit.reasons.join(" ")).toContain("git history");
    expect(level({ baseline: { applicable: true, score: 0.4, reasons: ["x"] } }).level).toBe("high");
  });

  it("PR behaviour and tool config never raise confidence (they do not corroborate who wrote the code)", () => {
    expect(level({ pr: { applicable: true, score: 0.9, notes: ["big"] }, tools: ["Cursor"], toolScore: 0.35 }).level).toBe("medium");
  });

  it("mixed authorship caps it at medium and says why", () => {
    const c = level({ git: { applicable: true, score: 0.5, aiCommits: 1, totalCommits: 2 }, mixedAuthorship: true });
    expect(c.level).toBe("medium");
    expect(c.reasons.join(" ")).toContain("files disagree strongly");
  });

  it("lists the evidence that does not exist for this scan", () => {
    expect(level({}).unavailable).toEqual(["git history", "the author's baseline", "pull-request details"]);
    expect(level({ git: { applicable: true, score: 0, aiCommits: 0, totalCommits: 2 }, pr: { applicable: true, score: 0, notes: [] }, baseline: { applicable: true, score: 0, reasons: [] } }).unavailable).toEqual([]);
  });
});

describe("the scan carries it, without changing the score", () => {
  const long = Array.from({ length: 80 }, (_, i) => `export const value${i} = ${i};`).join("\n");
  const input = { repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main", files: [{ path: "src/a.ts", content: long }] };

  it("runScan returns ai_evidence with groups and a confidence level", () => {
    const r = runScan(input);
    expect(r.ai_evidence!.groups).toHaveLength(7);
    expect(["none", "low", "medium", "high"]).toContain(r.ai_evidence!.confidence.level);
    expect(r.ai_evidence!.confidence.unavailable).toContain("git history");
  });

  it("its code-structure score is the scan's code evidence", () => {
    const r = runScan(input);
    expect(r.ai_evidence!.groups.find(g => g.id === "code_structure")!.score).toBeCloseTo(r.evidence_breakdown.code_evidence, 10);
  });

  it("a git log makes git history applicable", () => {
    const log = "1111111111111111111111111111111111111111|Ana|ana@a.example|1700000000|G|Generated by Copilot: add handler\n2222222222222222222222222222222222222222|Ana|ana@a.example|1700000100|G|fix typo";
    const r = runScan({ ...input, git_log: log });
    expect(r.ai_evidence!.groups.find(g => g.id === "code_evolution")).toMatchObject({ applicable: true, score: 0.5 });
    expect(r.ai_evidence!.confidence.unavailable).not.toContain("git history");
  });

  it("is deterministic", () => {
    expect(runScan(input).ai_evidence).toEqual(runScan(input).ai_evidence);
  });
});

describe("it is saved with the scan", () => {
  const long = Array.from({ length: 80 }, (_, i) => `export const value${i} = ${i};`).join("\n");
  it("evidence_breakdown (the stored JSON) carries the same report, so a saved scan keeps it", () => {
    const r = runScan({ repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main", files: [{ path: "src/a.ts", content: long }] });
    expect(r.evidence_breakdown.attribution).toEqual(r.ai_evidence);
    expect(JSON.parse(JSON.stringify(r.evidence_breakdown)).attribution.groups).toHaveLength(7);
  });
  it("and does not change the combined score or its likelihood band", () => {
    const r = runScan({ repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main", files: [{ path: "src/a.ts", content: long }] });
    const { attribution, ...rest } = r.evidence_breakdown;
    expect(attribution).toBeDefined();
    expect(rest.combined).toBeCloseTo(rest.code_evidence * 0.25 + rest.pr_evidence * 0.25 + rest.git_evidence * 0.25 + rest.baseline_evidence * 0.15 + rest.tool_evidence * 0.10, 10);
  });
});
