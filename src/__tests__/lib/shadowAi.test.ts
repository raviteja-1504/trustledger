/**
 * @jest-environment node
 *
 * Shadow AI built from stored scan evidence: explicit evidence of an unapproved tool is a violation; a style-based
 * guess is only ever a hint; nothing is a violation until an org sets a policy; a resolved detection seen again
 * reopens.
 */
import { toolId, normalizePolicy, detectCommitEvidence, UNSPECIFIED_TOOL } from "@/lib/aiTools";
import { buildDetections, summarize, approvalOf, detectionKey, HINT_MIN_CONFIDENCE, unapprovedToolsInScan, shadowAiCheckMarkdown, type ScanRow, type FileRow, type TriageRow } from "@/lib/shadowAi";

const scan = (id: string, over: Partial<ScanRow> = {}): ScanRow => ({
  id, repo_full_name: "acme/app", pr_number: 7, pr_author: "dev-a", created_at: "2026-10-10T00:00:00Z", ai_tooling: [], ...over,
});

describe("tool catalog", () => {
  it("maps the scanner's names and the style guesser's ids onto one id", () => {
    expect(toolId("Claude Code")).toBe("claude");
    expect(toolId("claude")).toBe("claude");
    expect(toolId("GitHub Copilot")).toBe("github-copilot");
    expect(toolId("github-copilot")).toBe("github-copilot");
    expect(toolId("Codeium")).toBe("windsurf");
    expect(toolId("AI Agents")).toBe(UNSPECIFIED_TOOL);
    expect(toolId("human")).toBeNull();
    expect(toolId("unknown")).toBeNull();
    expect(toolId(undefined)).toBeNull();
  });

  it("a submitted policy keeps only known tools, once, in catalog order", () => {
    expect(normalizePolicy(["claude", "evil", "github-copilot", "claude", 3])).toEqual(["github-copilot", "claude"]);
    expect(normalizePolicy("claude")).toEqual([]);
  });
});

describe("commit evidence", () => {
  it("finds AI co-author trailers and AI bot authors, one entry per (commit, tool)", () => {
    const ev = detectCommitEvidence([
      { sha: "aaa1111", message: "Fix login\n\nCo-Authored-By: Claude Opus <noreply@anthropic.com>\n\nGenerated with [Claude Code]" },
      { sha: "bbb2222", message: "Add tests\n\nCo-authored-by: Copilot <copilot@github.com>" },
      { sha: "ccc3333", message: "Refactor", author_login: "devin-ai-integration[bot]" },
      { sha: "ddd4444", message: "Plain human commit\n\nCo-authored-by: Jane Doe <jane@acme.dev>" },
      { sha: "eee5555", message: "mentions claude in passing: co-authored-by claude is our convention" },
    ]);
    expect(ev).toEqual([
      { tool: "claude", sha: "aaa1111", label: "Claude co-author trailer on commit" },
      { tool: "github-copilot", sha: "bbb2222", label: "Copilot co-author trailer on commit" },
      { tool: "devin", sha: "ccc3333", label: "Commit authored by Devin" },
    ]);
  });
});

describe("buildDetections", () => {
  const scans = [
    scan("s1", { created_at: "2026-10-10T00:00:00Z", ai_tooling: [{ tool: "Cursor", file: ".cursorrules", label: "Cursor AI agent rules file" }] }),
    scan("s2", { created_at: "2026-10-12T00:00:00Z", pr_number: 9, pr_author: "dev-b", ai_tooling: [{ tool: "Cursor", file: ".cursorrules", label: "Cursor AI agent rules file" }, { tool: "claude", file: "commit:aaa1111", label: "Claude co-author trailer on commit" }] }),
    scan("s3", { ai_tooling: [{ tool: "AI Agents", file: "AGENTS.md", label: "Generic AI agent instructions" }] }),
  ];
  const files: FileRow[] = [
    { scan_id: "s1", file_path: "src/a.ts", attribution: { model: "chatgpt", confidence: 0.95 } },
    { scan_id: "s1", file_path: "src/b.ts", attribution: { model: "gemini", confidence: HINT_MIN_CONFIDENCE - 0.01 } },
    { scan_id: "s1", file_path: "src/c.ts", attribution: { model: "human", confidence: 0.99 } },
  ];

  it("only explicit evidence of an UNAPPROVED tool is a violation; a confident style guess is still a hint", () => {
    const ds = buildDetections(scans, files, ["claude"], new Map());
    const cursor = ds.find(d => d.tool === "cursor")!;
    expect(cursor).toMatchObject({ tier: "explicit", approval: "unapproved", violation: true });
    expect(ds.find(d => d.tool === "claude")).toMatchObject({ tier: "explicit", approval: "approved", violation: false, location: "commit:aaa1111" });
    const chatgpt = ds.find(d => d.tool === "chatgpt")!;
    expect(chatgpt).toMatchObject({ tier: "hint", approval: "unapproved", violation: false, confidence: 0.95 });
    expect(ds.some(d => d.tool === "gemini")).toBe(false);                // below the hint threshold
    expect(ds.find(d => d.tool === UNSPECIFIED_TOOL)).toMatchObject({ approval: "unidentified", violation: false });
  });

  it("one detection per (repo, tool, location) across scans, with every author, PR and date range", () => {
    const cursor = buildDetections(scans, [], ["claude"], new Map()).find(d => d.tool === "cursor")!;
    expect(cursor).toMatchObject({
      key: detectionKey("acme/app", "cursor", ".cursorrules"), scans: 2,
      developers: ["dev-a", "dev-b"], pull_requests: [7, 9],
      first_seen: "2026-10-10T00:00:00Z", last_seen: "2026-10-12T00:00:00Z",
    });
  });

  it("explicit evidence outranks a hint for the same file", () => {
    const ds = buildDetections(
      [scan("s1", { ai_tooling: [{ tool: "ChatGPT", file: "src/a.ts", label: "\"Generated by ChatGPT\" marker" }] })],
      [{ scan_id: "s1", file_path: "src/a.ts", attribution: { model: "chatgpt", confidence: 0.7 } }], [], new Map());
    expect(ds).toHaveLength(1);
    expect(ds[0]).toMatchObject({ tier: "explicit", confidence: 1, violation: true, scans: 1 });   // one scan, not two
    expect(ds[0].evidence).toHaveLength(2);
  });

  it("without a policy nothing is a violation", () => {
    const ds = buildDetections(scans, files, null, new Map());
    expect(ds.some(d => d.violation)).toBe(false);
    expect(ds.find(d => d.tool === "cursor")!.approval).toBe("unreviewed");
  });

  it("triage sticks; a resolved detection seen again afterwards reopens", () => {
    const key = detectionKey("acme/app", "cursor", ".cursorrules");
    const before: TriageRow = { status: "resolved", notes: [{ at: "x", by: "a@b", text: "removed" }], updated_at: "2026-10-11T00:00:00Z" };
    const after: TriageRow = { ...before, updated_at: "2026-10-13T00:00:00Z" };
    const accepted: TriageRow = { ...before, status: "acceptable", updated_at: "2026-10-11T00:00:00Z" };
    const get = (t: TriageRow) => buildDetections(scans, [], ["claude"], new Map([[key, t]])).find(d => d.key === key)!;
    expect(get(before)).toMatchObject({ status: "open", reopened: true });           // seen 10-12 after resolving 10-11
    expect(get(after)).toMatchObject({ status: "resolved", reopened: false });
    expect(get(accepted)).toMatchObject({ status: "acceptable", reopened: false }); // an accepted risk doesn't reopen
    expect(get(after).notes).toHaveLength(1);
  });

  it("violations sort first", () => {
    const ds = buildDetections(scans, files, ["claude"], new Map());
    expect(ds[0].violation).toBe(true);
    expect(ds.slice(1).every(d => !d.violation)).toBe(true);
  });
});

describe("pull request warning", () => {
  const tooling = [
    { tool: "Cursor", file: ".cursorrules", label: "Cursor AI agent rules file" },
    { tool: "cursor", file: "commit:9f2c1a4", label: "Cursor co-author trailer on commit" },
    { tool: "Claude Code", file: "CLAUDE.md", label: "Claude Code project instructions" },
    { tool: "AI Agents", file: "AGENTS.md", label: "Generic AI agent instructions" },
  ];

  it("lists only unapproved, identifiable tools, grouped, with where the evidence is", () => {
    expect(unapprovedToolsInScan(tooling, ["claude"])).toEqual([
      { tool: "cursor", label: "Cursor", evidence: ["`.cursorrules` (Cursor AI agent rules file)", "commit 9f2c1a4 (Cursor co-author trailer on commit)"] },
    ]);
  });

  it("leaves out evidence a reviewer accepted for this repository (other repos and other statuses still warn)", () => {
    const triage = new Map<string, Pick<TriageRow, "status">>([
      [detectionKey("acme/app", "cursor", ".cursorrules"), { status: "acceptable" }],
      [detectionKey("acme/app", "cursor", "commit:9f2c1a4"), { status: "resolved" }],
    ]);
    expect(unapprovedToolsInScan(tooling, ["claude"], { repo: "acme/app", triage })).toEqual([
      { tool: "cursor", label: "Cursor", evidence: ["commit 9f2c1a4 (Cursor co-author trailer on commit)"] },
    ]);
    expect(unapprovedToolsInScan(tooling, ["claude"], { repo: "acme/web", triage })[0].evidence).toHaveLength(2);
    // everything accepted: no warning at all
    triage.set(detectionKey("acme/app", "cursor", "commit:9f2c1a4"), { status: "acceptable" });
    expect(unapprovedToolsInScan(tooling, ["claude"], { repo: "acme/app", triage })).toEqual([]);
  });

  it("says nothing without a policy, or when everything is approved", () => {
    expect(unapprovedToolsInScan(tooling, null)).toEqual([]);
    expect(unapprovedToolsInScan(tooling, ["cursor", "claude"])).toEqual([]);
    expect(shadowAiCheckMarkdown([], "https://x/shadow-ai")).toBe("");
  });

  it("is a warning that states it doesn't block, and caps long evidence lists", () => {
    const many = Array.from({ length: 5 }, (_, i) => ({ tool: "Cursor", file: `f${i}.ts`, label: "marker" }));
    const md = shadowAiCheckMarkdown(unapprovedToolsInScan(many, []), "https://app.example/shadow-ai");
    expect(md).toContain("### Unapproved AI tools (warning)");
    expect(md).toContain("does not block the merge");
    expect(md).toContain("and 2 more");
    expect(md).toContain("[Shadow AI](https://app.example/shadow-ai)");
  });
});

describe("summarize", () => {
  it("counts open violations, compliance and affected developers", () => {
    const scans = [
      scan("s1", { pr_author: "dev-a", ai_tooling: [{ tool: "Cursor", file: ".cursorrules" }, { tool: "GitHub Copilot", file: ".github/copilot-instructions.md" }] }),
      scan("s2", { repo_full_name: "acme/other", pr_author: "dev-b", ai_tooling: [{ tool: "Windsurf", file: ".windsurfrules" }] }),
    ];
    const resolved = new Map([[detectionKey("acme/other", "windsurf", ".windsurfrules"), { status: "resolved" as const, notes: [], updated_at: "2027-01-01T00:00:00Z" }]]);
    const ds = buildDetections(scans, [], ["github-copilot"], resolved);
    const s = summarize(ds, ["github-copilot"]);
    expect(s).toMatchObject({ policy_configured: true, violations: 2, open_violations: 1, approved_usage: 1, developers_with_violations: 1 });
    expect(s.compliance).toBeCloseTo(1 / 2);   // copilot vs cursor; the resolved windsurf violation is excluded
    expect(summarize(ds, null).compliance).toBeNull();
    expect(summarize([], ["claude"]).compliance).toBeNull();
    expect(approvalOf("claude", null)).toBe("unreviewed");
  });

  it("per tool, violations are split by status: an accepted one is not an open violation", () => {
    const scans = [
      scan("s1", { ai_tooling: [{ tool: "Cursor", file: ".cursorrules" }, { tool: "cursor", file: "commit:a1" }, { tool: "cursor", file: "commit:b2" }, { tool: "cursor", file: "commit:c3" }] }),
      scan("s2", { ai_tooling: [{ tool: "Windsurf", file: ".windsurfrules" }] }),
    ];
    const t = (status: TriageRow["status"]) => ({ status, notes: [], updated_at: "2027-01-01T00:00:00Z" });
    const triage = new Map([
      [detectionKey("acme/app", "cursor", ".cursorrules"), t("acceptable")],
      [detectionKey("acme/app", "cursor", "commit:a1"), t("resolved")],
      [detectionKey("acme/app", "cursor", "commit:b2"), t("investigating")],
      [detectionKey("acme/app", "windsurf", ".windsurfrules"), t("acceptable")],
    ]);
    const s = summarize(buildDetections(scans, [], ["claude"], triage), ["claude"]);
    expect(s.by_tool.map(x => [x.tool, x.violations, x.open, x.accepted, x.resolved])).toEqual([
      // cursor: c3 open + b2 investigating = 2 open; windsurf: accepted only, so it sorts after
      ["cursor", 4, 2, 1, 1], ["windsurf", 1, 0, 1, 0],
    ]);
    // open violations sort first, whatever the total: 3 accepted Devin files come after 1 open Windsurf file
    const many = [scan("s3", { ai_tooling: [{ tool: "Devin", file: "a" }, { tool: "Devin", file: "b" }, { tool: "Devin", file: "c" }, { tool: "Windsurf", file: "w" }] })];
    const accepted = new Map(["a", "b", "c"].map(f => [detectionKey("acme/app", "devin", f), t("acceptable")]));
    expect(summarize(buildDetections(many, [], ["claude"], accepted), ["claude"]).by_tool.map(x => x.tool)).toEqual(["windsurf", "devin"]);
  });

  it("'needs review' leaves out what a reviewer accepted or resolved", () => {
    const scans = [scan("s1", { ai_tooling: [{ tool: "AI Agents", file: "AGENTS.md" }, { tool: "AI Agents", file: "docs/AGENTS.md" }, { tool: "AI Agents", file: "x/AGENTS.md" }] })];
    const triage = new Map([
      [detectionKey("acme/app", UNSPECIFIED_TOOL, "AGENTS.md"), { status: "acceptable" as const, notes: [], updated_at: "2027-01-01T00:00:00Z" }],
      [detectionKey("acme/app", UNSPECIFIED_TOOL, "docs/AGENTS.md"), { status: "resolved" as const, notes: [], updated_at: "2027-01-01T00:00:00Z" }],
    ]);
    const s = summarize(buildDetections(scans, [], ["claude"], triage), ["claude"]);
    expect([s.unidentified, s.needs_review]).toEqual([3, 1]);
    // without a policy every identified tool is undecided too
    expect(summarize(buildDetections([scan("s2", { ai_tooling: [{ tool: "Cursor", file: ".cursorrules" }] })], [], null, new Map()), null).needs_review).toBe(1);
  });
});
