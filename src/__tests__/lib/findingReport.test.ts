import { analyzeFile, getFixSuggestions } from "@/lib/scanner";
import { toStoredIndicators } from "@/lib/indicatorStorage";
import { collectFindingReports, buildFindingReport, partsToText, inputToSink } from "@/lib/findingReport";
import { buildCheckAnnotations, MAX_CHECK_ANNOTATIONS } from "@/lib/checkAnnotations";
import { buildPRCommentDirect } from "@/lib/githubComment";
import { buildCheckSummary } from "@/lib/github";
import { findingMeta } from "@/lib/findingCatalog";
import type { FileIndicator } from "@/types";

// Unified finding evidence: every surface outside the PR page (check-run annotations, PR comment, check
// summary, SARIF -- see sarif.test.ts) renders the same report, driven here by real scanner output.

const PATH = "src/routes/users.ts";
const ROUTE = [
  `function listUsers(req, res) {`,
  `  const name = req.query.name;`,
  `  const sql = "SELECT * FROM users WHERE name = '" + name + "'";`,
  `  db.query(sql);`,
  `  res.send("<h1>" + name + "</h1>");`,
  `}`,
  `app.get("/users", listUsers);`,
  ``,
].join("\n");

const analysis = analyzeFile(PATH, ROUTE);
const files = [{ file_path: PATH, indicators: analysis.indicators as FileIndicator[], fix_suggestions: analysis.fix_suggestions }];

describe("collectFindingReports", () => {
  const reports = collectFindingReports(files);

  it("keeps CWE-mapped findings in the project's own code, most severe first", () => {
    expect(reports.length).toBeGreaterThan(0);
    expect(reports.every(r => !!r.cwe)).toBe(true);
    const ranks = reports.map(r => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 })[r.severity]);
    expect([...ranks].sort((a, b) => b - a)).toEqual(ranks);
  });

  it("excludes AI-authorship signals and findings in test or vendored code", () => {
    const base: FileIndicator = { id: "sql-injection", label: "SQL", severity: "critical", line: 3, cwe: "CWE-89" };
    const got = collectFindingReports([{ file_path: "a.ts", indicators: [
      base,
      { ...base, line: 4, codeCategory: "test_code" },
      { ...base, line: 5, codeCategory: "third_party" },
      { id: "doc-coverage", label: "Doc coverage", severity: "low", line: 6 },
    ] }]);
    expect(got.map(r => r.line)).toEqual([3]);
  });

  it("names every finding from the shared catalog", () => {
    for (const r of reports) expect(r.title).toBe(findingMeta(r.id).title);
  });
});

describe("check-run annotations", () => {
  const annotations = buildCheckAnnotations(files, { reviewUrl: "https://app.example/pr/1" });
  const sql = annotations.find(a => a.title.startsWith("SQL Injection") && a.message.includes("Input → sink"))!;

  it("annotate the flagged line with name, CWE and severity", () => {
    expect(sql).toBeDefined();
    expect(sql.path).toBe(PATH);
    expect(sql.start_line).toBe(4);
    expect(sql.end_line).toBe(4);
    expect(sql.annotation_level).toBe("failure");
    expect(sql.title).toBe("SQL Injection (CWE-89) · CRITICAL");
  });

  it("explain the flow from the real input to the sink, and give the fix", () => {
    expect(sql.message).toContain("req.query.name");
    expect(sql.message).toContain("`req.query.name` → 1 step → `db.query(sql)`");
    expect(sql.message).toMatch(/Fix: Use parameterised queries/);
    expect(sql.message).toContain("https://app.example/pr/1");
    expect(sql.raw_details).toContain("Data flow:");
    expect(sql.raw_details).toContain("L2 Input: req.query.name");
    expect(sql.raw_details).toContain("Why this was flagged:");
  });

  it("stay within GitHub's per-update limit, keeping the most severe", () => {
    const many: FileIndicator[] = Array.from({ length: 80 }, (_, i) => ({
      id: i < 70 ? "weak-crypto" : "sql-injection", label: "x", severity: i < 70 ? "medium" : "critical", line: i + 1, cwe: "CWE-1",
    }));
    const out = buildCheckAnnotations([{ file_path: "a.ts", indicators: many }]);
    expect(out).toHaveLength(MAX_CHECK_ANNOTATIONS);
    expect(out.slice(0, 10).every(a => a.annotation_level === "failure")).toBe(true);
  });

  it("skip low-severity findings", () => {
    const out = buildCheckAnnotations([{ file_path: "a.ts", indicators: [{ id: "cookie-no-secure", label: "x", severity: "low", line: 1, cwe: "CWE-614" }] }]);
    expect(out).toEqual([]);
  });
});

describe("PR comment", () => {
  const comment = buildPRCommentDirect({
    scan_id: "abcdef123456", repo: "o/r", pr_number: 1, overall_risk: "CRITICAL", total_ai_percentage: 0.2,
    files: [{ file_path: PATH, risk_score: "CRITICAL", ai_percentage: 0.2, risk_indicators: analysis.risk_indicators, attested: false }],
    appUrl: "https://app.example",
    findings: collectFindingReports(files),
  });

  it("lists each security finding with its location and plain-language explanation", () => {
    expect(comment).toContain("**Security findings**");
    expect(comment).toContain(`**SQL Injection (CWE-89)** in \`${PATH}:4\``);
    expect(comment).toContain("Untrusted input `req.query.name` (URL query parameter)");
  });

  it("names XSS in the file list (the old hand-picked label table silently omitted it)", () => {
    const fileListOnly = buildPRCommentDirect({
      scan_id: "abcdef123456", repo: "o/r", pr_number: 1, overall_risk: "HIGH", total_ai_percentage: 0,
      files: [{ file_path: PATH, risk_score: "HIGH", ai_percentage: 0, risk_indicators: ["xss", "doc-coverage"], attested: false }],
      appUrl: "https://app.example",
    });
    expect(fileListOnly).toMatch(/- ⏳ `routes\/users\.ts` — .* · Cross-Site Scripting/);
  });
});

describe("check summary", () => {
  it("uses finding names, not raw ids", () => {
    const { summary } = buildCheckSummary({ overall_risk: "CRITICAL", total_ai_percentage: 0,
      files: [{ file_path: PATH, risk_score: "CRITICAL", risk_indicators: ["sql-injection", "xss"] }] });
    expect(summary).toContain("SQL Injection, Cross-Site Scripting");
    expect(summary).not.toContain("sql-injection");
  });
});

describe("markdown safety", () => {
  it("keeps code that contains backticks intact and neutralises HTML in engine text", () => {
    const r = buildFindingReport({
      id: "xss", label: "XSS", severity: "high", line: 2, cwe: "CWE-79",
      sourceExpr: "`<b>${req.query.q}</b>`", sinkExpr: "res.send",
      detail: "Value <script> reaches res.send | escaped in the wrong context",
    }, "a.ts");
    const md = partsToText(r.evidence.summary, "markdown");
    expect(md).toContain("&lt;script&gt;");
    expect(md).toContain("\\|");
    const r2 = buildFindingReport({ id: "xss", label: "XSS", severity: "high", line: 2, sourceExpr: "`<b>${x}</b>`", sinkExpr: "res.send" }, "a.ts");
    expect(inputToSink(r2, "markdown")).toContain("`` `<b>${x}</b>` ``");
  });
});

describe("stored findings (what SARIF and inherited files use) produce the same report", () => {
  it("fresh and stored indicators render identically", () => {
    const stored = toStoredIndicators(analysis.indicators);
    const fixes = new Map(getFixSuggestions(stored).map(f => [f.vuln_id, f]));
    const fresh = collectFindingReports(files).map(r => partsToText(r.evidence.summary));
    const fromStored = collectFindingReports([{ file_path: PATH, indicators: stored }], fixes).map(r => partsToText(r.evidence.summary));
    expect(fromStored).toEqual(fresh);
  });
});
