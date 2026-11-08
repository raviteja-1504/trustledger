import { buildPRCommentDirect, MAX_FILE_ROWS } from "@/lib/githubComment";
import type { FindingReport } from "@/lib/findingReport";

type F = Parameters<typeof buildPRCommentDirect>[0]["files"][number];
const file = (path: string, risk: string, over: Partial<F> = {}): F => ({ file_path: path, risk_score: risk, ai_percentage: 0.5, risk_indicators: [], attested: false, ...over });
const finding = (filePath: string, severity: FindingReport["severity"], title: string, line?: number): FindingReport =>
  ({ id: "x", title, severity, filePath, line, evidence: { summary: [{ text: "SECRET-DETAIL" }], flow: [], checks: [] } } as unknown as FindingReport);
const build = (files: F[], findings?: FindingReport[]) => buildPRCommentDirect({
  scan_id: "abcdef123456", repo: "o/r", pr_number: 1, overall_risk: "CRITICAL", total_ai_percentage: 0.4, files, findings, appUrl: "https://app.example",
});
const rows = (c: string) => c.split("\n").filter(l => l.startsWith("| `"));

describe("PR comment: the Critical and High files table", () => {
  it("has the columns a reviewer needs, one row per file", () => {
    const c = build([file("src/a.ts", "CRITICAL"), file("src/b.ts", "HIGH")]);
    expect(c).toContain("| File | Risk | Findings | Top issues | Reachable | AI | Status |");
    expect(rows(c)).toHaveLength(2);
    expect(c).toContain("**Critical and High files** (2, 2 to attest):");
  });

  it("never shows the data flow: no source/sink paths, no finding explanations", () => {
    const c = build([file("src/a.ts", "CRITICAL")], [finding("src/a.ts", "critical", "SQL Injection", 4)]);
    expect(c).not.toContain("SECRET-DETAIL");
    expect(c).not.toContain("<sub>");
    expect(c).not.toContain("**Security findings**");
  });

  it("counts findings by severity, most severe first, and names the top issues with their lines", () => {
    const c = build([file("src/a.ts", "CRITICAL")], [
      finding("src/a.ts", "high", "XSS", 20), finding("src/a.ts", "critical", "SQL Injection", 4), finding("src/a.ts", "critical", "SQL Injection", 9), finding("src/a.ts", "medium", "Weak Hash", 30),
    ]);
    expect(rows(c)[0]).toContain("| 2 critical · 1 high · 1 medium |");
    expect(rows(c)[0]).toContain("SQL Injection (L4), XSS (L20) +1 more");
  });

  it("falls back to the file's security signals when no finding detail is available, and to a dash when it has none", () => {
    const withSignal = build([file("src/a.ts", "HIGH", { risk_indicators: ["sql-injection"] })]);
    expect(rows(withSignal)[0]).toMatch(/\| — \| SQL Injection \|/);
    const none = build([file("src/a.ts", "HIGH", { risk_indicators: ["doc-coverage"] })]);
    expect(rows(none)[0]).toMatch(/\| — \| — \|/);
  });

  it("puts CRITICAL files first, and within a rating the file with the most serious findings", () => {
    const c = build(
      [file("src/low-sev.ts", "HIGH"), file("src/worst.ts", "CRITICAL"), file("src/more-sev.ts", "HIGH")],
      [finding("src/low-sev.ts", "medium", "A"), finding("src/more-sev.ts", "high", "B")],
    );
    expect(rows(c).map(r => r.match(/`([^`]+)`/)![1])).toEqual(["src/worst.ts", "src/more-sev.ts", "src/low-sev.ts"]);
  });

  it("shows the reachable count, the AI share and each file's attestation status", () => {
    const c = build([
      file("src/a.ts", "CRITICAL", { reachable_indicator_labels: ["SQL Injection", "XSS"], ai_percentage: 0.62 }),
      file("src/b.ts", "HIGH", { attested: true, ai_percentage: 0.1 }),
    ]);
    const [a, b] = rows(c);
    expect(a).toContain("🎯 2");
    expect(a).toContain("| 62% |");
    expect(a).toContain("⏳ to attest");
    expect(b).toContain("| — | 10% | ✅ attested |");
  });

  it("says when everything is attested", () => {
    expect(build([file("src/a.ts", "CRITICAL", { attested: true })])).toContain("(1, all attested)");
  });

  it("caps the rows and says how many more there are", () => {
    const many = Array.from({ length: MAX_FILE_ROWS + 4 }, (_, i) => file(`src/f${String(i).padStart(2, "0")}.ts`, "HIGH"));
    const c = build(many);
    expect(rows(c)).toHaveLength(MAX_FILE_ROWS);
    expect(c).toContain("_…and 4 more. The full list is in TrustLedger._");
    expect(c).toContain(`(${MAX_FILE_ROWS + 4}, ${MAX_FILE_ROWS + 4} to attest)`);
  });

  it("a pipe in a finding title or path can't break the table", () => {
    const c = build([file("src/a|b.ts", "CRITICAL")], [finding("src/a|b.ts", "critical", "Weird | Title", 1)]);
    const row = rows(c)[0];
    expect(row).toContain("a\\|b.ts");
    expect(row).toContain("Weird \\| Title (L1)");
    expect(row.replace(/\\\|/g, "").split("|")).toHaveLength(9);                  // 7 cells + the two outer edges
  });

  it("no table when no file is Critical or High", () => {
    const c = build([file("src/a.ts", "MEDIUM"), file("src/b.ts", "LOW")]);
    expect(c).not.toContain("| File |");
    expect(c).not.toContain("Critical and High files");
  });
});
