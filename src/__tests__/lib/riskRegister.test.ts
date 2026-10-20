/**
 * Risk register derivation and merge (lib/riskRegister.ts): derived risks state facts only -- open, unassigned,
 * no due date, no invented residuals -- and what people recorded is applied without blanking anything.
 */
import { deriveRisks, mergeRisks, rowsToStore, type RiskItem, type RiskRow } from "@/lib/riskRegister";
import type { DashboardData, ScanResult } from "@/types";

const file = (repo: string, path: string, risk: string, attested = false, ai = 0.5) =>
  ({ repo, file_path: path, risk_score: risk, attested, ai_pct: ai, scan_id: "s1", pr_number: 1 });
const data = (files: ReturnType<typeof file>[], repos: Array<{ repo: string; attestation_rate: number; high_crit_count?: number }> = []) =>
  ({ top_risk_files: files, repos, unattested_deploy_count: 99 } as unknown as DashboardData);
const scan = (repo: string, files: Array<{ file_path: string; risk_indicators: string[] }>) => ({ repo, files } as unknown as ScanResult);
const T = "2026-10-20T12:00:00Z";

describe("deriveRisks", () => {
  it("derived risks are open, unassigned, with no due date or residual scores, identified today", () => {
    const risks = deriveRisks(data([file("acme/api", "src/a.ts", "CRITICAL")]), [scan("acme/api", [{ file_path: "src/k.ts", risk_indicators: ["eval-exec"] }])], T);
    expect(risks.length).toBeGreaterThan(0);
    for (const r of risks) {
      expect(r).toMatchObject({ status: "open", owner: "unassigned", treatment: "mitigate", auto_derived: true, identified_at: "2026-10-20", notes: [] });
      expect(r.due_date).toBeUndefined();
      expect(r.residual_likelihood).toBeUndefined();
      expect(r.residual_impact).toBeUndefined();
    }
  });

  it("unsigned CRITICAL / HIGH files: one risk per repo and level; signed-off and MEDIUM files don't count", () => {
    const risks = deriveRisks(data([
      file("acme/api", "src/a.ts", "CRITICAL", false, 0.8), file("acme/api", "src/b.ts", "CRITICAL", false, 0.4),
      file("acme/api", "src/c.ts", "CRITICAL", true), file("acme/web", "src/h.ts", "HIGH"), file("acme/web", "src/m.ts", "MEDIUM"),
    ]), [], T);
    const crit = risks.find(r => r.id === "DR-CRIT-UNATT-acme-api")!;
    expect(crit).toMatchObject({ likelihood: 5, impact: 5, repo: "acme/api", title: "2 CRITICAL files unattested in api — merge blocked" });
    expect(crit.description).toBe("a.ts, b.ts flagged CRITICAL (avg 60% AI-written) and not yet signed off.");
    expect(risks.find(r => r.id === "DR-HIGH-UNATT-acme-web")!.title).toBe("1 HIGH-risk file awaiting attestation in web");
    expect(risks.some(r => r.id === "DR-CRIT-UNATT-acme-web" || r.id === "DR-HIGH-UNATT-acme-api")).toBe(false);
  });

  it("the org-wide backlog counts the waiting files and repos, not the server's violation count", () => {
    const risks = deriveRisks(data([file("acme/api", "a", "CRITICAL"), file("acme/api", "b", "HIGH"), file("acme/web", "c", "HIGH"), file("acme/web", "d", "HIGH", true)]), [], T);
    expect(risks.find(r => r.id === "DR-DEPLOY-BLOCK")!.title).toBe("3 HIGH/CRITICAL files awaiting sign-off across 2 repos");
    expect(deriveRisks(data([file("acme/api", "a", "HIGH", true)]), [], T).some(r => r.id === "DR-DEPLOY-BLOCK")).toBe(false);
  });

  it("risk patterns come from the latest scans' files, with their CWE", () => {
    const risks = deriveRisks(data([]), [
      scan("acme/api", [{ file_path: "src/db.py", risk_indicators: ["sql-injection"] }, { file_path: "src/q.py", risk_indicators: ["sql-injection", "hardcoded-secret"] }]),
      scan("acme/web", [{ file_path: "src/jwt.ts", risk_indicators: ["jwt-none-alg"] }]),
    ], T);
    const sql = risks.find(r => r.id === "DR-SQL-INJECT-acme-api")!;
    expect(sql).toMatchObject({ title: "SQL injection pattern in 2 files in api", category: "ai-code", related_link: "/violations" });
    expect(sql.related_cwe).toMatch(/^CWE-89/);
    expect(risks.find(r => r.id === "DR-SECRETS-acme-api")).toMatchObject({ category: "secrets", title: "1 hardcoded credential detected in api" });
    expect(risks.find(r => r.id === "DR-JWT-BYPASS-acme-web")!.status).toBe("open");   // was pre-marked "mitigating"
    expect(risks.some(r => r.id.startsWith("DR-EVAL-EXEC"))).toBe(false);
  });

  it("long file lists are shortened", () => {
    const files = Array.from({ length: 7 }, (_, i) => file("acme/api", `src/f${i}.ts`, "HIGH"));
    expect(deriveRisks(data(files), [], T).find(r => r.id === "DR-HIGH-UNATT-acme-api")!.description).toMatch(/^f0\.ts, f1\.ts, f2\.ts, f3\.ts, f4\.ts and 2 more flagged HIGH/);
  });

  it("low attestation: only repos below 60% that have HIGH/CRITICAL files", () => {
    const risks = deriveRisks(data([], [
      { repo: "acme/api", attestation_rate: 0.5, high_crit_count: 4 }, { repo: "acme/web", attestation_rate: 0.6, high_crit_count: 2 },
      { repo: "acme/empty", attestation_rate: 0, high_crit_count: 0 },
    ]), [], T);
    const low = risks.filter(r => r.id.startsWith("DR-LOW-ATT"));
    expect(low.map(r => r.id)).toEqual(["DR-LOW-ATT-acme-api"]);
    expect(low[0]).toMatchObject({ title: "Low attestation — api at 50%", related_link: "/repo/acme/api" });
    expect(low[0].mitigation).not.toMatch(/LOW and MEDIUM/);
  });

  it("each id appears once even when two repo names slug the same", () => {
    const risks = deriveRisks(data([file("acme/a.b", "x", "HIGH"), file("acme/a-b", "y", "HIGH")]), [], T);
    expect(risks.filter(r => r.id === "DR-HIGH-UNATT-acme-a-b")).toHaveLength(1);
  });
});

const derived = (o: Partial<RiskItem> = {}): RiskItem => ({
  id: "DR-X", title: "t", description: "d", category: "ai-code", likelihood: 4, impact: 4, status: "open", treatment: "mitigate",
  owner: "unassigned", mitigation: "m", identified_at: "2026-10-20", auto_derived: true, notes: [], ...o,
});
const row = (o: Partial<RiskRow> = {}): RiskRow => ({
  external_id: "DR-X", auto_derived: true, title: "t", description: null, category: "ai-code", likelihood: 4, impact: 4,
  residual_likelihood: null, residual_impact: null, status: "open", treatment: "mitigate", owner_email: null, due_date: null,
  mitigation: null, related_cve: null, related_cwe: null, related_link: null, repo: null, notes: [], created_at: "2026-09-01T08:00:00Z", ...o,
});

describe("rowsToStore + mergeRisks", () => {
  it("recorded decisions apply; unset recorded fields never blank the derived ones", () => {
    const store = rowsToStore([row({ status: "mitigating", owner_email: "lead@acme.test", due_date: "2026-11-01" })]);
    const [r] = mergeRisks([derived()], store);
    expect(r).toMatchObject({ status: "mitigating", owner: "lead@acme.test", due_date: "2026-11-01", mitigation: "m", identified_at: "2026-09-01" });
    const [empty] = mergeRisks([derived()], rowsToStore([row({ owner_email: "", mitigation: "" })]));
    expect(empty).toMatchObject({ owner: "unassigned", mitigation: "m" });
    const [blank] = mergeRisks([derived()], rowsToStore([row()]));
    expect(blank).toMatchObject({ owner: "unassigned", mitigation: "m", notes: [] });
    expect(blank.due_date).toBeUndefined();
  });

  it("notes: recorded ones replace the derived ones only when there are some", () => {
    expect(mergeRisks([derived({ notes: ["auto"] })], rowsToStore([row({ notes: ["n1"] })]))[0].notes).toEqual(["n1"]);
    expect(mergeRisks([derived({ notes: ["auto"] })], rowsToStore([row({ notes: [] })]))[0].notes).toEqual(["auto"]);
  });

  it("manual risks come from their rows, unassigned when nobody owns them; highest score first", () => {
    const store = rowsToStore([row({ external_id: "MR-1", auto_derived: false, title: "Vendor", likelihood: 5, impact: 5, created_at: "2026-08-02T00:00:00Z" }), row({ external_id: null })]);
    const all = mergeRisks([derived({ likelihood: 2, impact: 2 })], store);
    expect(all.map(r => r.id)).toEqual(["MR-1", "DR-X"]);
    expect(all[0]).toMatchObject({ owner: "unassigned", identified_at: "2026-08-02", auto_derived: false });
  });

  it("a derived risk with no row keeps its derived values", () => {
    expect(mergeRisks([derived({ owner: "unassigned" })], { overrides: {}, manuals: [] })[0]).toEqual(derived());
  });
});
