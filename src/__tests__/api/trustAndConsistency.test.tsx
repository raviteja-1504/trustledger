/**
 * @jest-environment node
 *
 * End-to-end through the REAL route handlers (only the database, auth, cache and audit log are faked):
 *  1. Trust Record lifecycle: download -> valid; reformat -> still valid; change one byte -> tampered;
 *     signature byte flipped -> tampered; verified by another deployment's key -> unknown key.
 *  2. Cross-surface smoke test: one finding reads the same on the PR page API, the rendered PR finding card,
 *     the SARIF export, the Trust Record and the copyable PR summary -- location, severity, confidence,
 *     introduced-by-PR, and triage/suppression state.
 */
import { NextRequest } from "next/server";
import { renderToStaticMarkup } from "react-dom/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-1", actor_email: "lead@acme.dev", role: "admin" }),
  requireRole: () => null,
  requirePermission: async () => null,
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => {} }));
jest.mock("@/lib/cache", () => {
  const actual = jest.requireActual("@/lib/cache");
  return { ...actual, cached: async (_k: string, _t: number, fn: () => unknown) => fn(), cacheGet: async () => null, cacheSet: async () => {}, cacheDel: async () => {} };
});

import { GET as getScan } from "@/app/api/scans/[id]/route";
import { GET as getTrustRecord } from "@/app/api/scans/[id]/trust-record/route";
import { POST as verifyRecord } from "@/app/api/trust-record/verify/route";
import { GET as getSarif } from "@/app/api/export/sarif/route";
import { runScan } from "@/lib/scanner";
import { toStoredIndicators } from "@/lib/indicatorStorage";
import { addedLines, markIntroduced } from "@/lib/prDiff";
import { buildPrSecuritySummary } from "@/lib/prSecuritySummary";
import { InlineSecurityFinding } from "@/components/InlineFinding";
import { FindingTriageContext } from "@/components/FindingTriage";
import type { ScanResult, FileIndicator } from "@/types";

jest.setTimeout(60000);

const SCAN_ID = "11111111-1111-4111-8111-111111111111";
const SRC = `export function register(app) {\n  app.get("/o", (req, res) => db.query("SELECT * FROM o WHERE id = " + req.query.id));\n  app.get("/go", (req, res) => res.redirect(req.query.next));\n}\n`;

/** The database a real webhook scan would have left behind: scan row, file row with stored findings, triage. */
function seed() {
  const r = runScan({ repo: "acme/shop", pr_number: 7, commit_sha: "abcdef1234567", files: [{ path: "src/routes.ts", content: SRC }] });
  const added = addedLines({ filename: "src/routes.ts", status: "modified", patch: "@@ -1,3 +1,4 @@\n export function register(app) {\n+  app.get(\"/o\", (req, res) => db.query(\"SELECT * FROM o WHERE id = \" + req.query.id));\n   app.get(\"/go\", (req, res) => res.redirect(req.query.next));\n }" });
  const f = r.files[0];
  markIntroduced(f.indicators, f.file_path, added);
  const stored = toStoredIndicators(f.indicators);
  const redirect = stored.find(i => i.id === "open-redirect")!;
  db = fakeSupabase({
    scans: [{ id: SCAN_ID, org_id: "org-1", repo_full_name: "acme/shop", pr_number: 7, commit_sha: "abcdef1234567", branch: "main", overall_risk: f.risk_score, total_ai_percentage: 0, created_at: "2026-09-30T08:00:00Z", triggered_by: "webhook", duration_ms: 1200, evidence_breakdown: null, ai_tooling: [], check_run_sync_error: null, health: r.health, telemetry: r.telemetry }],
    scan_files: [{ scan_id: SCAN_ID, org_id: "org-1", file_path: f.file_path, language: f.language, ai_percentage: f.ai_percentage, risk_score: f.risk_score, risk_indicators: f.risk_indicators, content_hash: "h1", line_count: f.line_count, content: SRC, indicators: stored, attribution: null }],
    finding_triage: [{ org_id: "org-1", repo_full_name: "acme/shop", fingerprint: redirect.fingerprint, rule_id: "open-redirect", file_path: f.file_path, status: "accepted", reason: "gateway allow-list", expires_at: null, set_by_email: "lead@acme.dev", set_at: "2026-09-29T00:00:00Z" }],
    attestations: [], violations: [{ scan_id: SCAN_ID, status: "open", risk_score: "CRITICAL" }],
    organizations: [{ id: "org-1", name: "Acme" }],
  });
}

const req = (url: string, init?: { method?: string; body?: string }) => new NextRequest(new URL(url, "http://localhost"), init);
const verify = async (doc: unknown) => (await verifyRecord(req("/api/trust-record/verify", { method: "POST", body: JSON.stringify({ document: doc }) }))).json() as Promise<{ status: string }>;

describe("Trust Record: valid -> modify one byte -> tampered -> unknown key", () => {
  const OLD = process.env.EXPORT_SIGNING_KEY;
  afterAll(() => { process.env.EXPORT_SIGNING_KEY = OLD; });

  it("through the real download and verify endpoints", async () => {
    seed();
    process.env.EXPORT_SIGNING_KEY = "deployment-A-key";
    const res = await getTrustRecord(req(`/api/scans/${SCAN_ID}/trust-record`), { params: { id: SCAN_ID } });
    expect(res.headers.get("content-disposition")).toContain("trust-record-acme-shop-pr7-abcdef12.json");
    const text = await res.text();
    const doc = JSON.parse(text);
    expect(doc.signature.key_id).toMatch(/^[0-9a-f]{16}$/);

    // 1. Exactly as downloaded: valid.
    expect((await verify(doc)).status).toBe("valid");
    // 2. Reformatted (whitespace, key order) but the same content: still valid -- the signature covers content.
    const reordered = JSON.parse(JSON.stringify(doc, null, 0));
    reordered.record = Object.fromEntries(Object.entries(reordered.record).reverse());
    expect((await verify(reordered)).status).toBe("valid");
    // 3. One byte changed inside the record (the finding's line number): tampered.
    const lineAt = text.indexOf('"line": ') + '"line": '.length;
    const oneByte = text.slice(0, lineAt) + String((Number(text[lineAt]) + 1) % 10) + text.slice(lineAt + 1);
    expect(oneByte.length).toBe(text.length);
    expect((await verify(JSON.parse(oneByte))).status).toBe("tampered");
    // 4. One byte of the signature flipped: tampered.
    const sig = doc.signature.value as string;
    expect((await verify({ ...doc, signature: { ...doc.signature, value: (sig[0] === "a" ? "b" : "a") + sig.slice(1) } })).status).toBe("tampered");
    // 5. The untouched record, checked by a deployment with a different key: unknown key, not "tampered".
    process.env.EXPORT_SIGNING_KEY = "deployment-B-key";
    expect((await verify(doc)).status).toBe("unknown_key");
    // 6. ...and a server with no key at all can't verify.
    delete process.env.EXPORT_SIGNING_KEY;
    const oldCron = process.env.CRON_SECRET; delete process.env.CRON_SECRET;
    expect((await verify(doc)).status).toBe("not_configured");
    process.env.CRON_SECRET = oldCron;
  });
});

describe("cross-surface smoke test: one finding, five surfaces, one story", () => {
  it("PR page API, PR finding card, SARIF, Trust Record and PR summary agree", async () => {
    seed();
    process.env.EXPORT_SIGNING_KEY = "k";

    // PR page data (what the dashboard renders).
    const scan = await (await getScan(req(`/api/scans/${SCAN_ID}`), { params: { id: SCAN_ID } })).json() as ScanResult;
    const apiInds = scan.files[0].indicators as FileIndicator[];
    const apiSqli = apiInds.find(i => i.id === "sql-injection")!;
    const apiRedirect = apiInds.find(i => i.id === "open-redirect")!;

    // SARIF export.
    const sarif = await (await getSarif(req(`/api/export/sarif?scan_id=${SCAN_ID}`))).json() as { runs: Array<{ results: Array<{ ruleId: string; locations: Array<{ physicalLocation: { region: { startLine: number } } }>; properties: Record<string, unknown>; suppressions?: Array<{ justification: string }> }> }> };
    const sarifOf = (id: string) => sarif.runs[0].results.find(r => r.ruleId === id)!;

    // Trust Record.
    const record = (await (await getTrustRecord(req(`/api/scans/${SCAN_ID}/trust-record`), { params: { id: SCAN_ID } })).json()).record as { findings: Array<{ rule: string; line: number; severity: string; confidence: string; introduced_by_pr: boolean | null; decision: { status: string; reason: string } | null }> };
    const recOf = (id: string) => record.findings.find(f => f.rule === id)!;

    // PR summary (built from the PR page data, as the Copy summary button does).
    const summary = buildPrSecuritySummary(scan);

    // PR finding card (the rendered UI).
    const card = (ind: FileIndicator) => renderToStaticMarkup(
      <FindingTriageContext.Provider value={{ repo: "acme/shop", canTriage: true, onDecision: () => {} }}>
        <InlineSecurityFinding ind={ind} filePath="src/routes.ts" siblings={apiInds} />
      </FindingTriageContext.Provider>,
    );

    // The introduced SQL injection.
    expect(apiSqli).toMatchObject({ line: 2, severity: "critical", introduced: true, lifecycle_status: "new" });
    expect(apiSqli.triage).toBeUndefined();
    expect(sarifOf("sql-injection").locations[0].physicalLocation.region.startLine).toBe(2);
    expect(sarifOf("sql-injection").properties).toMatchObject({ "security-severity": "9.0", "trustledger/confidenceLevel": "confirmed", "trustledger/introducedByPR": true });
    expect(sarifOf("sql-injection").suppressions).toBeUndefined();
    expect(recOf("sql-injection")).toMatchObject({ line: 2, severity: "critical", confidence: "confirmed", introduced_by_pr: true, decision: null });
    expect(summary).toContain("| Critical | SQL Injection (CWE-89) | `src/routes.ts:2` | Confirmed | New · introduced |");
    const sqliCard = card(apiSqli);
    expect(sqliCard).toContain("Confirmed");
    expect(sqliCard).toContain("Introduced by this PR");
    expect(sqliCard).toContain(">New<");

    // The pre-existing, accepted open redirect.
    expect(apiRedirect).toMatchObject({ line: 3, introduced: false, lifecycle_status: "accepted" });
    expect(apiRedirect.triage).toMatchObject({ status: "accepted", reason: "gateway allow-list" });
    expect(sarifOf("open-redirect").properties["trustledger/introducedByPR"]).toBe(false);
    expect(sarifOf("open-redirect").suppressions?.[0].justification).toBe("Risk accepted: gateway allow-list (lead@acme.dev)");
    expect(recOf("open-redirect")).toMatchObject({ line: 3, introduced_by_pr: false, decision: { status: "accepted", reason: "gateway allow-list" } });
    expect(summary).toContain("`src/routes.ts:3` | Confirmed | Accepted risk · pre-existing · “gateway allow-list”");
    const redirectCard = card(apiRedirect);
    expect(redirectCard).toContain("Accepted risk");
    expect(redirectCard).toContain("Pre-existing");
  });
});
