/**
 * @jest-environment node
 *
 * A 1,242-file scan (OWASP BenchmarkPython) showed "1000 files" on its PR page: PostgREST returns at most 1000
 * rows per request, and the per-scan reads were single selects. The fake database here truncates every response
 * at 1000 rows the same way, so each surface must page (lib/allRows.ts) to see the whole scan.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { allRows, PAGE_SIZE } from "@/lib/allRows";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-1", actor_email: "lead@acme.dev", role: "admin" }),
  requireRole: () => null,
  requirePermission: async () => null,
  permissionsFor: async () => jest.requireActual("@/lib/permissions").builtinPermissions("admin"),
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => {}, verifyAuditChain: async () => ({ valid: true, checked: 0 }) }));
jest.mock("@/lib/autoIncidents", () => ({ syncAutoIncidents: async () => {} }));
jest.mock("@/lib/cache", () => {
  const actual = jest.requireActual("@/lib/cache");
  return { ...actual, cached: async (_k: string, _t: number, fn: () => unknown) => fn(), cacheGet: async () => null, cacheSet: async () => {}, cacheDel: async () => {} };
});

import { GET as getScan } from "@/app/api/scans/[id]/route";
import { GET as getTrustRecord } from "@/app/api/scans/[id]/trust-record/route";
import { GET as getSarif } from "@/app/api/export/sarif/route";
import { POST as baseline } from "@/app/api/findings/baseline/route";
import { POST as bulk } from "@/app/api/scans/bulk/route";
import { GET as compare } from "@/app/api/scans/compare/route";
import { loadScoreInput } from "@/lib/governanceScoreLoader";
import { loadShadowAi } from "@/lib/shadowAiStore";
import { loadFactRows } from "@/lib/evidenceEngine";

jest.setTimeout(60_000);

const SCAN = "11111111-1111-4111-8111-111111111111";
const PREV = "22222222-2222-4222-8222-222222222222";
const N = 1242;
const path = (i: number) => `testcode/BenchmarkTest${String(i).padStart(5, "0")}.py`;
const finding = (i: number) => ({ id: "sql-injection", label: "SQL Injection", severity: "critical", line: 10, fingerprint: `fp-${i}` });

function seed() {
  const files = (scan: string) => Array.from({ length: N }, (_, i) => ({
    id: `${scan}-${i}`, scan_id: scan, org_id: "org-1", file_path: path(i), language: "python", ai_percentage: 0,
    risk_score: "CRITICAL", risk_indicators: ["sql-injection"], content_hash: `h${i}`, line_count: 20, content: null,
    indicators: [finding(i)], attribution: null, created_at: "2026-10-24T09:00:00Z",
  }));
  db = fakeSupabase({
    scans: [
      { id: SCAN, org_id: "org-1", repo_full_name: "acme/bench", pr_number: 1, commit_sha: "b9f3f6ba00", branch: "main", overall_risk: "CRITICAL", total_ai_percentage: 0, created_at: "2026-10-24T09:00:00Z", triggered_by: "webhook", duration_ms: 31500, file_count: N, evidence_breakdown: null, ai_tooling: [] },
      { id: PREV, org_id: "org-1", repo_full_name: "acme/bench", pr_number: 1, commit_sha: "a1a1a1a1a1", branch: "main", overall_risk: "CRITICAL", total_ai_percentage: 0, created_at: "2026-10-23T09:00:00Z", triggered_by: "webhook", duration_ms: 30000, file_count: N, evidence_breakdown: null, ai_tooling: [] },
    ],
    scan_files: [...files(SCAN), ...files(PREV)],
    attestations: [], violations: [], finding_triage: [], secret_findings: [], repositories: [{ org_id: "org-1", repo_full_name: "acme/bench", is_active: true }],
    organizations: [{ id: "org-1", name: "Acme" }],
  }, { maxRows: PAGE_SIZE });
}

const req = (url: string, init?: { method?: string; body?: string }) => new NextRequest(new URL(url, "http://localhost"), init);
const params = { params: Promise.resolve({ id: SCAN }) };

describe("allRows", () => {
  it("reads page after page until a short one, asking for consecutive windows", async () => {
    const windows: Array<[number, number]> = [];
    const rows = Array.from({ length: 2500 }, (_, i) => i);
    const { data, error } = await allRows<number>(async (from, to) => { windows.push([from, to]); return { data: rows.slice(from, to + 1), error: null }; });
    expect(data).toEqual(rows);
    expect(error).toBeNull();
    expect(windows).toEqual([[0, 999], [1000, 1999], [2000, 2999]]);
  });

  it("an exact multiple of the page size ends on the empty page after it", async () => {
    const rows = Array.from({ length: 2000 }, (_, i) => i);
    const { data } = await allRows<number>(async (from, to) => ({ data: rows.slice(from, to + 1), error: null }));
    expect(data.length).toBe(2000);
  });

  it("stops at the first error and returns what it had, with the error", async () => {
    let calls = 0;
    const { data, error } = await allRows<number>(async (from) => {
      calls++;
      return from === 0 ? { data: Array.from({ length: PAGE_SIZE }, (_, i) => i), error: null } : { data: null, error: { message: "boom" } };
    });
    expect(calls).toBe(2);
    expect(data.length).toBe(PAGE_SIZE);
    expect(error).toEqual({ message: "boom" });
  });

  it("stops at its page limit even if a callback ignores the range", async () => {
    let calls = 0;
    const { data } = await allRows<number>(async () => { calls++; return { data: Array.from({ length: PAGE_SIZE }, (_, i) => i), error: null }; });
    expect(calls).toBe(200);
    expect(data.length).toBe(200 * PAGE_SIZE);
  });
});

describe(`a ${N}-file scan behind a ${PAGE_SIZE}-row response cap`, () => {
  beforeEach(seed);

  const attestFirst = async (n: number) => {
    const atts = db.client.from("attestations") as unknown as { insert: (r: unknown) => PromiseLike<unknown> };
    await atts.insert(Array.from({ length: n }, (_, i) => ({ org_id: "org-1", scan_id: SCAN, file_path: path(i), risk_score: "CRITICAL", reviewer_email: "lead@acme.dev", payload_hash: `p${i}`, created_at: "2026-10-24T10:00:00Z" })));
  };

  it("PR page lists every file, every attestation, and compares with the whole previous scan", async () => {
    await attestFirst(1100);
    const scan = await (await getScan(req(`/api/scans/${SCAN}`), params)).json() as {
      files: Array<{ file_path: string; attested: boolean }>; lifecycle: { summary: { new: number; existing: number } };
    };
    expect(scan.files.length).toBe(N);
    expect(new Set(scan.files.map(f => f.file_path)).size).toBe(N);
    expect(scan.files.filter(f => f.attested).length).toBe(1100);
    // the previous scan has the same findings: cut at 1000, the last 242 files' findings read as "new"
    expect(scan.lifecycle.summary).toMatchObject({ new: 0, existing: N });
  });

  it("the signed Trust Record lists every file, finding and attestation", async () => {
    await attestFirst(1100);
    const { record } = await (await getTrustRecord(req(`/api/scans/${SCAN}/trust-record`), params)).json();
    expect(record.files.length).toBe(N);
    expect(record.findings.length).toBe(N);
    expect(record.summary.files).toBe(N);
    expect(record.attestations.length).toBe(1100);
  });

  it("the SARIF export has every finding", async () => {
    const sarif = await (await getSarif(req(`/api/export/sarif?scan_id=${SCAN}`))).json() as { runs: Array<{ results: unknown[] }> };
    expect(sarif.runs[0].results.length).toBe(N);
  });

  it("Baseline accepts every finding, not the first 1000 files'", async () => {
    await baseline(req("/api/findings/baseline", { method: "POST", body: JSON.stringify({ scan_id: SCAN }) }));
    const inserted = db.writes.filter(w => w.table === "finding_triage").flatMap(w => (Array.isArray(w.payload) ? w.payload : [w.payload]) as Array<{ fingerprint: string }>);
    expect(new Set(inserted.map(r => r.fingerprint)).size).toBe(N);
  });

  it("Attest all signs off every file once -- including past 1000 already-attested ones", async () => {
    // 1100 already attested: without paging the check saw 1000 of them and attested 100 a second time.
    const atts = db.client.from("attestations") as unknown as { insert: (r: unknown) => PromiseLike<unknown> };
    await atts.insert(Array.from({ length: 1100 }, (_, i) => ({ org_id: "org-1", scan_id: SCAN, file_path: path(i), risk_score: "CRITICAL", reviewer_email: "lead@acme.dev", payload_hash: `p${i}` })));
    const res = await bulk(req("/api/scans/bulk?op=attest", { method: "POST", body: JSON.stringify({ scan_id: SCAN, reviewer_email: "lead@acme.dev" }) }));
    expect(res.status).toBe(200);
    const all = db.writes.filter(w => w.table === "attestations" && w.op === "insert").flatMap(w => (Array.isArray(w.payload) ? w.payload : [w.payload]) as Array<{ file_path: string }>);
    expect(all.length).toBe(N);
    expect(new Set(all.map(a => a.file_path)).size).toBe(N);
  });

  it("Compare sees both whole scans", async () => {
    const r = await (await compare(req(`/api/scans/compare?scan_a=${PREV}&scan_b=${SCAN}`))).json() as {
      scan_a: { file_count: number }; scan_b: { file_count: number }; diff: { new_files: unknown[]; resolved: unknown[]; unchanged: number };
    };
    expect([r.scan_a.file_count, r.scan_b.file_count]).toEqual([N, N]);
    // cut at 1000 each, files 1000+ of one scan looked "new" or "resolved" against the other
    expect(r.diff.new_files).toEqual([]);
    expect(r.diff.resolved).toEqual([]);
    expect(r.diff.unchanged).toBe(N);
  });

  it("Shadow AI sees every file's attribution, not the first 1000 rows of the scans", async () => {
    const files = db.client.from("scan_files") as unknown as { update: (p: unknown) => { eq: (c: string, v: unknown) => PromiseLike<unknown> } };
    await files.update({ attribution: { model: "claude", confidence: 0.9 } }).eq("scan_id", SCAN);
    const { detections } = await loadShadowAi(db.client as never, "org-1", 30);
    expect(detections.filter(d => d.tier === "hint").length).toBe(N);
  });

  it("compliance evidence counts every risky file and attestation", async () => {
    await attestFirst(1100);
    const rows = await loadFactRows(db.client as never, "org-1", "2026-10-01T00:00:00Z", "2026-10-31T23:59:59Z", new Date("2026-10-24T12:00:00Z"));
    expect(rows.riskyFiles.length).toBe(2 * N);
    expect(rows.attestations.length).toBe(1100);
  });

  it("the governance score counts every risky file", async () => {
    const input = await loadScoreInput(db.client as never, "org-1", new Date("2026-10-24T12:00:00Z"));
    expect(input.riskyFiles.length).toBe(2 * N);
  });
});
