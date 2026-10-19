/**
 * @jest-environment node
 *
 * /api/trust-score: computed from the org's real data (and only its own), saved as one snapshot per day, served
 * with real history, downloadable as an Ed25519-signed report.
 */
import crypto from "crypto";
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { _resetExportKeyCache } from "@/lib/exportSigning";
import { canonicalJson } from "@/lib/trustRecord";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", actor_email: "a@acme.dev", role: "developer" }),
}));

import { GET } from "@/app/api/trust-score/route";

const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const req = (q = "") => new NextRequest(new URL(`/api/trust-score${q}`, "https://app.example"));
const ago = (d: number) => new Date(Date.now() - d * 86400_000).toISOString();
const today = new Date().toISOString().slice(0, 10);

beforeEach(() => {
  delete process.env.EXPORT_SIGNING_PRIVATE_KEY; _resetExportKeyCache();
  db = fakeSupabase({
    organizations: [{ id: "org-1", name: "Acme", ai_tool_policy: { allowed: ["claude"] } }],
    repositories: [
      { id: "r1", org_id: "org-1", repo_full_name: "acme/app", is_active: true },
      { id: "r9", org_id: "org-2", repo_full_name: "other/repo", is_active: true },
    ],
    scans: [
      { id: "s1", org_id: "org-1", repo_full_name: "acme/app", pr_number: 1, pr_author: "dev", created_at: ago(1), ai_tooling: [] },
      { id: "s9", org_id: "org-2", repo_full_name: "other/repo", pr_number: 1, pr_author: "x", created_at: ago(1), ai_tooling: [] },
    ],
    scan_files: [{ scan_id: "s1", org_id: "org-1", file_path: "pay.ts", risk_score: "CRITICAL", ai_percentage: 0.9, attribution: null }],
    attestations: [],
    violations: [
      { id: "v1", org_id: "org-1", scan_id: "s1", file_path: "pay.ts", risk_score: "CRITICAL", status: "open", sla_deadline: ago(1) },
      { id: "v9", org_id: "org-2", scan_id: "s9", file_path: "x.ts", risk_score: "CRITICAL", status: "open", sla_deadline: null },
    ],
    secret_findings: [],
    shadow_ai_triage: [],
    trust_score_history: [{ org_id: "org-1", day: ago(10).slice(0, 10), total: 500, dimensions: {}, repo_scores: [] }],
    audit_log: [],
  });
});

it("another org's newer scan of a same-named repo never supersedes this org's scan", async () => {
  rows("scans").push({ id: "s8", org_id: "org-2", repo_full_name: "acme/app", pr_number: 1, pr_author: "x", created_at: ago(0), ai_tooling: [] });
  const body = await (await GET(req())).json();
  expect(body.score.dimensions.find((d: { key: string }) => d.key === "review").value).toBe(0);   // org-1's unreviewed file still counts
});

it("computes this org's score from its own data and explains it", async () => {
  const body = await (await GET(req())).json();
  const s = body.score;
  expect(s.total).toBeGreaterThan(0);
  expect(s.total).toBeLessThan(1000);
  expect(s.repos.map((r: { repo: string }) => r.repo)).toEqual(["acme/app"]);   // org-2's repo never appears
  const exposure = s.dimensions.find((d: { key: string }) => d.key === "exposure");
  expect(exposure.facts[0]).toContain("1 open critical file");
  const review = s.dimensions.find((d: { key: string }) => d.key === "review");
  expect(review.value).toBe(0);                                                   // the risky AI file is unreviewed
});

it("saves one snapshot per day (re-opening updates it) and returns history", async () => {
  await GET(req());
  await GET(req());
  const snaps = rows("trust_score_history").filter(r => r.org_id === "org-1");
  expect(snaps.map(r => r.day).sort()).toEqual([ago(10).slice(0, 10), today]);
  const body = await (await GET(req())).json();
  expect(body.history_available).toBe(true);
  expect(body.history.map((h: { day: string }) => h.day)).toEqual([ago(10).slice(0, 10), today]);
  expect(body.history[1].total).toBe(body.score.total);
});

it("the report is Ed25519-signed when a key is set, verifiable with the public key, and audit-logged", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  process.env.EXPORT_SIGNING_PRIVATE_KEY = privateKey.export({ type: "pkcs8", format: "pem" }) as string; _resetExportKeyCache();
  const res = await GET(req("?report=1"));
  expect(res.headers.get("Content-Disposition")).toContain(`trust-score-${today}.json`);
  const doc = JSON.parse(await res.text());
  expect(doc.record.schema).toBe("trustledger.trust-score-report/v1");
  expect(doc.record.organization).toBe("Acme");
  expect(doc.signature.algorithm).toBe("Ed25519");
  expect(crypto.verify(null, Buffer.from(canonicalJson(doc.record)), publicKey, Buffer.from(doc.signature.value, "base64"))).toBe(true);
  doc.record.score.total = 1000;   // tampering breaks it
  expect(crypto.verify(null, Buffer.from(canonicalJson(doc.record)), publicKey, Buffer.from(doc.signature.value, "base64"))).toBe(false);
  expect(rows("audit_log")).toEqual([expect.objectContaining({ event_type: "report_generated", payload: expect.objectContaining({ kind: "trust_score_report", signed: true }) })]);
});

it("before the history migration, the score is still live with empty history", async () => {
  const real = db.client.from.bind(db.client);
  (db.client as { from: (t: string) => unknown }).from = (t: string) => t === "trust_score_history"
    ? { upsert: async () => ({ error: { code: "42P01" } }), select: () => ({ eq: () => ({ gte: () => ({ order: async () => ({ data: null, error: { code: "42P01" } }) }) }) }) }
    : real(t);
  const body = await (await GET(req())).json();
  expect(body.score.total).toBeGreaterThan(0);
  expect(body.history).toEqual([]);
  expect(body.history_available).toBe(false);
});
