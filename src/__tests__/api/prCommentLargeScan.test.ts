/**
 * @jest-environment node
 *
 * The manual "post PR comment" route read a scan's files and attestations with plain selects, which PostgREST
 * cuts at 1000 rows: a 1,242-file scan was described as 1000 files, and files signed off past the first 1000
 * attestations showed "Pending". The fake database truncates every response at 1000 rows the same way.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-1", actor_email: "lead@acme.dev", role: "admin" }),
  requirePermission: async () => null,
}));
jest.mock("@/lib/github", () => ({ ...jest.requireActual("@/lib/github"), getInstallationToken: jest.fn(async () => ({ token: "t" })) }));

import { POST } from "@/app/api/github-app/comment/route";

const SCAN = "11111111-1111-4111-8111-111111111111";
const N = 1242;
const path = (i: number) => `testcode/BenchmarkTest${String(i).padStart(5, "0")}.py`;

const realFetch = global.fetch;
let posted = "";
beforeEach(() => {
  posted = "";
  global.fetch = (async (_url: string, init?: RequestInit) => {
    if (init?.method === "POST" || init?.method === "PATCH") posted = (JSON.parse(String(init.body)) as { body: string }).body;
    return new Response("[]", { status: 200 });
  }) as typeof fetch;
  // Only the LAST ten files are high-risk, and every file is attested: cut at 1000 attestations (by path), the
  // ten in the comment's table would show "Pending".
  db = fakeSupabase({
    scans: [{ id: SCAN, org_id: "org-1", repo_full_name: "acme/bench", pr_number: 1, overall_risk: "CRITICAL", total_ai_percentage: 0 }],
    scan_files: Array.from({ length: N }, (_, i) => ({
      id: `f-${i}`, scan_id: SCAN, org_id: "org-1", file_path: path(i), risk_score: i >= N - 10 ? "CRITICAL" : "LOW",
      ai_percentage: 0, risk_indicators: i >= N - 10 ? ["sql-injection"] : [],
    })),
    attestations: Array.from({ length: N }, (_, i) => ({ id: `a-${i}`, org_id: "org-1", scan_id: SCAN, file_path: path(i) })),
  }, { maxRows: 1000 });
});
afterEach(() => { global.fetch = realFetch; });

it("describes every file and every sign-off of a 1,242-file scan", async () => {
  const res = await POST(new NextRequest(new URL("http://localhost/api/github-app/comment"), {
    method: "POST", body: JSON.stringify({ scan_id: SCAN, repo: "acme/bench", pr_number: 1, installation_id: 1 }),
  }));
  expect(res.status).toBe(200);
  expect(posted).toContain(`| Files Scanned | ${N} |`);
  expect(posted.match(/✅ Attested/g)?.length).toBe(10);
  expect(posted).not.toContain("Pending");
});
