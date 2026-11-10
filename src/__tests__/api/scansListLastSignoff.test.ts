/**
 * @jest-environment node
 *
 * GET /api/scans reports when a scan's files were last signed off, separately from when it was scanned: the history
 * groups rows by scan date, so a scan from Sunday signed off today looked untouched.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", role: "admin" }),
}));

import { GET } from "@/app/api/scans/route";

const scan = (id: string, repo: string, pr: number) => ({ id, org_id: "org-1", repo_full_name: repo, pr_number: pr, created_at: "2026-11-08T20:00:00Z", overall_risk: "HIGH", total_ai_percentage: 0, file_count: 2 });
const att = (scan_id: string, file_path: string, created_at: string) => ({ org_id: "org-1", scan_id, file_path, risk_score: "HIGH", created_at });

beforeEach(() => {
  db = fakeSupabase({
    repositories: [{ org_id: "org-1", repo_full_name: "o/r", is_active: true }, { org_id: "org-1", repo_full_name: "o/q", is_active: true }],
    scans: [scan("s-signed", "o/r", 1), scan("s-none", "o/q", 2)],
    scan_files: [],
    attestations: [
      att("s-signed", "a.ts", "2026-11-09T09:00:00Z"),
      att("s-signed", "b.ts", "2026-11-10T07:45:00Z"),   // the newest sign-off wins
      att("s-signed", "c.ts", "2026-11-09T12:00:00Z"),
    ],
    violations: [],
  });
});

describe("GET /api/scans last_attested_at", () => {
  it("is the newest sign-off of the scan, and null when nothing was signed off", async () => {
    const res = await GET(new NextRequest(new URL("/api/scans", "https://app.example")));
    const { scans } = await res.json() as { scans: Array<{ scan_id: string; created_at: string; last_attested_at: string | null; attested_count: number }> };
    const signed = scans.find(s => s.scan_id === "s-signed")!;
    expect(signed.last_attested_at).toBe("2026-11-10T07:45:00Z");
    expect(signed.attested_count).toBe(3);
    expect(signed.created_at).toBe("2026-11-08T20:00:00Z");   // the scan date is unchanged
    expect(scans.find(s => s.scan_id === "s-none")!.last_attested_at).toBeNull();
  });
});
