/**
 * @jest-environment node
 *
 * GET /api/scans: ?since= and ?before= accept the timestamps the database itself returns ("...+00:00"). Only "...Z"
 * was accepted, so the PR page's rescan poll (and paging with next_before) always got a 400.
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

beforeEach(() => {
  db = fakeSupabase({
    repositories: [{ org_id: "org-1", repo_full_name: "o/r", is_active: true }],
    scans: [
      { id: "s-old", org_id: "org-1", repo_full_name: "o/r", pr_number: 7, created_at: "2026-06-01T10:00:00Z", overall_risk: "LOW", total_ai_percentage: 0, file_count: 1 },
      { id: "s-new", org_id: "org-1", repo_full_name: "o/r", pr_number: 7, created_at: "2026-06-01T10:05:00Z", overall_risk: "LOW", total_ai_percentage: 0, file_count: 1 },
    ],
    attestations: [], violations: [],
  });
});

const get = async (qs: string) => { const res = await GET(new NextRequest(new URL(`/api/scans?${qs}`, "https://app.example"))); return { status: res.status, body: await res.json() as { scans?: Array<{ scan_id: string }>; error?: string } }; };

describe("GET /api/scans cursors", () => {
  it.each([
    ["Z", "2026-06-01T10:02:00Z"],
    ["Z with milliseconds", "2026-06-01T10:02:00.000Z"],
    ["+00:00 (the database's spelling)", "2026-06-01T10:02:00.123456+00:00"],
  ])("since accepts %s", async (_n, ts) => {
    const { status, body } = await get(`repo=o%2Fr&since=${encodeURIComponent(ts)}`);
    expect(status).toBe(200);
    expect(body.scans?.map(s => s.scan_id)).toEqual(["s-new"]);
  });

  it("since accepts another offset (the database compares instants; the in-memory fake compares text, so only the status is checked)", async () => {
    expect((await get(`since=${encodeURIComponent("2026-06-01T12:02:00+02:00")}`)).status).toBe(200);
  });

  it("before accepts +00:00 too", async () => {
    const { status } = await get(`before=${encodeURIComponent("2026-06-01T10:03:00+00:00")}`);
    expect(status).toBe(200);
  });

  it.each(["yesterday", "2026-06-01", "2026-06-01T10:00:00", "2026-06-01T10:00:00+0200", "2026-06-01T10:00:00Zjunk"])("still rejects %s", async ts => {
    const { status, body } = await get(`since=${encodeURIComponent(ts)}`);
    expect(status).toBe(400);
    expect(body.error).toBe("invalid_cursor");
  });
});
