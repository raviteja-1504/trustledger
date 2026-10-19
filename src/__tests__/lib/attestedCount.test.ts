/**
 * @jest-environment node
 *
 * Scan history "files attested": attesting one file showed 2, because the page added the server's count to this
 * browser's record of the same attestation; and the server counted attestation ROWS, so a file with two rows
 * counted twice. Both now count distinct files.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { effectiveAttestedCount, locallyAttestedFiles } from "@/lib/attestedCount";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", role: "admin" }),
}));

import { GET } from "@/app/api/scans/route";

const key = (scan: string, path: string, risk = "high") => `${risk}::${scan}::${path}`;

describe("effectiveAttestedCount", () => {
  it("a file attested in this browser AND known to the server counts once", () => {
    const statuses = { [key("s1", "src/a.ts")]: "resolved" };
    expect(effectiveAttestedCount({ scan_id: "s1", file_count: 5, attested_count: 1, attested_files: ["src/a.ts"] }, statuses)).toBe(1);
  });

  it("the server's files and different local files add up as a union", () => {
    const statuses = { [key("s1", "src/b.ts")]: "in_review", [key("s1", "src/a.ts")]: "resolved" };
    expect(effectiveAttestedCount({ scan_id: "s1", file_count: 5, attested_count: 1, attested_files: ["src/a.ts"] }, statuses)).toBe(2);
  });

  it("only attested statuses for THIS scan count", () => {
    const statuses = {
      [key("s1", "src/a.ts")]: "open",
      [key("s2", "src/b.ts")]: "resolved",
      "malformed-key": "resolved",
      [key("s1", "")]: "resolved",
    };
    expect(effectiveAttestedCount({ scan_id: "s1", file_count: 5, attested_count: 0, attested_files: [] }, statuses)).toBe(0);
  });

  it("never exceeds the scan's file count", () => {
    const statuses = { [key("s1", "x.ts")]: "resolved", [key("s1", "y.ts")]: "resolved" };
    expect(effectiveAttestedCount({ scan_id: "s1", file_count: 2, attested_count: 2, attested_files: ["a.ts", "b.ts"] }, statuses)).toBe(2);
  });

  it("demo data (a count, no file list): the larger of the two, never their sum", () => {
    const statuses = { [key("s1", "a.ts")]: "resolved" };
    expect(effectiveAttestedCount({ scan_id: "s1", file_count: 7, attested_count: 3 }, statuses)).toBe(3);
    expect(effectiveAttestedCount({ scan_id: "s1", file_count: 7, attested_count: 0 }, statuses)).toBe(1);
  });

  it("parses file paths that themselves contain '::'", () => {
    expect([...locallyAttestedFiles("s1", { [key("s1", "pkg::mod/a.rs")]: "resolved" })]).toEqual(["pkg::mod/a.rs"]);
  });
});

describe("GET /api/scans attested_count", () => {
  beforeEach(() => {
    db = fakeSupabase({
      repositories: [{ id: "r1", org_id: "org-1", repo_full_name: "acme/app", is_active: true }],
      scans: [{ id: "s1", org_id: "org-1", repo_full_name: "acme/app", pr_number: 7, commit_sha: "abc", branch: "f", overall_risk: "HIGH", total_ai_percentage: 0.2, file_count: 4, created_at: "2026-10-01T00:00:00Z", triggered_by: "webhook" }],
      // Two rows for a.ts (second reviewer / a racing double click) and one for b.ts.
      attestations: [
        { id: "a1", scan_id: "s1", file_path: "src/a.ts" },
        { id: "a2", scan_id: "s1", file_path: "src/a.ts" },
        { id: "a3", scan_id: "s1", file_path: "src/b.ts" },
      ],
      scan_files: [],
    });
  });

  it("counts distinct attested files, and lists them", async () => {
    const res = await GET(new NextRequest(new URL("https://app.example/api/scans")));
    const { scans } = await res.json();
    expect(scans).toHaveLength(1);
    expect(scans[0].attested_count).toBe(2);
    expect([...scans[0].attested_files].sort()).toEqual(["src/a.ts", "src/b.ts"]);
  });
});
