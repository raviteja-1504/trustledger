/**
 * @jest-environment node
 *
 * The CSV export route must not hand an attacker a way into a spreadsheet: a file path or an assignee typed by someone
 * else, opened by an auditor in Excel, must arrive as text.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { parseCsv } from "@/lib/csv";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-1", actor_email: "lead@acme.dev", role: "admin" }),
  requirePermission: async () => null,
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => {}, verifyAuditChain: async () => ({ valid: true }) }));

import { GET } from "@/app/api/export/route";

beforeEach(() => {
  db = fakeSupabase({
    violations: [
      { id: "v1", org_id: "org-1", scan_id: "s1", file_path: '=HYPERLINK("https://evil.example","click")', risk_score: "CRITICAL", status: "open", assigned_email: "+evil@acme.dev", sla_deadline: null, resolved_at: null, created_at: "2026-11-25T00:00:00Z" },
      { id: "v2", org_id: "org-1", scan_id: "s1", file_path: 'src/a,b "quoted".ts', risk_score: "HIGH", status: "open", assigned_email: "@boss", sla_deadline: "2026-12-01", resolved_at: null, created_at: "2026-11-24T00:00:00Z" },
    ],
  });
});

const get = async () => (await GET(new NextRequest(new URL("https://app.example/api/export?type=violations&format=csv")))).text();

describe("GET /api/export?format=csv", () => {
  it("neutralises formulas, so no cell begins with = + - or @", async () => {
    const rows = parseCsv(await get());
    expect(rows[0]).toContain("file_path");
    const fileCol = rows[0].indexOf("file_path"), mailCol = rows[0].indexOf("assigned_email");
    expect(rows[1][fileCol]).toBe(`'=HYPERLINK("https://evil.example","click")`);
    expect(rows[1][mailCol]).toBe("'+evil@acme.dev");
    expect(rows[2][mailCol]).toBe("'@boss");
    for (const row of rows.slice(1)) for (const cell of row) expect(/^[=+\-@\t\r]/.test(cell)).toBe(false);
  });

  it("keeps commas and quotes inside their own cell", async () => {
    const rows = parseCsv(await get());
    expect(rows.every(r => r.length === rows[0].length)).toBe(true);        // nothing spilled into another column
    expect(rows[2][rows[0].indexOf("file_path")]).toBe('src/a,b "quoted".ts');
  });
});
