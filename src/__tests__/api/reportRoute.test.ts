/**
 * @jest-environment node
 *
 * POST /api/report: hands the PDF renderer elements its own React accepts (lib/pdfElements.ts), returns the signed
 * PDF; a render failure is a 500 error (not a 200 carrying the report as JSON); no signing key is a 503.
 */
import { NextRequest } from "next/server";

let rendered: unknown = null;
let renderFails = false;
jest.mock("@react-pdf/renderer", () => ({
  renderToBuffer: jest.fn(async (doc: unknown) => { if (renderFails) throw new Error("layout failed"); rendered = doc; return Buffer.from("%PDF-1.4 test"); }),
}), { virtual: false });
jest.mock("@/lib/reportPDF", () => {
  const React = jest.requireActual("react");
  return { buildReportDocument: ({ data }: { data: { report_id: string } }) => React.createElement("DOCUMENT", null, React.createElement("TEXT", null, data.report_id)) };
});
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", actor_email: "a@acme.test" }), requirePermission: async () => null }));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true, headers: {} }), RATE_LIMITS: { report: {} } }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => {} }));
jest.mock("@/lib/serverErrors", () => ({ reportServerError: () => {} }));
jest.mock("@/lib/logger", () => ({ logger: { error: () => {} } }));
jest.mock("@/lib/evidenceEngine", () => ({
  collectEvidence: async () => ({ framework: "SOC2", framework_name: "SOC 2", standard: "AICPA", scope: "x", status_counts: {}, controls: [],
    facts: { risky: { total: 0, reviewed: 0 }, reviews: { independent: 0, self: 0 } } }),
}));
const inserted: unknown[] = [];
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    from: (table: string) => {
      const q = {
        select: () => q, eq: () => q, gte: () => q, lte: () => q, order: () => q, limit: () => q,
        single: async () => ({ data: { name: "Acme", slug: "acme", github_org: null } }),
        insert: async (r: unknown) => { inserted.push({ table, r }); return { error: null }; },
        then: (res: (v: unknown) => unknown) => Promise.resolve({ data: [], count: 0, error: null }).then(res),
      };
      return q;
    },
  }),
}));

import { POST } from "@/app/api/report/route";

const post = () => POST(new NextRequest(new URL("/api/report", "https://app.example"), {
  method: "POST", body: JSON.stringify({ framework: "SOC2", period_start: "2026-09-01T00:00:00Z", period_end: "2026-10-01T00:00:00Z" }),
  headers: { "content-type": "application/json" },
}));

const KEY = process.env.EXPORT_SIGNING_KEY, CRON = process.env.CRON_SECRET;
beforeEach(() => { rendered = null; renderFails = false; inserted.length = 0; process.env.EXPORT_SIGNING_KEY = "test-signing-material"; delete process.env.CRON_SECRET; });
afterAll(() => { process.env.EXPORT_SIGNING_KEY = KEY; process.env.CRON_SECRET = CRON; });

describe("POST /api/report", () => {
  it("renders host elements built with the renderer's React and returns the signed PDF", async () => {
    const res = await post();
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/pdf");
    expect(res.headers.get("x-trustledger-signature")).toMatch(/^[0-9a-f]{64}$/);
    expect(Buffer.from(await res.arrayBuffer()).toString()).toBe("%PDF-1.4 test");
    const doc = rendered as { $$typeof: symbol; type: unknown; props: { children: { type: unknown } } };
    expect(doc.$$typeof).toBe(Symbol.for("react.element"));
    expect(doc.type).toBe("DOCUMENT");                  // the component was called: only host elements reach the renderer
    expect(doc.props.children.type).toBe("TEXT");
    expect(inserted.some(i => (i as { table: string }).table === "report_generations")).toBe(true);
  });

  it("a render failure is a 500 error without the report data", async () => {
    renderFails = true;
    const res = await post();
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body).toEqual({ error: "report_render_failed", pdf_render_failed: true });
    expect(inserted).toHaveLength(0);
  });

  it("no signing key → 503 saying so", async () => {
    delete process.env.EXPORT_SIGNING_KEY;
    const res = await post();
    expect(res.status).toBe(503);
    expect((await res.json()).error).toBe("report_signing_not_configured");
  });
});
