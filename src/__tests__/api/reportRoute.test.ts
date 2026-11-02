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
  collectEvidence: async () => ({ framework: evidenceFramework, framework_name: "SOC 2", standard: "AICPA", scope: "x", status_counts: {}, controls: [],
    facts: { risky: { total: 0, reviewed: 0 }, reviews: { independent: 0, self: 0 } }, unreviewed }),
}));
let registerFails = false;
const registerLoads: string[] = [];
jest.mock("@/lib/changeRegisterLoader", () => ({
  loadChangeRegister: async (_db: unknown, org: string) => {
    registerLoads.push(org);
    if (registerFails) throw new Error("GitHub down");
    const { buildRegister } = jest.requireActual("@/lib/changeRegister");
    return buildRegister({ period_start: "2026-09-01T00:00:00Z", period_end: "2026-10-01T00:00:00Z",
      pulls: [{ repo: "acme/api", number: 1, title: "x", author: "alice", merged_at: "2026-09-10T00:00:00Z", merged_by: null, head_sha: "s", url: "u" }],
      reviews: new Map(), scans: [], riskyFiles: [], signoffs: [], coverage: [{ repo: "acme/api", read: true, pulls: 1 }] });
  },
}));
let evidenceFramework = "soc2";
let unreviewed: unknown[] = [];
let tableRows: Record<string, unknown[]> = {};
const inserted: unknown[] = [];
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    from: (table: string) => {
      let span: [number, number] = [0, 999_999];
      const q = {
        select: () => q, eq: () => q, gte: () => q, lte: () => q, order: () => q, limit: () => q,
        range: (f: number, t: number) => { span = [f, t]; return q; },
        single: async () => ({ data: { name: "Acme", slug: "acme", github_org: null } }),
        insert: async (r: unknown) => { inserted.push({ table, r }); return { error: null }; },
        then: (res: (v: unknown) => unknown) => Promise.resolve({ data: (tableRows[table] ?? []).slice(span[0], span[1] + 1), count: 0, error: null }).then(res),
      };
      return q;
    },
  }),
}));

import crypto from "crypto";
import { POST } from "@/app/api/report/route";
import { canonicalJson } from "@/lib/trustRecord";
import { _resetExportKeyCache, keyIdMatches } from "@/lib/exportSigning";

const post = () => POST(new NextRequest(new URL("/api/report", "https://app.example"), {
  method: "POST", body: JSON.stringify({ framework: "SOC2", period_start: "2026-09-01T00:00:00Z", period_end: "2026-10-01T00:00:00Z" }),
  headers: { "content-type": "application/json" },
}));

const KEY = process.env.EXPORT_SIGNING_KEY, CRON = process.env.CRON_SECRET;
beforeEach(() => { rendered = null; renderFails = false; inserted.length = 0; registerFails = false; registerLoads.length = 0; evidenceFramework = "soc2"; unreviewed = []; tableRows = {}; process.env.EXPORT_SIGNING_KEY = "test-signing-material"; delete process.env.CRON_SECRET; });
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

  it("a cron secret is never used as a signing key", async () => {
    delete process.env.EXPORT_SIGNING_KEY;
    process.env.CRON_SECRET = "cron-only";
    const res = await post();
    expect(res.status).toBe(503);
  });
});

describe("POST /api/report with an Ed25519 key: a bundle anyone can verify", () => {
  const PRIV = process.env.EXPORT_SIGNING_PRIVATE_KEY;
  let publicPem = "";
  beforeAll(() => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    process.env.EXPORT_SIGNING_PRIVATE_KEY = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    publicPem = publicKey.export({ type: "spki", format: "pem" }) as string;
    _resetExportKeyCache();
  });
  afterAll(() => { process.env.EXPORT_SIGNING_PRIVATE_KEY = PRIV; _resetExportKeyCache(); });

  const postBundle = () => POST(new NextRequest(new URL("/api/report", "https://app.example"), {
    method: "POST", body: JSON.stringify({ framework: "SOC2", period_start: "2026-09-01T00:00:00Z", period_end: "2026-10-01T00:00:00Z", format: "bundle" }),
    headers: { "content-type": "application/json" },
  }));

  it("returns the PDF and its evidence record, signed over the record's canonical JSON with the published key", async () => {
    const res = await postBundle();
    expect(res.status).toBe(200);
    const body = await res.json() as { pdf_base64: string; evidence: { record: Record<string, unknown>; signature: { algorithm: string; value: string; key_id: string; public_key_pem: string; record_sha256: string } } };
    expect(Buffer.from(body.pdf_base64, "base64").toString()).toBe("%PDF-1.4 test");
    const { record, signature } = body.evidence;
    expect(signature.algorithm).toBe("Ed25519");
    const canonical = canonicalJson(record);
    // the SHA-256 the PDF prints is the record's
    expect(signature.record_sha256).toBe(crypto.createHash("sha256").update(canonical).digest("hex"));
    // verifiable with the public key alone, and it is the deployment's key
    expect(crypto.verify(null, Buffer.from(canonical), crypto.createPublicKey(publicPem), Buffer.from(signature.value, "base64"))).toBe(true);
    expect(keyIdMatches(signature, publicPem)).toBe(true);
    // a changed record fails
    const tampered = canonicalJson({ ...record, period_end: "2026-12-31T00:00:00Z" });
    expect(crypto.verify(null, Buffer.from(tampered), crypto.createPublicKey(publicPem), Buffer.from(signature.value, "base64"))).toBe(false);
  });

  it("the change register and its sample (seeded with the report id) are in the signed record", async () => {
    const body = await (await postBundle()).json();
    const { record, signature } = body.evidence;
    expect(registerLoads).toEqual(["org-1"]);
    expect(record.change_register.summary.merged).toBe(1);
    expect(record.change_register.sample).toMatchObject({ seed: record.report_id, size: 25, picked: [{ repo: "acme/api", number: 1 }] });
    expect(crypto.verify(null, Buffer.from(canonicalJson(record)), crypto.createPublicKey(publicPem), Buffer.from(signature.value, "base64"))).toBe(true);
  });

  it("a register that can't be built is stated in the record and the report still generates", async () => {
    registerFails = true;
    const res = await postBundle();
    expect(res.status).toBe(200);
    expect((await res.json()).evidence.record.change_register).toEqual({ error: expect.stringContaining("could not be built") });
  });

  it("AI code governance has no change-control criterion: no register, but its mapping view is signed", async () => {
    evidenceFramework = "aigov";
    const body = await (await postBundle()).json();
    expect(registerLoads).toEqual([]);
    expect(body.evidence.record).not.toHaveProperty("change_register");
    expect(body.evidence.record.framework_view.kind).toBe("ai_mapping");
  });

  it("ISO 27001 carries its SoA input in the signed record; SOC 2 has no separate view", async () => {
    evidenceFramework = "iso27001";
    expect((await (await postBundle()).json()).evidence.record.framework_view.kind).toBe("iso_soa");
    evidenceFramework = "soc2";
    expect((await (await postBundle()).json()).evidence.record).not.toHaveProperty("framework_view");
  });

  it("lists every gap, sign-off and secret -- past one database page -- with tidy secret labels", async () => {
    unreviewed = Array.from({ length: 640 }, (_, i) => ({ repo: "acme/api", pr_number: 1, scan_id: "s", file_path: `f${i}.py`, risk_score: "CRITICAL", ai_percentage: 0.1 }));
    tableRows = {
      attestations: Array.from({ length: 1200 }, (_, i) => ({ id: `a${i}`, scan_id: "s", file_path: `f${i}`, risk_score: "HIGH", reviewer_email: "r@acme.test", payload_hash: "h", created_at: "2026-09-10T00:00:00Z" })),
      secret_findings: [
        { id: "x1", file_path: "a.tf", secret_type: "generic", severity: "HIGH", label: "Hardcoded Hardcoded secret", status: "open", created_at: "2026-09-10T00:00:00Z" },
        { id: "x2", file_path: "b.ts", secret_type: "pem", severity: "CRITICAL", label: "Hardcoded Private key", status: "open", created_at: "2026-09-10T00:00:00Z" },
      ],
    };
    const { record } = (await (await postBundle()).json()).evidence;
    expect(record.gaps).toHaveLength(640);
    expect(record.gaps[0]).toEqual({ repo: "acme/api", pr_number: 1, file_path: "f0.py", risk_score: "CRITICAL", ai_percentage: 0.1 });
    expect(record.attestations).toHaveLength(1200);
    expect(record.metrics.total_attestations).toBe(1200);
    expect(record.secrets.map((s: { label: string }) => s.label)).toEqual(["Hardcoded secret", "Hardcoded Private key"]);
  });

  it("signs with Ed25519 even when no HMAC key is set", async () => {
    delete process.env.EXPORT_SIGNING_KEY;
    const res = await postBundle();
    expect(res.status).toBe(200);
    expect((await res.json()).evidence.signature.algorithm).toBe("Ed25519");
  });
});
