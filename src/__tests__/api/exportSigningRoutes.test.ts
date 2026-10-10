/**
 * @jest-environment node
 *
 * Public-key signing, end to end: the published public key, the signed audit-log export, and the offline
 * verifier an auditor runs with nothing but Node and the public key.
 */
import crypto from "crypto";
import { execFileSync } from "child_process";
import { mkdtempSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { _resetExportKeyCache, keyIdFromPem } from "@/lib/exportSigning";
import { buildTrustRecord, buildTrustRecordSignature, type TrustRecordInput } from "@/lib/trustRecord";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-admin", actor_email: "admin@acme.dev", role: "admin" }),
}));

import { GET as publicKeyGET } from "@/app/.well-known/trustledger-export-signing-key/route";
import { GET as signedGET } from "@/app/api/export/signed/route";

const genEd = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return { privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string, publicPem: publicKey.export({ type: "spki", format: "pem" }) as string };
};
const saved = { priv: process.env.EXPORT_SIGNING_PRIVATE_KEY, hmac: process.env.EXPORT_SIGNING_KEY };
const setPriv = (pem?: string) => { if (pem) process.env.EXPORT_SIGNING_PRIVATE_KEY = pem; else delete process.env.EXPORT_SIGNING_PRIVATE_KEY; _resetExportKeyCache(); };
afterEach(() => {
  setPriv(saved.priv);
  if (saved.hmac === undefined) delete process.env.EXPORT_SIGNING_KEY; else process.env.EXPORT_SIGNING_KEY = saved.hmac;
});
beforeEach(() => {
  db = fakeSupabase({
    organizations: [{ id: "org-1", name: "Acme", slug: "acme" }],
    org_members: [{ id: "m1", org_id: "org-1", user_id: "u-admin", email: "admin@acme.dev", role: "admin", custom_role_id: null }],
    audit_log: [],
  });
});

describe("/.well-known/trustledger-export-signing-key", () => {
  it("publishes the public key and its id when a private key is set", async () => {
    const k = genEd(); setPriv(k.privatePem);
    const res = publicKeyGET();
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.algorithm).toBe("Ed25519");
    expect(body.key_id).toBe(keyIdFromPem(k.publicPem));
    expect(body.public_key_pem.trim()).toBe(k.publicPem.trim());
    expect(JSON.stringify(body)).not.toContain("PRIVATE");
  });
  it("404s when no key is configured", async () => {
    setPriv(undefined);
    expect(publicKeyGET().status).toBe(404);
  });
});

describe("signed audit-log export", () => {
  const req = () => new NextRequest(new URL("https://app.example/api/export/signed"));

  it("is Ed25519-signed when a private key is set, verifiable with the published public key", async () => {
    const k = genEd(); setPriv(k.privatePem); delete process.env.EXPORT_SIGNING_KEY;
    const res = await signedGET(req());
    expect(res.status).toBe(200);
    expect(res.headers.get("X-TrustLedger-Signature-Algo")).toBe("Ed25519");
    const out = await res.json();
    const i = out.integrity;
    expect(i.signature_algo).toBe("Ed25519");
    expect(i.key_id).toBe(keyIdFromPem(k.publicPem));
    expect(i.public_key_url).toBe("https://app.example/.well-known/trustledger-export-signing-key");
    // Rebuild the signed bytes exactly as the route does, and verify with the PUBLIC key only.
    const content = JSON.stringify({ org_id: out.metadata.org_id, period_start: out.metadata.period_start, period_end: out.metadata.period_end, exported_at: out.metadata.exported_at, event_count: out.metadata.event_count, chain_valid: i.chain_valid, events: out.events });
    expect(crypto.verify(null, Buffer.from(content), crypto.createPublicKey(k.publicPem), Buffer.from(i.signature, "base64"))).toBe(true);
    expect(crypto.verify(null, Buffer.from(content.replace("acme", "evil") + "x"), crypto.createPublicKey(k.publicPem), Buffer.from(i.signature, "base64"))).toBe(false);
  });

  it("CSV export names the algorithm and where to fetch the public key", async () => {
    const k = genEd(); setPriv(k.privatePem);
    const res = await signedGET(new NextRequest(new URL("https://app.example/api/export/signed?format=csv")));
    const csv = await res.text();
    expect(csv).toContain("# Signature (Ed25519): ");
    expect(csv).toContain(`# Public key id: ${keyIdFromPem(k.publicPem)}`);
    expect(csv).toContain("# Public key: https://app.example/.well-known/trustledger-export-signing-key");
  });

  it("falls back to HMAC when only the shared secret is set, and 503s with neither", async () => {
    setPriv(undefined); process.env.EXPORT_SIGNING_KEY = "shared";
    const res = await signedGET(req());
    expect((await res.json()).integrity.signature_algo).toBe("HMAC-SHA256");
    delete process.env.EXPORT_SIGNING_KEY;
    const savedCron = process.env.CRON_SECRET; delete process.env.CRON_SECRET;
    try { expect((await signedGET(req())).status).toBe(503); }
    finally { if (savedCron !== undefined) process.env.CRON_SECRET = savedCron; }
  });
});

describe("offline verifier (scripts/verify-trust-record.mjs)", () => {
  const INPUT: TrustRecordInput = {
    org_name: "Acme", scan: { id: "s1", repo: "acme/app", pr_number: 7, commit_sha: "abc1234", created_at: "2026-10-01T00:00:00Z", overall_risk: "HIGH", total_ai_percentage: 12, triggered_by: "pr", duration_ms: 100 },
    engine_version: "9", health: null, files: [], attestations: [], triage: new Map(), open_blocking_violations: 0, generated_at: "2026-10-02T00:00:00Z",
  };
  const script = join(process.cwd(), "scripts", "verify-trust-record.mjs");
  const dir = mkdtempSync(join(tmpdir(), "tl-verify-"));
  const run = (...args: string[]) => {
    try { return { code: 0, out: execFileSync(process.execPath, [script, ...args], { encoding: "utf8", stdio: "pipe" }) }; }
    catch (e) { const err = e as { status: number; stdout: string; stderr: string }; return { code: err.status, out: (err.stdout ?? "") + (err.stderr ?? "") }; }
  };
  const write = (name: string, value: unknown) => { const p = join(dir, name); writeFileSync(p, typeof value === "string" ? value : JSON.stringify(value)); return p; };

  it("verifies an intact record; with the trusted key file too", () => {
    const k = genEd(); setPriv(k.privatePem);
    const record = buildTrustRecord(INPUT);
    const doc = write("ok.json", { record, signature: buildTrustRecordSignature(record, undefined) });
    expect(run(doc).code).toBe(0);
    expect(run(doc, write("trusted.pem", k.publicPem))).toMatchObject({ code: 0 });
  });

  it("fails a tampered record, and a record signed with a key that isn't the trusted one", () => {
    const k = genEd(); setPriv(k.privatePem);
    const record = buildTrustRecord(INPUT);
    const sig = buildTrustRecordSignature(record, undefined);
    const tampered = write("bad.json", { record: { ...record, organization: "Someone else" }, signature: sig });
    expect(run(tampered).code).toBe(1);
    const other = genEd();
    expect(run(write("good.json", { record, signature: sig }), write("other.pem", other.publicPem)).code).toBe(1);
  });

  it("explains that HMAC documents can't be verified offline", () => {
    setPriv(undefined);
    const record = buildTrustRecord(INPUT);
    const r = run(write("hmac.json", { record, signature: buildTrustRecordSignature(record, "shared") }));
    expect(r.code).toBe(2);
    expect(r.out).toContain("HMAC-SHA256");
  });
});
