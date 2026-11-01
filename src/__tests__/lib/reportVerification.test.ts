/**
 * @jest-environment node
 *
 * Verifying an evidence file with Web Crypto (lib/reportVerification.ts), as the /verify page does: real Ed25519
 * signatures over a real report record, checked against the PUBLISHED key; every way a file can be wrong fails.
 */
import crypto from "crypto";
import { verifyEvidence, keyIdOf, type PublishedKey } from "@/lib/reportVerification";
import { canonicalJson } from "@/lib/canonicalJson";
import { buildRegister, registerForReport } from "@/lib/changeRegister";
import { keyId } from "@/lib/exportSigning";

const subtle = globalThis.crypto.subtle;
const pair = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return { privateKey, pem: publicKey.export({ type: "spki", format: "pem" }) as string, id: keyId(publicKey) };
};
const ours = pair();
const PUBLISHED: PublishedKey = { key_id: ours.id, public_key_pem: ours.pem };

const register = registerForReport(buildRegister({
  period_start: "2026-10-01T00:00:00Z", period_end: "2026-10-31T23:59:59Z",
  pulls: Array.from({ length: 8 }, (_, i) => ({ repo: "acme/api", number: i + 1, title: `PR ${i + 1}`, author: "alice",
    merged_at: `2026-10-1${i}T12:00:00Z`, merged_by: "carol", head_sha: `sha${i}`, url: `u${i}` })),
  reviews: new Map(), scans: [], riskyFiles: [], signoffs: [], coverage: [{ repo: "acme/api", read: true, pulls: 8 }],
}), "REPORT-1", 3);
const baseRecord = { report_id: "REPORT-1", framework: "SOC2", period_start: "2026-10-01T00:00:00Z", period_end: "2026-10-31T23:59:59Z", change_register: register };

function sign(record: object, key = ours) {
  const canonical = canonicalJson(record);
  return {
    record,
    signature: {
      algorithm: "Ed25519", value: crypto.sign(null, Buffer.from(canonical), key.privateKey).toString("base64"),
      key_id: key.id, public_key_pem: key.pem, signed_content: "canonical JSON of `record`",
      record_sha256: crypto.createHash("sha256").update(canonical).digest("hex"),
    },
  };
}
const verify = (doc: unknown, published: PublishedKey | null = PUBLISHED, s: SubtleCrypto = subtle) => verifyEvidence(doc, published, s);
const step = (r: Awaited<ReturnType<typeof verify>>, label: string) => r.steps.find(s => s.label === label);

describe("verifyEvidence", () => {
  it("a genuine report verifies: fingerprint, published key, signature, every register row, the sample", async () => {
    const doc = sign(baseRecord);
    const r = await verify(doc);
    expect(r.verdict).toBe("verified");
    expect(r.steps.map(s => [s.label, s.ok])).toEqual([
      ["Record fingerprint", true], ["Signing key", true], ["Signature", true], ["Change register rows", true], ["Auditor sample", true],
    ]);
    expect(r.record_sha256).toBe(doc.signature.record_sha256);
    expect(r.report).toEqual({ id: "REPORT-1", framework: "SOC2", period_start: "2026-10-01T00:00:00Z", period_end: "2026-10-31T23:59:59Z" });
  });

  it("a record changed after signing fails its fingerprint and its signature", async () => {
    const doc = sign(baseRecord);
    const r = await verify({ ...doc, record: { ...baseRecord, period_end: "2026-12-31T00:00:00Z" } });
    expect(r.verdict).toBe("failed");
    expect(step(r, "Record fingerprint")!.ok).toBe(false);
    expect(step(r, "Signature")!.ok).toBe(false);
  });

  it("a file signed with someone else's key -- even carrying that key -- fails against the published key", async () => {
    const r = await verify(sign(baseRecord, pair()));
    expect(r.verdict).toBe("failed");
    expect(step(r, "Signing key")!.detail).toMatch(/not the published key/);
  });

  it("a file claiming our key id but carrying another key is inconsistent", async () => {
    const doc = sign(baseRecord);
    const r = await verify({ ...doc, signature: { ...doc.signature, public_key_pem: pair().pem } });
    expect(step(r, "Signing key")!.ok).toBe(false);
  });

  it("the signature is checked with the published key, not one the file carries (a file with no key still verifies)", async () => {
    const doc = sign(baseRecord);
    const { public_key_pem: _drop, ...noKey } = doc.signature;
    expect((await verify({ ...doc, signature: noKey })).verdict).toBe("verified");
  });

  it("a validly signed record whose register row was altered before signing is caught by the row hash", async () => {
    const rows = register.rows.map((row, i) => (i === 2 ? { ...row, title: "edited" } : row));
    const r = await verify(sign({ ...baseRecord, change_register: { ...register, rows } }));
    expect(step(r, "Signature")!.ok).toBe(true);
    expect(step(r, "Change register rows")).toEqual({ label: "Change register rows", ok: false, detail: "1 of 8 rows don't match their SHA-256." });
  });

  it("a sample that doesn't re-draw from its seed is caught", async () => {
    const sample = { ...register.sample, picked: register.rows.slice(0, 3).map(x => ({ repo: x.repo, number: x.number, row_sha256: x.row_sha256 })) };
    const same = register.sample.picked.map(p => p.number).join() === sample.picked.map(p => p.number).join();
    const r = await verify(sign({ ...baseRecord, change_register: { ...register, sample: same ? { ...sample, seed: "other" } : sample } }));
    expect(step(r, "Auditor sample")!.ok).toBe(false);
  });

  it("HMAC, no published key, or a browser without Ed25519: can't be verified here (not 'verified')", async () => {
    const doc = sign(baseRecord);
    expect((await verify({ ...doc, signature: { algorithm: "HMAC-SHA256", value: "ab", record_sha256: doc.signature.record_sha256 } })).verdict).toBe("unverifiable");
    expect((await verify(doc, null)).verdict).toBe("unverifiable");
    const noEd = { digest: subtle.digest.bind(subtle), importKey: async () => { throw new DOMException("Unrecognized name", "NotSupportedError"); } } as unknown as SubtleCrypto;
    const r = await verify(doc, PUBLISHED, noEd);
    expect(r.verdict).toBe("unverifiable");
    expect(step(r, "Signature")!.detail).toMatch(/verify-trust-record\.mjs/);
  });

  it("anything else isn't an evidence file", async () => {
    for (const bad of [null, "x", {}, { record: {} }, { signature: {} }]) expect((await verify(bad)).verdict).toBe("failed");
  });

  it("computes key ids exactly as the server does", async () => {
    expect(await keyIdOf(subtle, ours.pem)).toBe(ours.id);
  });
});
