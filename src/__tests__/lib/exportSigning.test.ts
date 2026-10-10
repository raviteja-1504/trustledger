/**
 * @jest-environment node
 *
 * Public-key (Ed25519) signing of exported evidence. The point of public-key signing is that an auditor can
 * verify a document with the published public key alone, and that a document signed with a stranger's key is
 * rejected rather than self-validating.
 */
import crypto from "crypto";
import {
  signEd25519, verifyEd25519, keyIdMatches, keyId, keyIdFromPem, exportPublicKey, exportPrivateKey,
  _resetExportKeyCache, EXPORT_SIG_ALGO,
} from "@/lib/exportSigning";
import { buildTrustRecord, buildTrustRecordSignature, checkTrustRecord, canonicalJson, type TrustRecordInput } from "@/lib/trustRecord";

const genEd = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicPem: publicKey.export({ type: "spki", format: "pem" }) as string,
  };
};

const INPUT: TrustRecordInput = {
  org_name: "Acme", scan: { id: "s1", repo: "acme/app", pr_number: 7, commit_sha: "abc1234", created_at: "2026-10-01T00:00:00Z", overall_risk: "HIGH", total_ai_percentage: 12, triggered_by: "pr", duration_ms: 100 },
  engine_version: "9", health: null, files: [], attestations: [], triage: new Map(), open_blocking_violations: 0, generated_at: "2026-10-02T00:00:00Z",
};
const record = buildTrustRecord(INPUT);

const saved = process.env.EXPORT_SIGNING_PRIVATE_KEY;
const setKey = (pem: string | undefined) => { if (pem === undefined) delete process.env.EXPORT_SIGNING_PRIVATE_KEY; else process.env.EXPORT_SIGNING_PRIVATE_KEY = pem; _resetExportKeyCache(); };
afterEach(() => { setKey(saved); });

describe("key handling", () => {
  it("loads a valid Ed25519 key and derives a stable id and public PEM", () => {
    const { privatePem, publicPem } = genEd();
    setKey(privatePem);
    expect(exportPrivateKey()).not.toBeNull();
    const pub = exportPublicKey()!;
    expect(pub.algorithm).toBe("Ed25519");
    expect(pub.key_id).toMatch(/^[0-9a-f]{16}$/);
    expect(pub.key_id).toBe(keyIdFromPem(publicPem));
    expect(pub.public_key_pem.trim()).toBe(publicPem.trim());
  });

  it("ignores a missing, malformed, or non-Ed25519 key", () => {
    setKey(undefined); expect(exportPrivateKey()).toBeNull();
    setKey("not a pem"); expect(exportPrivateKey()).toBeNull();
    const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    setKey(rsa); expect(exportPrivateKey()).toBeNull();
    expect(exportPublicKey()).toBeNull();
  });
});

describe("sign and verify", () => {
  it("signs canonical bytes and verifies them; a changed byte fails", () => {
    const { privatePem } = genEd();
    setKey(privatePem);
    const sig = signEd25519(canonicalJson(record), "note")!;
    expect(sig.algorithm).toBe(EXPORT_SIG_ALGO);
    expect(Buffer.from(sig.value, "base64")).toHaveLength(64);
    expect(verifyEd25519(canonicalJson(record), sig)).toBe(true);
    expect(verifyEd25519(canonicalJson(record) + " ", sig)).toBe(false);
    expect(verifyEd25519(canonicalJson(record), { ...sig, value: Buffer.alloc(64).toString("base64") })).toBe(false);
  });

  it("returns null when no private key is configured", () => {
    setKey(undefined);
    expect(signEd25519("x", "note")).toBeNull();
  });

  it("keyIdMatches only when the embedded key is our trusted key and matches its own id", () => {
    const ours = genEd(), theirs = genEd();
    setKey(ours.privatePem);
    const sig = signEd25519("x", "note")!;
    expect(keyIdMatches(sig, ours.publicPem)).toBe(true);
    expect(keyIdMatches(sig, theirs.publicPem)).toBe(false);                       // not our key
    expect(keyIdMatches({ ...sig, key_id: "0".repeat(16) }, ours.publicPem)).toBe(false); // claimed id lies
    expect(keyIdMatches({ ...sig, public_key_pem: theirs.publicPem }, ours.publicPem)).toBe(false);
    expect(keyId(crypto.createPublicKey(ours.publicPem))).toBe(keyIdFromPem(ours.publicPem));
  });
});

describe("Trust Record end to end", () => {
  it("prefers Ed25519 when a private key is set, and verifies against the published public key", () => {
    const { privatePem } = genEd();
    setKey(privatePem);
    const sig = buildTrustRecordSignature(record, "hmac-secret")!;
    expect(sig.algorithm).toBe("Ed25519");
    const pub = exportPublicKey()!.public_key_pem;
    expect(checkTrustRecord({ record, signature: sig }, "hmac-secret", pub)).toBe("valid");
  });

  it("detects tampering after signing", () => {
    const { privatePem } = genEd();
    setKey(privatePem);
    const sig = buildTrustRecordSignature(record, undefined)!;
    const pub = exportPublicKey()!.public_key_pem;
    expect(record.verdict.merge_gate).toBe("clear");
    const tampered = { ...record, verdict: { ...record.verdict, merge_gate: "blocked" } };
    expect(checkTrustRecord({ record: tampered, signature: sig }, undefined, pub)).toBe("tampered");
  });

  it("rejects a document signed with a stranger's key as unknown_key, even though it self-verifies", () => {
    const stranger = genEd();
    // Attacker signs a forged record with their OWN key and embeds their public key.
    const forged = { ...record, organization: "Attacker Inc" };
    const forgedSig = crypto.sign(null, Buffer.from(canonicalJson(forged), "utf8"), crypto.createPrivateKey(stranger.privatePem)).toString("base64");
    const strangerPubId = keyIdFromPem(stranger.publicPem);
    const doc = { record: forged, signature: { algorithm: "Ed25519", value: forgedSig, key_id: strangerPubId, public_key_pem: stranger.publicPem, signed_content: "x" } };
    // The forged doc verifies against the stranger's OWN key...
    expect(verifyEd25519(canonicalJson(forged), doc.signature)).toBe(true);
    // ...but our server, trusting only OUR key, rejects it.
    const ours = genEd();
    setKey(ours.privatePem);
    expect(checkTrustRecord(doc, undefined, exportPublicKey()!.public_key_pem)).toBe("unknown_key");
  });

  it("an Ed25519 document on a server with no public key configured is not_configured", () => {
    const { privatePem } = genEd();
    setKey(privatePem);
    const sig = buildTrustRecordSignature(record, undefined)!;
    expect(checkTrustRecord({ record, signature: sig }, "hmac", undefined)).toBe("not_configured");
  });

  it("falls back to HMAC when only the shared secret is set", () => {
    setKey(undefined);
    const sig = buildTrustRecordSignature(record, "hmac-secret")!;
    expect(sig.algorithm).toBe("HMAC-SHA256");
    expect(checkTrustRecord({ record, signature: sig }, "hmac-secret")).toBe("valid");
    expect(buildTrustRecordSignature(record, undefined)).toBeNull();
  });
});
