/**
 * Attestation signing tests — task spec F:
 *   F1  valid signature
 *   F2  modified payload (single-field tamper)
 *   F3  invalid signature (wrong base64)
 *   F4  revoked key → verifyAttestation returns "key_revoked"
 *   F5  retired key → verifyAttestation returns "key_retired" (but payload still verifies)
 *   F6  key not found → verifyAttestation returns "key_not_found"
 *   F7  incorrect commit SHA (payload field mismatch)
 *   F8  modified file hash (payload field mismatch)
 *   F9  pre-signing attestation (no signature) → "no_signature"
 *   F10 unauthorized signing (env var absent) → ensureSigningKey returns null; no signing
 */

import crypto from "crypto";
import {
  generateSigningKeyPair,
  signCanonicalPayload,
  verifyCanonicalPayload,
  canonicalPayloadBytes,
  buildFindingsDigest,
  buildPolicyVersion,
  verifyAttestation,
  ensureSigningKey,
  PAYLOAD_SCHEMA_VERSION,
  type CanonicalAttestationPayload,
} from "@/lib/attestationSigning";
import { checkAuditChain, auditEntryHash, type ChainRow } from "@/lib/audit";

// ── Helpers ───────────────────────────────────────────────────────────────────

function makePayload(overrides: Partial<CanonicalAttestationPayload> = {}): CanonicalAttestationPayload {
  return {
    schema_version:  PAYLOAD_SCHEMA_VERSION,
    reviewer_email:  "alice@example.com",
    reviewer_id:     "user-uuid-1",
    org_id:          "org-uuid-1",
    repo:            "acme/backend",
    commit_sha:      "a".repeat(40),
    file_path:       "src/auth/login.ts",
    content_hash:    "deadbeef".repeat(8),
    scan_id:         "scan-uuid-1",
    findings_digest: buildFindingsDigest([{ severity: "HIGH", rule: "SQL_INJECTION" }]),
    decision:        "attested",
    policy_version:  buildPolicyVersion({ block_on_critical: true, block_on_high: true }),
    timestamp:       "2026-11-24T00:00:00.000Z",
    key_id:          "key-uuid-1",
    ...overrides,
  };
}

/** Minimal mock DB that returns configured rows for specific tables / query keys. */
function makeMockDb(keyRows: Record<string, { public_key_pem: string; status: string } | null>) {
  return {
    from: (table: string) => ({
      select: () => ({
        eq: (_col: string, val: string) => ({
          single: () =>
            Promise.resolve({ data: table === "signing_keys" ? (keyRows[val] ?? null) : null }),
        }),
      }),
      insert: () => ({ select: () => ({ single: () => Promise.resolve({ data: null }) }) }),
      is: () => ({
        eq: () => ({ maybeSingle: () => Promise.resolve({ data: null }) }),
      }),
      upsert: () => ({ select: () => ({ single: () => Promise.resolve({ data: null }) }) }),
    }),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any;
}

// ── F1: Valid signature ───────────────────────────────────────────────────────

test("F1: sign then verify produces a valid signature", () => {
  const { privateKeyPem, publicKeyPem } = generateSigningKeyPair();
  const payload = makePayload();
  const sig = signCanonicalPayload(payload, privateKeyPem);

  expect(typeof sig).toBe("string");
  expect(sig.length).toBeGreaterThan(0);
  expect(verifyCanonicalPayload(payload, sig, publicKeyPem)).toBe(true);
});

// ── F2: Modified payload ──────────────────────────────────────────────────────

test("F2: modifying any payload field after signing invalidates the signature", () => {
  const { privateKeyPem, publicKeyPem } = generateSigningKeyPair();
  const payload = makePayload();
  const sig = signCanonicalPayload(payload, privateKeyPem);

  const tampered = { ...payload, reviewer_email: "eve@attacker.com" };
  expect(verifyCanonicalPayload(tampered, sig, publicKeyPem)).toBe(false);
});

// ── F3: Invalid signature ─────────────────────────────────────────────────────

test("F3: a random base64 string is not a valid signature", () => {
  const { publicKeyPem } = generateSigningKeyPair();
  const payload = makePayload();
  const garbage = Buffer.alloc(64, 0xff).toString("base64");
  expect(verifyCanonicalPayload(payload, garbage, publicKeyPem)).toBe(false);
});

test("F3: an empty signature string returns false without throwing", () => {
  const { publicKeyPem } = generateSigningKeyPair();
  expect(verifyCanonicalPayload(makePayload(), "", publicKeyPem)).toBe(false);
});

// ── F4: Revoked key ───────────────────────────────────────────────────────────

test("F4: verifyAttestation returns key_revoked when key status is revoked", async () => {
  const { privateKeyPem, publicKeyPem } = generateSigningKeyPair();
  const payload = makePayload({ key_id: "key-revoked" });
  const sig = signCanonicalPayload(payload, privateKeyPem);

  const db = makeMockDb({ "key-revoked": { public_key_pem: publicKeyPem, status: "revoked" } });
  const { result } = await verifyAttestation(db, { signature: sig, signing_key_id: "key-revoked", payload_json: payload });
  expect(result).toBe("key_revoked");
});

// ── F5: Retired key ───────────────────────────────────────────────────────────

test("F5: verifyAttestation returns key_retired (not invalid) when key is retired but signature is correct", async () => {
  const { privateKeyPem, publicKeyPem } = generateSigningKeyPair();
  const payload = makePayload({ key_id: "key-retired" });
  const sig = signCanonicalPayload(payload, privateKeyPem);

  const db = makeMockDb({ "key-retired": { public_key_pem: publicKeyPem, status: "retired" } });
  const { result } = await verifyAttestation(db, { signature: sig, signing_key_id: "key-retired", payload_json: payload });
  expect(result).toBe("key_retired");
});

test("F5: verifyAttestation returns invalid when payload is tampered even on a retired key", async () => {
  const { privateKeyPem, publicKeyPem } = generateSigningKeyPair();
  const payload = makePayload({ key_id: "key-retired" });
  const sig = signCanonicalPayload(payload, privateKeyPem);
  const tampered = { ...payload, file_path: "src/evil/backdoor.ts" };

  const db = makeMockDb({ "key-retired": { public_key_pem: publicKeyPem, status: "retired" } });
  const { result } = await verifyAttestation(db, { signature: sig, signing_key_id: "key-retired", payload_json: tampered });
  expect(result).toBe("invalid");
});

// ── F6: Key not found ─────────────────────────────────────────────────────────

test("F6: verifyAttestation returns key_not_found when signing_key_id row is missing", async () => {
  const { privateKeyPem } = generateSigningKeyPair();
  const payload = makePayload({ key_id: "key-missing" });
  const sig = signCanonicalPayload(payload, privateKeyPem);

  const db = makeMockDb({}); // no rows
  const { result } = await verifyAttestation(db, { signature: sig, signing_key_id: "key-missing", payload_json: payload });
  expect(result).toBe("key_not_found");
});

// ── F7: Incorrect commit SHA ──────────────────────────────────────────────────

test("F7: signing with one commit SHA and verifying with another fails", () => {
  const { privateKeyPem, publicKeyPem } = generateSigningKeyPair();
  const payload = makePayload({ commit_sha: "a".repeat(40) });
  const sig = signCanonicalPayload(payload, privateKeyPem);

  const wrongCommit = { ...payload, commit_sha: "b".repeat(40) };
  expect(verifyCanonicalPayload(wrongCommit, sig, publicKeyPem)).toBe(false);
});

// ── F8: Modified file hash ────────────────────────────────────────────────────

test("F8: changing content_hash after signing fails verification", () => {
  const { privateKeyPem, publicKeyPem } = generateSigningKeyPair();
  const payload = makePayload({ content_hash: "aabbccdd".repeat(8) });
  const sig = signCanonicalPayload(payload, privateKeyPem);

  const wrongHash = { ...payload, content_hash: "11223344".repeat(8) };
  expect(verifyCanonicalPayload(wrongHash, sig, publicKeyPem)).toBe(false);
});

// ── F9: Pre-signing attestation (no signature) ────────────────────────────────

test("F9: attestation without a signature returns no_signature", async () => {
  const db = makeMockDb({});
  const { result } = await verifyAttestation(db, { signature: null, signing_key_id: null, payload_json: null });
  expect(result).toBe("no_signature");
});

test("F9: partial (signature present but payload_json null) returns no_signature", async () => {
  const db = makeMockDb({});
  const { result } = await verifyAttestation(db, { signature: "aGVsbG8=", signing_key_id: "key-uuid-1", payload_json: null });
  expect(result).toBe("no_signature");
});

// ── F10: Unauthorized signing (env var absent) ────────────────────────────────

test("F10: ensureSigningKey returns null when ATTESTATION_SIGNING_KEY is not set", async () => {
  const original = process.env.ATTESTATION_SIGNING_KEY;
  delete process.env.ATTESTATION_SIGNING_KEY;
  try {
    const db = makeMockDb({});
    const result = await ensureSigningKey(db);
    expect(result).toBeNull();
  } finally {
    if (original !== undefined) process.env.ATTESTATION_SIGNING_KEY = original;
  }
});

test("F10: ensureSigningKey returns null for an invalid PEM string", async () => {
  const original = process.env.ATTESTATION_SIGNING_KEY;
  process.env.ATTESTATION_SIGNING_KEY = "not-a-valid-pem";
  try {
    const db = makeMockDb({});
    const result = await ensureSigningKey(db);
    expect(result).toBeNull();
  } finally {
    if (original !== undefined) process.env.ATTESTATION_SIGNING_KEY = original;
    else delete process.env.ATTESTATION_SIGNING_KEY;
  }
});

// ── Additional: Deterministic serialization ───────────────────────────────────

test("canonical payload bytes are identical regardless of JS object key order", () => {
  const p1 = makePayload();
  // Same logical payload with keys in a different insertion order
  const p2: CanonicalAttestationPayload = {
    timestamp:       p1.timestamp,
    key_id:          p1.key_id,
    decision:        p1.decision,
    policy_version:  p1.policy_version,
    findings_digest: p1.findings_digest,
    scan_id:         p1.scan_id,
    content_hash:    p1.content_hash,
    file_path:       p1.file_path,
    commit_sha:      p1.commit_sha,
    repo:            p1.repo,
    org_id:          p1.org_id,
    reviewer_id:     p1.reviewer_id,
    reviewer_email:  p1.reviewer_email,
    schema_version:  p1.schema_version,
  };
  expect(canonicalPayloadBytes(p1).toString("hex")).toBe(canonicalPayloadBytes(p2).toString("hex"));
});

test("buildFindingsDigest produces different digests for different findings", () => {
  const d1 = buildFindingsDigest([{ severity: "HIGH", rule: "SQL_INJECTION" }]);
  const d2 = buildFindingsDigest([{ severity: "CRITICAL", rule: "RCE" }]);
  expect(d1).not.toBe(d2);
  // Idempotent
  expect(buildFindingsDigest([{ severity: "HIGH", rule: "SQL_INJECTION" }])).toBe(d1);
});

test("buildPolicyVersion is stable for the same gate settings", () => {
  const gate = { block_on_critical: true, block_on_high: false };
  expect(buildPolicyVersion(gate)).toBe(buildPolicyVersion(gate));
});

test("buildPolicyVersion differs when block_on_high changes", () => {
  expect(buildPolicyVersion({ block_on_critical: true, block_on_high: false })).not.toBe(
    buildPolicyVersion({ block_on_critical: true, block_on_high: true }),
  );
});

// ── F-chain: Broken audit chain (spec F.8 / spec E) ──────────────────────────
// The audit chain is primarily tested in src/__tests__/lib/audit.test.ts.
// This test verifies that checkAuditChain detects a broken prev_hash link, covering
// the invariant that attestation events recorded in audit_log cannot be silently removed
// or reordered without detection.

test("F-chain: checkAuditChain detects a broken link when prev_hash is tampered", () => {
  const actor   = "actor@example.com";
  const payload = { scan_id: "scan-1", file_path: "src/auth/login.ts" };
  const ts1     = "2026-11-24T00:00:00.000Z";
  const ts2     = "2026-11-24T00:01:00.000Z";

  // Build entries using the real auditEntryHash so they recompute correctly.
  const h1 = auditEntryHash(null, "scan.created", actor, payload, ts1);
  const h2 = auditEntryHash(h1,   "attestation",  actor, payload, ts2);

  const e1: ChainRow = { id: 1, event_type: "scan.created", actor_email: actor, payload, prev_hash: null, entry_hash: h1, created_at: ts1 };
  const e2: ChainRow = { id: 2, event_type: "attestation",  actor_email: actor, payload, prev_hash: h1,   entry_hash: h2, created_at: ts2 };

  // Intact chain is valid.
  expect(checkAuditChain([e1, e2]).valid).toBe(true);

  // Tamper e2's prev_hash → missing_link.
  const broken: ChainRow = { ...e2, prev_hash: "00000000000000000000000000000000" };
  const result = checkAuditChain([e1, broken]);
  expect(result.valid).toBe(false);
  expect(result.reason).toBe("missing_link");
});
