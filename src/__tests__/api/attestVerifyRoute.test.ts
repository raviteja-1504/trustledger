/**
 * @jest-environment node
 *
 * GET /api/attest/verify — inherited attestation verification scenarios (task 5).
 * Direct (non-inherited) path is covered here too as a baseline.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { generateSigningKeyPair, signCanonicalPayload, canonicalPayloadBytes } from "@/lib/attestationSigning";
import type { CanonicalAttestationPayload } from "@/lib/attestationSigning";
import crypto from "crypto";

// ── Key pair for tests ────────────────────────────────────────────────────────
const { privateKeyPem, publicKeyPem } = generateSigningKeyPair();
const KEY_ID = "key-0000-0000-0000-0000-000000000001";
const ORG    = "aabbccdd-aabb-4aab-8aab-aabbccddaabb";
const SCAN_A = "11111111-1111-4111-8111-111111111111"; // source scan
const SCAN_B = "22222222-2222-4222-8222-222222222222"; // inheriting scan
const ATT_SRC = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ATT_INH = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const FILE    = "src/lib/db.ts";
const HASH_A  = "deadbeef".repeat(8); // 64-hex content hash

function makePayload(overrides: Partial<CanonicalAttestationPayload> = {}): CanonicalAttestationPayload {
  return {
    schema_version:  1,
    reviewer_email:  "rev@example.com",
    reviewer_id:     "u1",
    org_id:          ORG,
    repo:            "acme/api",
    commit_sha:      "a".repeat(40),
    file_path:       FILE,
    content_hash:    HASH_A,
    scan_id:         SCAN_A,
    findings_digest: crypto.createHash("sha256").update("[]").digest("hex"),
    decision:        "attested",
    policy_version:  "v1:abc123",
    timestamp:       "2026-11-25T00:00:00.000Z",
    key_id:          KEY_ID,
    ...overrides,
  };
}

// ── DB setup helpers ──────────────────────────────────────────────────────────
let db: ReturnType<typeof fakeSupabase>;
const auth = { org_id: ORG, role: "admin", user_id: "u1" };

jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => auth }));

import { GET } from "@/app/api/attest/verify/route";

const get = async (id: string) => {
  const res = await GET(new NextRequest(new URL(`/api/attest/verify?id=${id}`, "https://app.example")));
  return { status: res.status, body: await res.json() as Record<string, unknown> };
};

function seedDb(opts: {
  srcPayload?: CanonicalAttestationPayload;
  srcSignature?: string | null;
  srcScanFile?: { content_hash: string | null } | null;
  inhScanFile?: { content_hash: string | null } | null;
  includeSource?: boolean;
}) {
  const {
    srcPayload   = makePayload(),
    srcSignature = signCanonicalPayload(srcPayload, privateKeyPem),
    srcScanFile  = { content_hash: HASH_A },
    inhScanFile  = { content_hash: HASH_A },
    includeSource = true,
  } = opts;

  const srcAtt = {
    id:             ATT_SRC,
    org_id:         ORG,
    scan_id:        SCAN_A,
    file_path:      FILE,
    reviewer_email: "rev@example.com",
    payload_hash:   crypto.createHash("sha256").update(canonicalPayloadBytes(srcPayload)).digest("hex"),
    payload_json:   srcPayload,
    signature:      srcSignature,
    signing_key_id: KEY_ID,
    created_at:     "2026-11-25T00:00:00.000Z",
  };

  const inhAtt = {
    id:             ATT_INH,
    org_id:         ORG,
    scan_id:        SCAN_B,
    file_path:      FILE,
    reviewer_email: "rev@example.com",
    payload_hash:   `inherited:${ATT_SRC}`,
    payload_json:   null,
    signature:      null,
    signing_key_id: null,
    created_at:     "2026-11-25T01:00:00.000Z",
  };

  db = fakeSupabase({
    attestations: includeSource ? [srcAtt, inhAtt] : [inhAtt],
    scan_files: [
      ...(srcScanFile  ? [{ scan_id: SCAN_A, file_path: FILE, ...srcScanFile }] : []),
      ...(inhScanFile  ? [{ scan_id: SCAN_B, file_path: FILE, ...inhScanFile }] : []),
    ],
    scans: [
      { id: SCAN_A, org_id: ORG, repo_full_name: "acme/api", commit_sha: "a".repeat(40) },
      { id: SCAN_B, org_id: ORG, repo_full_name: "acme/api", commit_sha: "b".repeat(40) },
    ],
    signing_keys: [{ id: KEY_ID, org_id: null, public_key_pem: publicKeyPem, status: "active" }],
  });
}

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/attest/verify — direct attestation baseline", () => {
  it("valid signature on a direct attestation returns verify_result=valid and is_inherited=false", async () => {
    const payload = makePayload();
    const signature = signCanonicalPayload(payload, privateKeyPem);
    db = fakeSupabase({
      attestations: [{
        id: ATT_SRC, org_id: ORG, scan_id: SCAN_A, file_path: FILE,
        reviewer_email: "rev@example.com",
        payload_hash: "h",
        payload_json:   payload,
        signature,
        signing_key_id: KEY_ID,
        created_at: "2026-11-25T00:00:00.000Z",
      }],
      scan_files: [{ scan_id: SCAN_A, file_path: FILE, content_hash: HASH_A }],
      scans: [{ id: SCAN_A, org_id: ORG, repo_full_name: "acme/api", commit_sha: "a".repeat(40) }],
      signing_keys: [{ id: KEY_ID, org_id: null, public_key_pem: publicKeyPem, status: "active" }],
    });

    const { status, body } = await get(ATT_SRC);
    expect(status).toBe(200);
    expect(body.verify_result).toBe("valid");
    expect(body.is_inherited).toBe(false);
    expect(body.has_signature).toBe(true);
  });

  it("404 when attestation not found", async () => {
    db = fakeSupabase({ attestations: [], scans: [], scan_files: [], signing_keys: [] });
    const { status } = await get(ATT_SRC);
    expect(status).toBe(404);
  });
});

describe("GET /api/attest/verify — inherited attestation", () => {
  it("valid inherited attestation: same content hash → verify_result=valid, is_inherited=true", async () => {
    seedDb({});
    const { status, body } = await get(ATT_INH);
    expect(status).toBe(200);
    expect(body.verify_result).toBe("valid");
    expect(body.is_inherited).toBe(true);
    expect(body.source_attestation_id).toBe(ATT_SRC);
    expect(body.has_signature).toBe(false);
  });

  it("source attestation deleted → verify_result=inherited_source_not_found", async () => {
    seedDb({ includeSource: false });
    const { status, body } = await get(ATT_INH);
    expect(status).toBe(200);
    expect(body.verify_result).toBe("inherited_source_not_found");
    expect(body.is_inherited).toBe(true);
  });

  it("content hash changed in inheriting scan → verify_result=inherited_content_changed", async () => {
    seedDb({ inhScanFile: { content_hash: "deadbeef".repeat(7) + "00000000" } }); // different hash
    const { status, body } = await get(ATT_INH);
    expect(status).toBe(200);
    expect(body.verify_result).toBe("inherited_content_changed");
    expect(body.is_inherited).toBe(true);
    expect(body.source_attestation_id).toBe(ATT_SRC);
  });

  it("content hash null in inheriting scan → verify_result=inherited_content_changed", async () => {
    seedDb({ inhScanFile: { content_hash: null } });
    const { status, body } = await get(ATT_INH);
    expect(status).toBe(200);
    expect(body.verify_result).toBe("inherited_content_changed");
  });

  it("content hash null in source scan → verify_result=inherited_content_changed", async () => {
    seedDb({ srcScanFile: { content_hash: null } });
    const { status, body } = await get(ATT_INH);
    expect(status).toBe(200);
    expect(body.verify_result).toBe("inherited_content_changed");
  });

  it("source attestation's signature is invalid → propagates 'invalid'", async () => {
    const payload = makePayload();
    // Sign with a different key — wrong signature
    const { privateKeyPem: wrongKey } = generateSigningKeyPair();
    const badSig = signCanonicalPayload(payload, wrongKey);
    seedDb({ srcPayload: payload, srcSignature: badSig });
    const { status, body } = await get(ATT_INH);
    expect(status).toBe(200);
    expect(body.verify_result).toBe("invalid");
    expect(body.is_inherited).toBe(true);
  });

  it("source attestation has no signature → propagates 'no_signature'", async () => {
    const payload = makePayload();
    seedDb({ srcPayload: payload, srcSignature: null });
    const { status, body } = await get(ATT_INH);
    expect(status).toBe(200);
    expect(body.verify_result).toBe("no_signature");
    expect(body.is_inherited).toBe(true);
  });
});
