/**
 * @jest-environment node
 */

import {
  buildEvidenceRecord,
  canonicalPayload,
  computeContentHash,
  computeExpirationDate,
  daysUntilExpiry,
  evidenceRecordToRow,
  freshnessLabel,
  isExpired,
  markExpired,
  markRevoked,
  markVerified,
  rowToEvidenceRecord,
  verifyRecord,
  EVIDENCE_TTL_DAYS,
  type EvidenceRecord,
  type EvidenceType,
} from "../../lib/evidenceRecord";

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeRecord(overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  const base = buildEvidenceRecord({
    evidence_id:         "00000000-0000-0000-0000-000000000001",
    org_id:              "org-test",
    framework:           "soc2",
    control_id:          "CC8.1",
    evidence_type:       "security_scan",
    evidence_source:     "https://example.com/scan/1",
    collection_timestamp: "2026-01-01T00:00:00.000Z",
    collector_identity:  "user-abc",
  });
  return { ...base, ...overrides };
}

// ── computeContentHash ────────────────────────────────────────────────────────

describe("computeContentHash", () => {
  it("returns a 64-char hex string", () => {
    const h = computeContentHash("hello world");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic", () => {
    expect(computeContentHash("abc")).toBe(computeContentHash("abc"));
  });

  it("changes when content changes", () => {
    expect(computeContentHash("abc")).not.toBe(computeContentHash("abd"));
  });
});

// ── canonicalPayload ──────────────────────────────────────────────────────────

describe("canonicalPayload", () => {
  it("produces valid JSON", () => {
    const record = makeRecord();
    expect(() => JSON.parse(canonicalPayload(record))).not.toThrow();
  });

  it("includes all stable identity fields", () => {
    const record = makeRecord();
    const parsed = JSON.parse(canonicalPayload(record));
    expect(parsed.evidence_id).toBeDefined();
    expect(parsed.org_id).toBeDefined();
    expect(parsed.framework).toBeDefined();
    expect(parsed.control_id).toBeDefined();
    expect(parsed.evidence_type).toBeDefined();
    expect(parsed.collection_timestamp).toBeDefined();
  });

  it("excludes mutable fields (verification_status, note)", () => {
    const record = makeRecord({ verification_status: "revoked", note: "test note" });
    const parsed = JSON.parse(canonicalPayload(record));
    expect(parsed.verification_status).toBeUndefined();
    expect(parsed.note).toBeUndefined();
  });

  it("keys are sorted alphabetically", () => {
    const record = makeRecord();
    const parsed = JSON.parse(canonicalPayload(record));
    const keys = Object.keys(parsed);
    expect(keys).toEqual([...keys].sort());
  });
});

// ── buildEvidenceRecord ───────────────────────────────────────────────────────

describe("buildEvidenceRecord", () => {
  it("sets verification_status to pending_verification", () => {
    expect(makeRecord().verification_status).toBe("pending_verification");
  });

  it("computes a non-empty content_hash", () => {
    expect(makeRecord().content_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("computes expiration_date from TTL", () => {
    const record = makeRecord();
    const ttl = EVIDENCE_TTL_DAYS["security_scan"];
    const collected = new Date("2026-01-01T00:00:00.000Z");
    const expected = new Date(collected);
    expected.setUTCDate(expected.getUTCDate() + ttl);
    expect(record.expiration_date).toBe(expected.toISOString());
  });

  it("includes optional fields when provided", () => {
    const record = buildEvidenceRecord({
      evidence_id: "id1", org_id: "o1", framework: "soc2", control_id: "CC8.1",
      evidence_type: "security_scan", evidence_source: "https://x.com",
      collection_timestamp: "2026-01-01T00:00:00.000Z",
      collector_identity: "u1",
      repository_id: "repo-1", commit_sha: "abc123", scan_id: "scan-1",
    });
    expect(record.repository_id).toBe("repo-1");
    expect(record.commit_sha).toBe("abc123");
    expect(record.scan_id).toBe("scan-1");
  });
});

// ── computeExpirationDate ─────────────────────────────────────────────────────

describe("computeExpirationDate", () => {
  it("adds the correct TTL days", () => {
    const base = new Date("2026-01-01T00:00:00.000Z");
    const exp = computeExpirationDate("pr_approval", base);
    expect(exp.getUTCFullYear()).toBe(2027);
    expect(exp.getUTCDate()).toBe(1);
  });

  it("security_scan expires in 90 days", () => {
    const base = new Date("2026-01-01T00:00:00.000Z");
    const exp = computeExpirationDate("security_scan", base);
    const diff = Math.round((exp.getTime() - base.getTime()) / 86_400_000);
    expect(diff).toBe(90);
  });
});

// ── isExpired / daysUntilExpiry ───────────────────────────────────────────────

describe("isExpired", () => {
  it("returns false when now is before expiration", () => {
    const record = makeRecord();
    const before = new Date(record.expiration_date);
    before.setUTCDate(before.getUTCDate() - 1);
    expect(isExpired(record, before)).toBe(false);
  });

  it("returns true when now equals expiration", () => {
    const record = makeRecord();
    expect(isExpired(record, new Date(record.expiration_date))).toBe(true);
  });

  it("returns true when now is after expiration", () => {
    const record = makeRecord();
    const after = new Date(record.expiration_date);
    after.setUTCDate(after.getUTCDate() + 1);
    expect(isExpired(record, after)).toBe(true);
  });
});

describe("daysUntilExpiry", () => {
  it("returns positive days for a fresh record", () => {
    const record = makeRecord();
    const now = new Date("2026-01-01T00:00:00.000Z");  // collection date
    const days = daysUntilExpiry(record, now);
    expect(days).toBe(EVIDENCE_TTL_DAYS["security_scan"]);
  });

  it("returns negative days for an expired record", () => {
    const record = makeRecord();
    const after = new Date(record.expiration_date);
    after.setUTCDate(after.getUTCDate() + 10);
    expect(daysUntilExpiry(record, after)).toBeLessThan(0);
  });
});

// ── verifyRecord / markVerified ───────────────────────────────────────────────

describe("verifyRecord", () => {
  it("returns true when payload matches the content hash", () => {
    const record = makeRecord();
    expect(verifyRecord(record, canonicalPayload(record))).toBe(true);
  });

  it("returns false when payload does not match", () => {
    const record = makeRecord();
    expect(verifyRecord(record, "tampered")).toBe(false);
  });
});

describe("markVerified", () => {
  it("sets status to verified for a non-expired record", () => {
    const record = makeRecord();
    const now = new Date("2026-01-01T00:00:00.000Z");
    const updated = markVerified(record, now);
    expect(updated.verification_status).toBe("verified");
  });

  it("sets status to expired for an already-expired record", () => {
    const record = makeRecord();
    const after = new Date(record.expiration_date);
    after.setUTCDate(after.getUTCDate() + 1);
    const updated = markVerified(record, after);
    expect(updated.verification_status).toBe("expired");
  });

  it("does not mutate the original", () => {
    const record = makeRecord();
    const now = new Date("2026-01-01T00:00:00.000Z");
    markVerified(record, now);
    expect(record.verification_status).toBe("pending_verification");
  });
});

// ── markExpired / markRevoked ─────────────────────────────────────────────────

describe("markExpired", () => {
  it("sets status to expired", () => {
    const updated = markExpired(makeRecord());
    expect(updated.verification_status).toBe("expired");
  });
});

describe("markRevoked", () => {
  it("sets status to revoked and stores reason in note", () => {
    const updated = markRevoked(makeRecord(), "superseded");
    expect(updated.verification_status).toBe("revoked");
    expect(updated.note).toBe("superseded");
  });
});

// ── freshnessLabel ────────────────────────────────────────────────────────────

describe("freshnessLabel", () => {
  const type: EvidenceType = "security_scan"; // TTL = 90 days

  it("fresh when > 50% TTL remains", () => {
    const record = makeRecord({ evidence_type: type });
    const now = new Date("2026-01-01T00:00:00.000Z");
    // 90 days TTL, 90 days remain at collection = fresh
    expect(freshnessLabel(record, now)).toBe("fresh");
  });

  it("aging when 10–50% TTL remains", () => {
    const record = makeRecord({ evidence_type: type });
    // Move now forward so only ~20 days remain (22% of 90)
    const now = new Date("2026-01-01T00:00:00.000Z");
    now.setUTCDate(now.getUTCDate() + 70);
    expect(freshnessLabel(record, now)).toBe("aging");
  });

  it("stale when 0–10% TTL remains", () => {
    const record = makeRecord({ evidence_type: type });
    const now = new Date("2026-01-01T00:00:00.000Z");
    now.setUTCDate(now.getUTCDate() + 86); // 4 days left ~4%
    expect(freshnessLabel(record, now)).toBe("stale");
  });

  it("expired when past expiration", () => {
    const record = makeRecord({ evidence_type: type });
    const now = new Date("2026-01-01T00:00:00.000Z");
    now.setUTCDate(now.getUTCDate() + 91);
    expect(freshnessLabel(record, now)).toBe("expired");
  });
});

// ── DB round-trip ─────────────────────────────────────────────────────────────

describe("evidenceRecordToRow / rowToEvidenceRecord round-trip", () => {
  it("round-trips a full record", () => {
    const original = buildEvidenceRecord({
      evidence_id: "id1", org_id: "o1", framework: "soc2", control_id: "CC8.1",
      evidence_type: "pr_approval", evidence_source: "https://github.com/pr/1",
      collection_timestamp: "2026-03-01T10:00:00.000Z",
      collector_identity: "user-xyz",
      repository_id: "my-repo", commit_sha: "aabbcc", scan_id: "s1",
    });

    const row = evidenceRecordToRow(original);
    const restored = rowToEvidenceRecord({ ...row, id: "id1", created_at: "2026-03-01T10:00:00.000Z" });

    expect(restored).not.toBeNull();
    expect(restored!.framework).toBe("soc2");
    expect(restored!.control_id).toBe("CC8.1");
    expect(restored!.evidence_type).toBe("pr_approval");
    expect(restored!.content_hash).toBe(original.content_hash);
    expect(restored!.expiration_date).toBe(original.expiration_date);
    expect(restored!.repository_id).toBe("my-repo");
    expect(restored!.commit_sha).toBe("aabbcc");
  });

  it("returns null for a legacy row with no v:1 payload", () => {
    const row = {
      id: "old1", org_id: "o1", framework_id: "soc2", control_id: "CC8.1",
      note: "plain text note", file_url: null,
      collected_by: null, collected_by_email: null, created_at: "2025-01-01T00:00:00.000Z",
    };
    expect(rowToEvidenceRecord(row)).toBeNull();
  });

  it("returns null for an empty note", () => {
    const row = {
      id: "old2", org_id: "o1", framework_id: "soc2", control_id: "CC8.1",
      note: "", file_url: null,
      collected_by: null, collected_by_email: null, created_at: "2025-01-01T00:00:00.000Z",
    };
    expect(rowToEvidenceRecord(row)).toBeNull();
  });
});
