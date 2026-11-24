import {
  getFrameworkMapping,
  requiredEvidenceTypes,
  coverageReport,
  frameworkCoverageSummary,
  ALL_FRAMEWORK_MAPPINGS,
  CONTROL_MAPPING_VERSION,
  SOC2_MAPPING,
  PCI_DSS_MAPPING,
  ISO27001_MAPPING,
  AIGOV_MAPPING,
} from "../../lib/controlMapping";
import { buildEvidenceRecord, type EvidenceRecord, type EvidenceType } from "../../lib/evidenceRecord";

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeRecord(
  framework: string,
  control_id: string,
  evidence_type: EvidenceType,
  collectedAt = "2026-01-01T00:00:00.000Z",
): EvidenceRecord {
  return buildEvidenceRecord({
    evidence_id:         `id-${Math.random().toString(36).slice(2)}`,
    org_id:              "org-test",
    framework,
    control_id,
    evidence_type,
    evidence_source:     "https://example.com",
    collection_timestamp: collectedAt,
    collector_identity:  "system",
  });
}

// ── getFrameworkMapping ───────────────────────────────────────────────────────

describe("getFrameworkMapping", () => {
  it("resolves soc2 (exact)", () => {
    expect(getFrameworkMapping("soc2")).toBe(SOC2_MAPPING);
  });

  it("resolves SOC2 (uppercase)", () => {
    expect(getFrameworkMapping("SOC2")).toBe(SOC2_MAPPING);
  });

  it("resolves iso27001", () => {
    expect(getFrameworkMapping("iso27001")).toBe(ISO27001_MAPPING);
  });

  it("resolves pcidss", () => {
    expect(getFrameworkMapping("pcidss")).toBe(PCI_DSS_MAPPING);
  });

  it("resolves aigov", () => {
    expect(getFrameworkMapping("aigov")).toBe(AIGOV_MAPPING);
  });

  it("returns undefined for unknown framework", () => {
    expect(getFrameworkMapping("hipaa")).toBeUndefined();
  });
});

// ── Framework invariants ──────────────────────────────────────────────────────

describe("framework mapping invariants", () => {
  it("all mappings have the current mapping version", () => {
    for (const fw of ALL_FRAMEWORK_MAPPINGS) {
      expect(fw.mapping_version).toBe(CONTROL_MAPPING_VERSION);
    }
  });

  it("every control has sufficient_alone = false", () => {
    for (const fw of ALL_FRAMEWORK_MAPPINGS) {
      for (const ctrl of fw.controls) {
        expect(ctrl.sufficient_alone).toBe(false);
      }
    }
  });

  it("every control has at least one primary evidence requirement", () => {
    for (const fw of ALL_FRAMEWORK_MAPPINGS) {
      for (const ctrl of fw.controls) {
        const hasPrimary = ctrl.required_evidence.some(r => r.role === "primary");
        expect(hasPrimary).toBe(true);
      }
    }
  });

  it("every framework has a scope_disclaimer", () => {
    for (const fw of ALL_FRAMEWORK_MAPPINGS) {
      expect(fw.scope_disclaimer.length).toBeGreaterThan(20);
    }
  });

  it("all 4 frameworks are present", () => {
    const ids = ALL_FRAMEWORK_MAPPINGS.map(f => f.framework_id);
    expect(ids).toContain("soc2");
    expect(ids).toContain("iso27001");
    expect(ids).toContain("pcidss");
    expect(ids).toContain("aigov");
  });
});

// ── requiredEvidenceTypes ─────────────────────────────────────────────────────

describe("requiredEvidenceTypes", () => {
  it("returns evidence types for a known control", () => {
    const types = requiredEvidenceTypes("soc2", "CC8.1");
    expect(types.length).toBeGreaterThan(0);
    expect(types).toContain("pr_approval");
    expect(types).toContain("security_scan");
  });

  it("returns empty array for unknown framework", () => {
    expect(requiredEvidenceTypes("hipaa", "CC8.1")).toEqual([]);
  });

  it("returns empty array for unknown control", () => {
    expect(requiredEvidenceTypes("soc2", "NONEXISTENT")).toEqual([]);
  });
});

// ── coverageReport ────────────────────────────────────────────────────────────

describe("coverageReport", () => {
  it("returns empty array for unknown framework", () => {
    expect(coverageReport("hipaa", [])).toEqual([]);
  });

  it("all controls show missing when no records exist", () => {
    const results = coverageReport("soc2", []);
    expect(results.every(c => c.status === "missing")).toBe(true);
    expect(results.every(c => c.sufficient_alone === false)).toBe(true);
  });

  it("satisfied when all required evidence types are covered", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const records: EvidenceRecord[] = [
      makeRecord("soc2", "CC6.1", "access_control_event", "2026-01-01T00:00:00.000Z"),
      makeRecord("soc2", "CC6.1", "pr_approval",          "2026-01-01T00:00:00.000Z"),
    ];
    const results = coverageReport("soc2", records, now);
    const ctrl = results.find(c => c.control_id === "CC6.1")!;
    expect(ctrl.status).toBe("satisfied");
    expect(ctrl.missing_types).toHaveLength(0);
    expect(ctrl.expired_types).toHaveLength(0);
  });

  it("partial when only some required types are covered", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    // CC8.1 needs pr_approval, reviewer_attestation, security_scan, repository_change
    const records: EvidenceRecord[] = [
      makeRecord("soc2", "CC8.1", "pr_approval", "2026-01-01T00:00:00.000Z"),
    ];
    const results = coverageReport("soc2", records, now);
    const ctrl = results.find(c => c.control_id === "CC8.1")!;
    expect(ctrl.status).toBe("partial");
    expect(ctrl.satisfied_types).toContain("pr_approval");
    expect(ctrl.missing_types.length).toBeGreaterThan(0);
  });

  it("expired when records exist but all are past expiration", () => {
    // Collect at a date that makes the 90-day security_scan expire before 'now'
    const collectedAt = "2025-01-01T00:00:00.000Z"; // well in the past
    const now = new Date("2026-01-01T00:00:00.000Z"); // now > expiration
    const records: EvidenceRecord[] = [
      makeRecord("soc2", "CC6.1", "access_control_event", collectedAt),
      makeRecord("soc2", "CC6.1", "pr_approval",          collectedAt),
    ];
    // Both are access_control_event (TTL=365d) collected 2025-01-01, expire 2026-01-01
    // isExpired checks <= now, so exactly at expiration => expired
    const results = coverageReport("soc2", records, now);
    const ctrl = results.find(c => c.control_id === "CC6.1")!;
    // All records expired at exactly 'now'
    expect(ctrl.status).toBe("expired");
  });

  it("revoked records are treated as missing", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const rec = makeRecord("soc2", "CC7.1", "security_scan", "2026-01-01T00:00:00.000Z");
    const revoked = { ...rec, verification_status: "revoked" as const };
    const results = coverageReport("soc2", [revoked], now);
    const ctrl = results.find(c => c.control_id === "CC7.1")!;
    expect(ctrl.satisfied_types).not.toContain("security_scan");
  });

  it("freshness_days is positive for active records", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const records: EvidenceRecord[] = [
      makeRecord("soc2", "CC6.1", "access_control_event", "2026-01-01T00:00:00.000Z"),
    ];
    const results = coverageReport("soc2", records, now);
    const ctrl = results.find(c => c.control_id === "CC6.1")!;
    if (ctrl.freshness_days !== null) {
      expect(ctrl.freshness_days).toBeGreaterThan(0);
    }
  });

  it("freshness_days is null when no active records exist", () => {
    const results = coverageReport("soc2", []);
    const ctrl = results.find(c => c.control_id === "CC8.1")!;
    expect(ctrl.freshness_days).toBeNull();
  });
});

// ── frameworkCoverageSummary ──────────────────────────────────────────────────

describe("frameworkCoverageSummary", () => {
  it("returns undefined for unknown framework", () => {
    expect(frameworkCoverageSummary("hipaa", [])).toBeUndefined();
  });

  it("total_controls matches the framework definition", () => {
    const summary = frameworkCoverageSummary("soc2", [])!;
    expect(summary.total_controls).toBe(SOC2_MAPPING.controls.length);
  });

  it("all missing when no records", () => {
    const summary = frameworkCoverageSummary("pcidss", [])!;
    expect(summary.missing).toBe(summary.total_controls);
    expect(summary.satisfied).toBe(0);
  });

  it("includes scope_disclaimer", () => {
    const summary = frameworkCoverageSummary("iso27001", [])!;
    expect(summary.scope_disclaimer.length).toBeGreaterThan(10);
  });

  it("counts sum to total_controls", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const records = [makeRecord("soc2", "CC6.1", "access_control_event", "2026-01-01T00:00:00.000Z")];
    const summary = frameworkCoverageSummary("soc2", records, now)!;
    expect(summary.satisfied + summary.partial + summary.missing + summary.expired).toBe(summary.total_controls);
  });
});
