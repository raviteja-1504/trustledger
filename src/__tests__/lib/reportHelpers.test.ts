/**
 * Tests for deterministic report helper functions.
 * These are pure functions — no React, no browser APIs.
 */

// ── Replicate helpers from reports/page.tsx ────────────────────────────────

function hashStr(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
  return h >>> 0;
}

function reportId(fw: string, start: string): string {
  const h = hashStr(fw + start).toString(16).toUpperCase().padStart(8, "0");
  return `TL-${h.slice(0, 8)}`;
}

function fingerprint(fw: string, org: string, start: string): string {
  const parts = [fw+org, org+start, fw+start+org, fw+org+start+"x", start+org+fw]
    .map(s => hashStr(s).toString(16).toUpperCase().padStart(8, "0"));
  const flat = parts.join("").slice(0, 40);
  return (flat.match(/.{4}/g) ?? []).join(" ");
}

function sha256hex(fw: string, org: string, start: string, end: string): string {
  const seed = fw + org + start + end;
  return [seed, seed+"a", seed+"b", seed+"c"]
    .map(s => hashStr(s).toString(16).toUpperCase().padStart(8, "0"))
    .join("");
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("hashStr", () => {
  it("returns a positive 32-bit integer", () => {
    expect(hashStr("hello")).toBeGreaterThanOrEqual(0);
    expect(hashStr("hello")).toBeLessThan(2 ** 32);
  });

  it("is deterministic — same input same output", () => {
    expect(hashStr("TrustLedger")).toBe(hashStr("TrustLedger"));
  });

  it("produces different output for different inputs", () => {
    expect(hashStr("abc")).not.toBe(hashStr("xyz"));
  });

  it("handles empty string without throwing", () => {
    expect(() => hashStr("")).not.toThrow();
  });
});

describe("reportId", () => {
  it("starts with TL-", () => {
    expect(reportId("SOC2", "2026-04-01")).toMatch(/^TL-/);
  });

  it("is deterministic", () => {
    expect(reportId("SOC2", "2026-04-01")).toBe(reportId("SOC2", "2026-04-01"));
  });

  it("differs for different frameworks", () => {
    expect(reportId("SOC2", "2026-04-01")).not.toBe(reportId("PCI-DSS", "2026-04-01"));
  });

  it("differs for different dates", () => {
    expect(reportId("SOC2", "2026-04-01")).not.toBe(reportId("SOC2", "2026-05-01"));
  });

  it("is exactly 11 characters (TL-XXXXXXXX)", () => {
    expect(reportId("SOC2", "2026-04-01")).toHaveLength(11);
  });
});

describe("fingerprint", () => {
  it("returns 10 groups of 4 hex chars separated by spaces", () => {
    const fp = fingerprint("SOC2", "novapay", "2026-04-01");
    const groups = fp.split(" ");
    expect(groups).toHaveLength(10);
    groups.forEach(g => expect(g).toMatch(/^[0-9A-F]{4}$/));
  });

  it("is deterministic", () => {
    expect(fingerprint("SOC2", "novapay", "2026-04-01"))
      .toBe(fingerprint("SOC2", "novapay", "2026-04-01"));
  });

  it("changes when org changes", () => {
    expect(fingerprint("SOC2", "novapay", "2026-04-01"))
      .not.toBe(fingerprint("SOC2", "othercorp", "2026-04-01"));
  });
});

describe("sha256hex", () => {
  it("returns a 32-character hex string", () => {
    const hex = sha256hex("SOC2", "novapay", "2026-04-01", "2026-05-01");
    expect(hex).toHaveLength(32);
    expect(hex).toMatch(/^[0-9A-F]+$/);
  });

  it("is deterministic", () => {
    expect(sha256hex("SOC2", "novapay", "2026-04-01", "2026-05-01"))
      .toBe(sha256hex("SOC2", "novapay", "2026-04-01", "2026-05-01"));
  });

  it("changes when any parameter changes", () => {
    const base = sha256hex("SOC2",    "novapay", "2026-04-01", "2026-05-01");
    expect(sha256hex("PCI-DSS", "novapay", "2026-04-01", "2026-05-01")).not.toBe(base);
    expect(sha256hex("SOC2",    "other",   "2026-04-01", "2026-05-01")).not.toBe(base);
    expect(sha256hex("SOC2",    "novapay", "2026-03-01", "2026-05-01")).not.toBe(base);
    expect(sha256hex("SOC2",    "novapay", "2026-04-01", "2026-06-01")).not.toBe(base);
  });
});
