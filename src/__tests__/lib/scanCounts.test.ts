import { computeScanCounts, listNewFindings, describeChanges, type CountFile, type CountIndicator } from "@/lib/scanCounts";
import type { TriageDecision } from "@/lib/findingLifecycle";

// A finding with a CWE is a security finding; anything else is a signal.
const isSecurity = (i: { id: string; label?: string; cwe?: string }) => !!i.cwe || /^sec-/.test(i.id);
const sec = (over: Partial<CountIndicator> = {}): CountIndicator => ({ id: "sec-sqli", cwe: "CWE-89", severity: "high", line: 1, ...over });
const sig = (over: Partial<CountIndicator> = {}): CountIndicator => ({ id: "ai-comment-style", severity: "low", ...over });
const file = (path: string, indicators: CountIndicator[], over: Partial<CountFile> = {}): CountFile => ({ file_path: path, risk_score: "LOW", indicators, ...over });
const accepted = (expires_at: string | null = null): TriageDecision => ({ status: "accepted", reason: "r", expires_at, set_by_email: null, set_at: "2026-01-01T00:00:00Z" });
const NOW = new Date("2026-06-01T00:00:00Z");

describe("computeScanCounts: files and findings are different units", () => {
  it("80 files can hold 160 findings: each is counted in its own unit", () => {
    const files = [
      file("a.ts", [sec(), sec({ line: 2 }), sec({ line: 3, severity: "critical" })], { risk_score: "CRITICAL" }),
      file("b.ts", [sec()], { risk_score: "HIGH" }),
      file("c.ts", [], { risk_score: "LOW" }),
    ];
    const c = computeScanCounts(files, { isSecurity, now: NOW });
    expect(c.files).toEqual({ scanned: 3, toReview: 2, signedOff: 0, withFindings: 2 });
    expect(c.security.total).toBe(4);
    expect(c.security.bySeverity).toEqual({ critical: 1, high: 3, medium: 0, low: 0 });
  });

  it("signed off counts only HIGH/CRITICAL files, from the file's flag or this session's set", () => {
    const files = [
      file("a.ts", [], { risk_score: "HIGH", attested: true }),
      file("b.ts", [], { risk_score: "CRITICAL" }),
      file("c.ts", [], { risk_score: "LOW", attested: true }),      // attested but not a review file: not counted
    ];
    expect(computeScanCounts(files, { isSecurity }).files.signedOff).toBe(1);
    expect(computeScanCounts(files, { isSecurity, attestedPaths: new Set(["b.ts"]) }).files.signedOff).toBe(2);
  });

  it("non-security indicators are reported apart and never added into the finding total", () => {
    const c = computeScanCounts([file("a.ts", [sec(), sig(), sig({ id: "other-signal" })])], { isSecurity });
    expect(c.security.total).toBe(1);
    expect(c.otherSignals).toBe(2);
  });

  it("severity buckets: unknown / info severities count as low", () => {
    const c = computeScanCounts([file("a.ts", [sec({ severity: "info" }), sec({ severity: "weird" }), sec({ severity: "medium" })])], { isSecurity });
    expect(c.security.bySeverity).toEqual({ critical: 0, high: 0, medium: 1, low: 2 });
  });

  it("indicators missing from a file (null) are fine", () => {
    expect(computeScanCounts([{ file_path: "a", indicators: null }], { isSecurity }).security.total).toBe(0);
  });
});

describe("computeScanCounts: introduced vs already there", () => {
  it("splits the findings whose origin is known", () => {
    const c = computeScanCounts([file("a.ts", [sec({ introduced: true }), sec({ introduced: true }), sec({ introduced: false })])], { isSecurity });
    expect(c.security.introduced).toBe(2);
    expect(c.security.preexisting).toBe(1);
  });
  it("is null (not 0) when no finding has diff information", () => {
    const c = computeScanCounts([file("a.ts", [sec(), sec()])], { isSecurity });
    expect(c.security.introduced).toBeNull();
    expect(c.security.preexisting).toBeNull();
  });
  it("findings of unknown origin are in neither side", () => {
    const c = computeScanCounts([file("a.ts", [sec({ introduced: true }), sec()])], { isSecurity });
    expect(c.security.total).toBe(2);
    expect(c.security.introduced).toBe(1);
    expect(c.security.preexisting).toBe(0);
  });
});

describe("computeScanCounts: triage decisions", () => {
  it("an active decision suppresses; an expired one does not", () => {
    const c = computeScanCounts([file("a.ts", [
      sec({ triage: accepted(null) }),
      sec({ triage: accepted("2027-01-01T00:00:00Z") }),
      sec({ triage: accepted("2026-01-01T00:00:00Z") }),            // expired before NOW
      sec(),
    ])], { isSecurity, now: NOW });
    expect(c.security.suppressed).toBe(2);
    expect(c.security.open).toBe(2);
    expect(c.security.total).toBe(4);
  });
});

describe("computeScanCounts: changes since the previous scan", () => {
  const lifecycle = (over = {}) => ({ hasPreviousScan: true, fixed: [], fixedTotal: 0, ...over });
  const files = () => [file("a.ts", [
    sec({ lifecycle_status: "new" }), sec({ lifecycle_status: "new" }),
    sec({ lifecycle_status: "existing" }),
    sec({ lifecycle_status: "reopened" }),
    sec({ lifecycle_status: "accepted" }), sec({ lifecycle_status: "false_positive" }),
    sig({ lifecycle_status: "new" }), sig({ lifecycle_status: "new" }), sig({ lifecycle_status: "new" }),   // signals: never counted here
  ])];

  it("counts security findings only: AI signals don't inflate 'new'", () => {
    const c = computeScanCounts(files(), { isSecurity, lifecycle: lifecycle() });
    expect(c.changes).toMatchObject({ new: 2, existing: 1, reopened: 1, accepted: 1, falsePositive: 1 });
  });
  it("is null for a first scan: there is nothing to compare with", () => {
    expect(computeScanCounts(files(), { isSecurity, lifecycle: lifecycle({ hasPreviousScan: false }) }).changes).toBeNull();
    expect(computeScanCounts(files(), { isSecurity }).changes).toBeNull();
  });
  it("fixed counts only security findings, and says when the API's list was capped", () => {
    const fixed = [{ id: "sec-a", label: "A" }, { id: "ai-x" }, { id: "sec-b" }];
    const exact = computeScanCounts([], { isSecurity, lifecycle: lifecycle({ fixed, fixedTotal: 3 }) }).changes!;
    expect(exact.fixed).toBe(2);
    expect(exact.fixedIsLowerBound).toBe(false);
    const capped = computeScanCounts([], { isSecurity, lifecycle: lifecycle({ fixed, fixedTotal: 500 }) }).changes!;
    expect(capped.fixedIsLowerBound).toBe(true);
  });
  it("a finding with no status is treated as existing, never as new", () => {
    expect(computeScanCounts([file("a.ts", [sec()])], { isSecurity, lifecycle: lifecycle() }).changes).toMatchObject({ new: 0, existing: 1 });
  });
});

describe("listNewFindings", () => {
  it("lists new and reopened security findings, most severe first, skipping signals and old findings", () => {
    const list = listNewFindings([
      file("b.ts", [sec({ lifecycle_status: "new", severity: "medium", line: 9 }), sec({ lifecycle_status: "existing" }), sig({ lifecycle_status: "new" })]),
      file("a.ts", [sec({ lifecycle_status: "reopened", severity: "critical", line: 3 }), sec({ lifecycle_status: "new", severity: "critical", line: 1 })]),
    ], isSecurity);
    expect(list.map(l => `${l.file}:${l.line}:${l.status}`)).toEqual(["a.ts:1:new", "a.ts:3:reopened", "b.ts:9:new"]);
  });
  it("labels through the caller's lookup", () => {
    const [l] = listNewFindings([file("a.ts", [sec({ lifecycle_status: "new", id: "sec-sqli" })])], isSecurity, i => `Title of ${i.id}`);
    expect(l.label).toBe("Title of sec-sqli");
  });
});

describe("describeChanges", () => {
  const base = { new: 0, existing: 0, reopened: 0, accepted: 0, falsePositive: 0, fixed: 0, fixedIsLowerBound: false };
  it("says plainly when nothing is new", () => {
    expect(describeChanges(base)).toEqual(["No new security findings"]);
  });
  it("explains each category in words", () => {
    const lines = describeChanges({ ...base, new: 1, existing: 4, reopened: 2, fixed: 3, accepted: 1, falsePositive: 1 });
    expect(lines).toEqual([
      "1 new security finding: not in the previous scan",
      "2 findings came back: fixed or accepted before, present again",
      "3 fixed: in the previous scan, gone now",
      "4 unchanged: already in the previous scan, still here",
      "2 findings under a triage decision (1 accepted risk, 1 false positive)",
    ]);
  });
  it("marks a capped fixed count as 'at least'", () => {
    expect(describeChanges({ ...base, fixed: 100, fixedIsLowerBound: true })).toContain("100+ fixed: in the previous scan, gone now");
  });
});
