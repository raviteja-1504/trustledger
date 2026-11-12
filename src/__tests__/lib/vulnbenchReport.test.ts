/**
 * @jest-environment node
 *
 * The published VulnBench 2.0 result: the headline numbers are derived from the per-vulnerability rows (so the page cannot claim
 * more than its own proof list shows), and the proof list is the benchmark's reference set (108 vulnerabilities, 14 types).
 */
import { VULNBENCH as V } from "@/lib/vulnbenchReport";

describe("VulnBench 2.0 report", () => {
  it("lists the benchmark's 108 reference vulnerabilities across 20 applications, with the published per-type counts", () => {
    expect(V.reference).toBe(108);
    expect(V.rows).toHaveLength(108);
    expect(new Set(V.rows.map(r => r.app)).size).toBe(20);
    expect(new Set(V.rows.map(r => r.id)).size).toBe(108);
    const count = (t: string) => V.rows.filter(r => r.type === t).length;
    expect(Object.fromEntries(V.byType.map(t => [t.type, t.total]))).toEqual({
      xss: 19, "path-traversal": 16, "command-injection": 13, "sql-injection": 13, "open-redirect": 11, ssrf: 9, "prototype-pollution": 6,
      "insecure-deserialization": 5, "template-injection": 4, "code-injection": 4, redos: 3, "mass-assignment": 2, "improper-type-validation": 2, idor: 1,
    });
    for (const t of V.byType) expect(count(t.type)).toBe(t.total);
  });

  it("the headline and per-type figures are exactly what the rows say", () => {
    const matched = V.rows.filter(r => r.headline).length;
    expect(V.headline.matched).toBe(matched);
    expect(V.headline.recall).toBeCloseTo(matched / 108, 3);
    expect(V.lenient.matched).toBe(V.rows.filter(r => r.lenient).length);
    for (const t of V.byType) {
      expect(t.headline).toBe(V.rows.filter(r => r.type === t.type && r.headline).length);
      expect(t.lenient).toBe(V.rows.filter(r => r.type === t.type && r.lenient).length);
    }
    expect(V.byType.reduce((s, t) => s + t.headline, 0)).toBe(matched);
    // macro recall: each of the 20 applications weighs the same
    const apps = new Set(V.rows.map(r => r.app));
    const macro = [...apps].reduce((s, a) => { const rs = V.rows.filter(r => r.app === a); return s + rs.filter(r => r.headline).length / rs.length; }, 0) / apps.size;
    expect(V.headline.macroRecall).toBeCloseTo(macro, 3);
    expect(V.perApp.reduce((s, a) => s + a.total, 0)).toBe(108);
  });

  it("the looser rule never matches less than the headline rule, and every match names the finding that earned it", () => {
    for (const r of V.rows) {
      if (r.headline) expect(r.lenient).toBe(true);
      expect(r.foundBy !== null).toBe(r.lenient);
      if (r.foundBy) { expect(r.foundBy.rule).toBeTruthy(); expect(r.foundBy.file).toBeTruthy(); expect(r.foundBy.line).toBeGreaterThan(0); }
      expect(r.reference.length).toBeGreaterThan(0);
    }
    expect(V.lenient.matched).toBeGreaterThanOrEqual(V.headline.matched);
  });

  it("precision is a lower bound computed from reported findings, and the published comparison rows carry their source", () => {
    expect(V.reportedFindings).toBeGreaterThanOrEqual(V.headline.matched);
    expect(V.precisionLowerBound).toBeCloseTo(V.headline.matched / V.reportedFindings, 3);
    expect(V.published.source).toBe("https://vulnbench.com/releases/2.0");
    for (const p of V.published.rows) expect(Math.abs(p.recall - p.matched / 108)).toBeLessThan(0.02);   // macro vs pooled differ slightly
    expect(V.benchmark.repoCommit).toMatch(/^[0-9a-f]{40}$/);
  });

  it("the misses are published, not hidden", () => {
    const missed = V.rows.filter(r => !r.headline);
    expect(missed.length).toBe(108 - V.headline.matched);
    expect(missed.every(r => r.foundBy === null || r.lenient)).toBe(true);
  });
});
