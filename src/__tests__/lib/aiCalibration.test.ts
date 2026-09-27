import { runScan } from "@/lib/scanner";
import {
  brierScore, expectedCalibrationError, fitCalibration, MIN_CALIBRATION_SAMPLES_PER_CLASS,
  toAiProbability, validateCalibrationMap, wilsonInterval,
} from "@/lib/aiCalibration";
import type { CalibrationMap } from "@/lib/aiCalibration";

// The AI number is an EVIDENCE SCORE, not a probability. These pin the separation: the score is untouched by
// calibration; a probability is reported only when a map fitted on enough labelled data exists, with an interval;
// otherwise the result is an explicit, reasoned "uncalibrated" -- never a guess.

// Small deterministic PRNG so a "random" dataset is identical on every run and machine.
function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
/** An OVERCONFIDENT detector: reports `score`, but the real chance of AI is score^2 (so a stated 0.8 is really 0.64). */
function overconfidentSamples(n: number, seed: number) {
  const rnd = mulberry32(seed);
  return Array.from({ length: n }, () => { const score = rnd(); return { score, ai: rnd() < score * score }; });
}
const META = { source: "synthetic overconfident detector", fitted_at: "2026-01-01T00:00:00Z" };

describe("wilsonInterval", () => {
  it("is well-behaved at the extremes and with no data", () => {
    const [lo0, hi0] = wilsonInterval(0, 10);
    expect(lo0).toBe(0);
    expect(hi0).toBeGreaterThan(0);
    expect(hi0).toBeLessThan(0.4);
    const [loN, hiN] = wilsonInterval(10, 10);
    expect(hiN).toBe(1);
    expect(loN).toBeGreaterThan(0.6);
    expect(wilsonInterval(0, 0)).toEqual([0, 1]);
  });
  it("brackets the observed rate and tightens as n grows", () => {
    const small = wilsonInterval(5, 10), large = wilsonInterval(500, 1000);
    expect(small[0]).toBeLessThan(0.5); expect(small[1]).toBeGreaterThan(0.5);
    expect(large[1] - large[0]).toBeLessThan(small[1] - small[0]);
  });
});

describe("fitCalibration (isotonic regression)", () => {
  it("pools a violation: a higher score never gets a LOWER probability", () => {
    const m = fitCalibration([
      { score: 0.1, ai: false }, { score: 0.2, ai: true }, { score: 0.3, ai: false }, { score: 0.4, ai: true }, { score: 0.5, ai: true },
    ], META, { minBinSamples: 1 });   // 1: this test is about pooling VIOLATORS, not about minimum bin support
    for (let i = 1; i < m.bins.length; i++) expect(m.bins[i].p).toBeGreaterThanOrEqual(m.bins[i - 1].p);
    // 0.2 (AI) and 0.3 (human) violate monotonicity, so they must have been pooled into ONE block of 2 samples.
    expect(m.bins.some(b => b.n === 2 && b.k === 1)).toBe(true);
  });

  it("is monotone with strictly increasing lower bounds on any data (property check over many seeds)", () => {
    for (let seed = 1; seed <= 25; seed++) {
      const m = fitCalibration(overconfidentSamples(300, seed), META);
      expect(m.bins[0].lo).toBe(0);
      for (let i = 1; i < m.bins.length; i++) {
        expect(m.bins[i].lo).toBeGreaterThan(m.bins[i - 1].lo);
        expect(m.bins[i].p).toBeGreaterThanOrEqual(m.bins[i - 1].p);
      }
    }
  });

  it("puts equal scores in one bin even with mixed labels (a tie can't straddle a boundary)", () => {
    const m = fitCalibration([
      { score: 0.5, ai: true }, { score: 0.5, ai: false }, { score: 0.5, ai: true }, { score: 0.9, ai: true },
    ], META, { minBinSamples: 1 });
    const tie = m.bins.find(b => b.lo <= 0.5 && b.n >= 3)!;
    expect(tie).toBeDefined();
    expect(tie.k).toBeGreaterThanOrEqual(2);
  });

  it("never claims certainty: a perfectly separable dataset still yields probabilities strictly inside (0,1)", () => {
    const m = fitCalibration([...Array(120)].map((_, i) => ({ score: i / 300, ai: false })).concat(
      [...Array(120)].map((_, i) => ({ score: 0.6 + i / 300, ai: true }))), META);
    for (const b of m.bins) { expect(b.p).toBeGreaterThan(0); expect(b.p).toBeLessThan(1); }
    expect(m.bins[0].p).toBeLessThan(0.05);
    expect(m.bins[m.bins.length - 1].p).toBeGreaterThan(0.95);
  });

  it("every bin has real support (no bin built from a single file), so a bin's rate is not noise", () => {
    for (let seed = 1; seed <= 10; seed++) {
      const m = fitCalibration(overconfidentSamples(2000, seed), META);
      for (const b of m.bins) expect(b.n).toBeGreaterThanOrEqual(25);
    }
  });

  it("drops non-finite scores and counts classes correctly", () => {
    const m = fitCalibration([{ score: NaN, ai: true }, { score: 0.2, ai: true }, { score: 0.3, ai: false }, { score: Infinity, ai: false }], META);
    expect(m.n_ai).toBe(1);
    expect(m.n_human).toBe(1);
  });

  it("has a version tag that is stable for identical input and changes with the data", () => {
    const a = fitCalibration(overconfidentSamples(200, 7), META);
    expect(fitCalibration(overconfidentSamples(200, 7), META).version).toBe(a.version);
    expect(fitCalibration(overconfidentSamples(200, 8), META).version).not.toBe(a.version);
  });
});

describe("a fitted map is a real calibration: it beats the raw score on data it never saw", () => {
  const train = overconfidentSamples(6000, 101);
  const test = overconfidentSamples(6000, 202);
  const map = fitCalibration(train, META);

  it("the map is usable (clears the per-class sample floor)", () => {
    expect(validateCalibrationMap(map)).toEqual([]);
  });

  it("expected calibration error on HELD-OUT data drops from large (raw score) to small (calibrated)", () => {
    const raw = expectedCalibrationError(test.map(s => ({ p: s.score, ai: s.ai })));
    const cal = expectedCalibrationError(test.map(s => ({ p: toAiProbability(s.score, map).value!, ai: s.ai })));
    expect(raw).toBeGreaterThan(0.12);                 // the score is badly miscalibrated as a probability (~1/6)
    expect(cal).toBeLessThan(0.04);
    expect(cal).toBeLessThan(raw / 3);
  });

  it("Brier score on held-out data improves", () => {
    const raw = brierScore(test.map(s => ({ p: s.score, ai: s.ai })));
    const cal = brierScore(test.map(s => ({ p: toAiProbability(s.score, map).value!, ai: s.ai })));
    expect(cal).toBeLessThan(raw);
  });

  it("is monotone in the score at lookup time", () => {
    let prev = -1;
    for (let s = 0; s <= 1.0001; s += 0.01) {
      const v = toAiProbability(s, map).value!;
      expect(v).toBeGreaterThanOrEqual(prev);
      prev = v;
    }
  });

  it("reports an in-range interval and the map version it used", () => {
    const r = toAiProbability(0.7, map);
    expect(r.status).toBe("calibrated");
    expect(r.calibration_version).toBe(map.version);
    expect(r.interval![0]).toBeGreaterThanOrEqual(0);
    expect(r.interval![1]).toBeLessThanOrEqual(1);
    expect(r.interval![0]).toBeLessThanOrEqual(r.interval![1]);
  });

  it("the value and interval come from the bin the score falls in (not just any bin)", () => {
    const s = 0.55;
    const bin = [...map.bins].reverse().find(b => b.lo <= s)!;
    const r = toAiProbability(s, map);
    expect(r.value).toBe(bin.p);
    expect(r.interval).toEqual(wilsonInterval(bin.k, bin.n));
    expect(r.interval![1] - r.interval![0]).toBeGreaterThan(0);   // a real interval, not a point
  });

  it("clamps out-of-range scores instead of extrapolating", () => {
    expect(toAiProbability(-3, map).value).toBe(toAiProbability(0, map).value);
    expect(toAiProbability(9, map).value).toBe(toAiProbability(1, map).value);
  });
});

describe("refusal: never a guess", () => {
  it("no map -> uncalibrated, value null, with a reason", () => {
    const r = toAiProbability(0.8, null);
    expect(r).toMatchObject({ status: "uncalibrated", value: null, interval: null, calibration_version: null });
    expect(r.reason).toMatch(/not a probability/);
  });

  it("a map fitted on too few samples is refused, even though it fits perfectly", () => {
    const tiny = fitCalibration(overconfidentSamples(60, 5), META);   // ~20 AI / ~40 human, far below the floor
    const r = toAiProbability(0.8, tiny);
    expect(r.status).toBe("uncalibrated");
    expect(r.value).toBeNull();
    expect(r.reason).toContain(String(MIN_CALIBRATION_SAMPLES_PER_CLASS));
  });

  it("a non-finite score is refused", () => {
    const m = fitCalibration(overconfidentSamples(2000, 3), META);
    expect(toAiProbability(NaN, m).status).toBe("uncalibrated");
  });

  it("a tampered / structurally invalid map is rejected rather than applied", () => {
    const good = fitCalibration(overconfidentSamples(2000, 4), META);
    const bad = (mutate: (m: CalibrationMap) => void) => { const c: CalibrationMap = JSON.parse(JSON.stringify(good)); mutate(c); return validateCalibrationMap(c); };
    expect(bad(m => { m.bins[0].lo = 0.1; })).toContain("first bin must start at score 0");
    expect(bad(m => { m.bins[2].p = m.bins[1].p - 0.2; }).some(e => /not monotone/.test(e))).toBe(true);
    expect(bad(m => { m.bins[2].lo = m.bins[1].lo; }).some(e => /strictly increase/.test(e))).toBe(true);
    expect(bad(m => { m.bins[1].k = m.bins[1].n + 1; }).some(e => /inconsistent k\/n/.test(e))).toBe(true);
    expect(bad(m => { m.bins[1].p = 1.5; }).some(e => /out of \[0,1\]/.test(e))).toBe(true);
    expect(validateCalibrationMap({ ...good, bins: [] })).toEqual(["no bins"]);
  });
});

describe("through runScan: the evidence score and the probability are separate things", () => {
  const files = [{ path: "src/a.ts", content: `// Generated by ChatGPT\nexport function computeTotalPriceWithDiscount(items, discountRate) {\n  const total = items.reduce((sum, item) => sum + item.price, 0);\n  return total * (1 - discountRate);\n}\n`.repeat(6) }];
  const scan = (extra: object = {}) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files, ...extra });
  const usable = fitCalibration(overconfidentSamples(3000, 9), META);

  it("by default (no bundled map) the result is uncalibrated and says why; the score is still reported", () => {
    const r = scan();
    expect(r.ai_probability).toMatchObject({ status: "uncalibrated", value: null });
    expect(r.ai_evidence_score).toBe(r.total_ai_percentage);
    expect(Number.isFinite(r.ai_evidence_score)).toBe(true);
  });

  it("an injected, valid map yields a calibrated probability WITHOUT changing the evidence score", () => {
    const without = scan();
    const withMap = scan({ calibration: usable });
    expect(withMap.total_ai_percentage).toBe(without.total_ai_percentage);      // calibration never rewrites the score
    expect(withMap.ai_evidence_score).toBe(without.ai_evidence_score);
    expect(withMap.ai_probability!.status).toBe("calibrated");
    expect(withMap.ai_probability!.value).toBe(toAiProbability(withMap.total_ai_percentage, usable).value);
    expect(withMap.ai_probability!.calibration_version).toBe(usable.version);
  });

  it("an insufficient map injected into a scan is refused, not applied", () => {
    const r = scan({ calibration: fitCalibration(overconfidentSamples(40, 2), META) });
    expect(r.ai_probability!.status).toBe("uncalibrated");
    expect(r.ai_probability!.value).toBeNull();
  });

  it("`calibration: null` explicitly disables calibration", () => {
    expect(scan({ calibration: null }).ai_probability!.status).toBe("uncalibrated");
  });
});
