/**
 * The public site's evidence (benchmark report) and coverage claims must be internally consistent and match the
 * engines: every count a whole number, every Juliet category balanced, every cited example pointing at a corpus in
 * the report, and the coverage matrix exactly the engine registry.
 */
import fs from "fs";
import path from "path";
import { BENCHMARK_REPORT as R, rates, categoryAverage, throughput } from "@/lib/benchmarkReport";
import { dataFlowRules, rulesByLanguage, COVERAGE_LANGUAGES, LANGUAGE_ENGINES, dataFlowCwes } from "@/lib/publicCoverage";
import { DATA_FLOW_LANGUAGES } from "@/lib/ruleLanguages";

describe("benchmark report", () => {
  it("names a commit and a measurement date", () => {
    expect(R.engineCommit).toMatch(/^[0-9a-f]{7,40}$/);
    expect(Number.isNaN(Date.parse(R.generatedAt))).toBe(false);
  });

  it("every category count is a non-negative whole number and every category has cases", () => {
    for (const c of R.corpora) {
      expect(c.categories.length).toBeGreaterThan(0);
      for (const cat of c.categories) {
        for (const n of [cat.tp, cat.fn, cat.fp, cat.tn]) expect(Number.isInteger(n) && n >= 0).toBe(true);
        expect(cat.tp + cat.fn + cat.fp + cat.tn).toBeGreaterThan(0);
      }
    }
  });

  it("Juliet categories are balanced: each case has one vulnerable and one safe region", () => {
    for (const c of R.corpora.filter(x => /Juliet/.test(x.name))) {
      for (const cat of c.categories) expect(cat.tp + cat.fn).toBe(cat.fp + cat.tn);
    }
  });

  it("rates and scores follow from the counts", () => {
    const r = rates([{ name: "x", tp: 3, fn: 1, fp: 1, tn: 3 }]);
    expect(r).toMatchObject({ tpr: 0.75, fpr: 0.25, score: 50, cases: 8 });
    expect(categoryAverage([{ name: "a", tp: 1, fn: 0, fp: 0, tn: 1 }, { name: "b", tp: 0, fn: 1, fp: 0, tn: 1 }])).toBe(50);
    expect(throughput({ files: 100, wallMs: 2000 })).toBe(50);
    expect(throughput({ files: null, wallMs: 2000 })).toBeNull();
  });

  it("every Juice Shop challenge says whether it was detected, and how", () => {
    expect(R.juice.challenges.length).toBeGreaterThan(0);
    for (const ch of R.juice.challenges) expect(ch.detected ? !!ch.via : ch.via === null).toBe(true);
  });

  it("every cited false positive / negative names a corpus in the report and explains itself", () => {
    const names = new Set([...R.corpora.map(c => c.name), R.juice.name]);
    for (const e of [...R.falsePositives, ...R.falseNegatives]) {
      expect(names.has(e.corpus)).toBe(true);
      expect(e.caseId.length).toBeGreaterThan(0);
      expect(e.explanation.length).toBeGreaterThan(40);
    }
    expect(R.falsePositives.length).toBeGreaterThan(0);
    expect(R.falseNegatives.length).toBeGreaterThan(0);
  });

  it("contains no mis-encoded text (UTF-8 read back as Windows-1252, e.g. an em dash shown as \"â€”\")", () => {
    expect(JSON.stringify(R)).not.toMatch(/â€|Ã[\u0080-¿]/);
  });

  it("the AI-attribution figures are proportions", () => {
    const a = R.aiAttribution;
    for (const x of [a.precision, a.recall, a.accuracy, a.rocAuc, a.toolAccuracy]) expect(x >= 0 && x <= 1).toBe(true);
    expect(a.samples).toBeGreaterThan(0);
  });
});

describe("public site text", () => {
  // UTF-8 read back as Windows-1252 and saved again: "·" becomes "Â·", "—" becomes "â€”"
  const MOJIBAKE = /Â[\u0080-¿]|â€|Ã[\u0080-¿]/;
  const SITE_SOURCES = ["src/app/page.tsx", "src/app/LandingClient.tsx", "src/app/trust", "src/app/docs", "src/app/blog", "src/app/benchmarks",
    "src/app/roadmap", "src/app/demo", "src/app/changelog", "src/components/marketing", "src/lib/demoSamples.ts", "src/lib/publicCoverage.ts"];
  const files = (p: string): string[] => {
    const abs = path.join(process.cwd(), p);
    return fs.statSync(abs).isDirectory() ? fs.readdirSync(abs).flatMap(n => files(path.join(p, n))) : /\.tsx?$/.test(p) ? [p] : [];
  };

  it("has no mis-encoded characters in any public page's source", () => {
    const bad = SITE_SOURCES.flatMap(files).filter(f => MOJIBAKE.test(fs.readFileSync(path.join(process.cwd(), f), "utf8")));
    expect(bad).toEqual([]);
  });
});

describe("coverage claims", () => {
  it("the rule list is exactly the union of the engine registries", () => {
    const union = new Set(DATA_FLOW_LANGUAGES.flatMap(l => [...l.ids]));
    expect(new Set(dataFlowRules().map(r => r.id))).toEqual(union);
    for (const r of dataFlowRules()) {
      expect(r.languages.length).toBeGreaterThan(0);
      for (const l of r.languages) expect(DATA_FLOW_LANGUAGES.find(x => x.language === l)?.ids).toContain(r.id);
    }
  });

  it("every rule has a title and a CWE", () => {
    for (const r of dataFlowRules()) {
      expect(r.title).not.toBe(r.id);
      expect(r.cwe).toMatch(/^CWE-\d+$/);
    }
    expect(dataFlowCwes().length).toBeGreaterThan(10);
  });

  it("the language descriptions name real engines, one each", () => {
    expect(LANGUAGE_ENGINES.map(l => l.engine).sort()).toEqual([...COVERAGE_LANGUAGES].sort());
    expect(rulesByLanguage().every(r => r.ruleCount > 0)).toBe(true);
  });
});
