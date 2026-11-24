/**
 * Security benchmark runner (task 10).
 *
 * Loads each per-app fixture + its metadata file, runs the production scanner,
 * maps findings to vulnerability categories, and assembles a SecurityBenchmarkReport.
 *
 * Usage (called from the regression test):
 *   const report = runSecurityBenchmark(scannerVersion, rulePackVersion, baseline?);
 *
 * Convention
 * ──────────
 * Each fixture file uses the existing // NN case-marker convention (cases 01–60 for
 * vulnerable patterns, 71–90 for negative / safe patterns).  A parallel <fixture>.meta.json
 * records the category, CWE and negative flag for each case.
 *
 * A negative case is "clean" code that resembles the vulnerable pattern but uses a safe
 * API (parameterised query, escaped output, etc.).  Any scanner finding on a negative case
 * counts as a false positive.
 */
import fs   from "fs";
import path from "path";
import { runScan } from "@/lib/scanner";
import { CURRENT_ENGINE_VERSION } from "@/lib/scanner";
import {
  type BenchmarkApp,
  type FixtureMeta,
  type CaseOutcome,
  type AppMetrics,
  type SecurityBenchmarkReport,
  type SecurityBaseline,
  VULN_CATEGORIES,
  CATEGORY_INDICATOR_IDS,
  APP_LANGUAGE,
  APP_DISPLAY_NAME,
  computeCategoryMetrics,
  aggregateApp,
  rollupByCategory,
  detectRegressions,
} from "@/lib/securityBenchmark";

const FIXTURES_DIR = path.join(__dirname, "fixtures");

/** All fixture + metadata pairs, one per benchmark app. */
const APP_FIXTURES: Array<{ app: BenchmarkApp; fixture: string; meta: string }> = [
  { app: "juiceshop", fixture: "juiceshop.ts.fixture",  meta: "juiceshop.meta.json"  },
  { app: "vulnbench", fixture: "vulnbench.py.fixture",  meta: "vulnbench.meta.json"  },
  { app: "dvwa",      fixture: "dvwa.php.fixture",      meta: "dvwa.meta.json"       },
  { app: "railsgoat", fixture: "railsgoat.rb.fixture",  meta: "railsgoat.meta.json"  },
  { app: "govwa",     fixture: "govwa.go.fixture",      meta: "govwa.meta.json"      },
  { app: "dvcsharp",  fixture: "dvcsharp.cs.fixture",   meta: "dvcsharp.meta.json"   },
];

// ── Case marker parsing (mirrors runBenchmark.ts) ─────────────────────────────

const CASE_MARKER_RE  = /^\s*(?:\/\/|#|\/?\*)\s*(\d{2})\b/;
const BONUS_MARKER_RE = /\bbonus(\d{2})\b/i;

function caseLabelForLine(lines: string[], line1: number): string | null {
  for (let i = line1 - 1; i >= 0; i--) {
    const l = lines[i];
    const bonus = l.match(BONUS_MARKER_RE);
    if (bonus) return `bonus${bonus[1]}`;
    const m = l.match(CASE_MARKER_RE);
    if (m) return m[1];
  }
  return null;
}

/** Collect every defined case label in file order. */
function collectCaseOrder(lines: string[]): string[] {
  const labels: string[] = [];
  for (const l of lines) {
    const bonus = l.match(BONUS_MARKER_RE);
    if (bonus) { labels.push(`bonus${bonus[1]}`); continue; }
    const m = l.match(CASE_MARKER_RE);
    if (m) labels.push(m[1]);
  }
  return labels;
}

// ── Build indicator-ID → category index ───────────────────────────────────────

type CategorySet = typeof VULN_CATEGORIES[number];

const ID_TO_CATEGORY = new Map<string, CategorySet>();
for (const [cat, ids] of Object.entries(CATEGORY_INDICATOR_IDS) as [CategorySet, readonly string[]][]) {
  for (const id of ids) ID_TO_CATEGORY.set(id, cat);
}

// ── Runner ────────────────────────────────────────────────────────────────────

function runAppBenchmark(
  app:      BenchmarkApp,
  fixture:  string,
  metaFile: string,
): { outcomes: CaseOutcome[]; totalCases: number; latency_ms: number } {
  const content = fs.readFileSync(path.join(FIXTURES_DIR, fixture), "utf-8");
  const meta    = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, metaFile), "utf-8")) as FixtureMeta;
  const lines   = content.split("\n");
  const caseOrder = collectCaseOrder(lines);

  const t0 = Date.now();
  const result = runScan({
    repo:       `benchmark/${app}`,
    pr_number:  1,
    commit_sha: "0000000",
    branch:     "main",
    files:      [{ path: meta.path, content }],
  });
  const totalLatency = Date.now() - t0;
  const perCaseLatency = caseOrder.length > 0 ? totalLatency / caseOrder.length : 0;

  const file = result.files.find(f => f.file_path === meta.path);
  const indicators = file?.indicators ?? [];

  // Group indicator IDs by case label
  const idsByCase = new Map<string, string[]>();
  for (const ind of indicators) {
    if (!ind.line) continue;
    const label = caseLabelForLine(lines, ind.line);
    if (!label) continue;
    let arr = idsByCase.get(label);
    if (!arr) { arr = []; idsByCase.set(label, arr); }
    arr.push(ind.id);
  }

  const outcomes: CaseOutcome[] = [];
  for (const label of caseOrder) {
    const caseMeta = meta.cases[label];
    if (!caseMeta) continue; // unlabelled case — skip

    const firedIds  = idsByCase.get(label) ?? [];
    const catMatch  = firedIds.some(id => ID_TO_CATEGORY.get(id) === caseMeta.category);

    let classification: CaseOutcome["classification"];
    if (caseMeta.negative) {
      // Negative case: any finding in the expected category = FP, silence = TN
      classification = catMatch ? "fp" : "tn";
    } else {
      // Positive (vulnerable) case: category match = TP, silence = FN
      classification = catMatch ? "tp" : "fn";
    }

    outcomes.push({
      label, meta: caseMeta, firedIds, categoryMatch: catMatch,
      classification, latency_ms: perCaseLatency,
    });
  }

  return { outcomes, totalCases: caseOrder.length, latency_ms: totalLatency };
}

// ── Public entry point ────────────────────────────────────────────────────────

export function runSecurityBenchmark(
  rulePackVersion: string,
  baseline?: SecurityBaseline,
): SecurityBenchmarkReport {
  const scannerVersion = CURRENT_ENGINE_VERSION;
  const apps: AppMetrics[] = [];

  for (const { app, fixture, meta: metaFile } of APP_FIXTURES) {
    const metaPath = path.join(FIXTURES_DIR, metaFile);
    if (!fs.existsSync(path.join(FIXTURES_DIR, fixture)) || !fs.existsSync(metaPath)) {
      // Fixture not yet implemented — record an empty entry and continue.
      apps.push({
        app, language: APP_LANGUAGE[app],
        categories: {}, overall: { precision: 1, recall: 0, f1: 0 },
        cases_total: 0,
      });
      continue;
    }

    let outcomes: CaseOutcome[] = [];
    let caseCount = 0;
    try {
      const r = runAppBenchmark(app, fixture, metaFile);
      outcomes  = r.outcomes;
      caseCount = r.totalCases;
    } catch (err) {
      console.error(`[securityBenchmark] ${app} fixture error:`, err);
    }

    const categories: Partial<AppMetrics["categories"]> = {};
    for (const cat of VULN_CATEGORIES) {
      const m = computeCategoryMetrics(outcomes, cat);
      if (m.total_cases > 0) categories[cat] = m;
    }

    apps.push({
      app, language: APP_LANGUAGE[app],
      categories,
      overall:     aggregateApp(categories),
      cases_total: caseCount,
    });
  }

  const by_category = rollupByCategory(apps);

  // Global overall
  let gTp = 0, gFp = 0, gFn = 0;
  for (const m of Object.values(by_category)) {
    if (!m) continue;
    gTp += m.tp; gFp += m.fp; gFn += m.fn;
  }
  const gPrec = gTp + gFp === 0 ? 1 : gTp / (gTp + gFp);
  const gRec  = gTp + gFn === 0 ? 0 : gTp / (gTp + gFn);
  const gF1   = gPrec + gRec === 0 ? 0 : 2 * gPrec * gRec / (gPrec + gRec);

  const report: SecurityBenchmarkReport = {
    scanner_version:   scannerVersion,
    rule_pack_version: rulePackVersion,
    generated_at:      new Date().toISOString(),
    apps, by_category,
    overall: { precision: gPrec, recall: gRec, f1: gF1 },
    regressions: baseline ? detectRegressions(
      { scanner_version: scannerVersion, rule_pack_version: rulePackVersion,
        generated_at: new Date().toISOString(), apps, by_category,
        overall: { precision: gPrec, recall: gRec, f1: gF1 }, regressions: [] },
      baseline,
    ) : [],
  };

  return report;
}

/** Convenience: list which fixture files are present. */
export function listAvailableFixtures(): string[] {
  return APP_FIXTURES
    .filter(({ fixture }) => fs.existsSync(path.join(FIXTURES_DIR, fixture)))
    .map(({ app }) => `${app} (${APP_LANGUAGE[app]})`);
}
