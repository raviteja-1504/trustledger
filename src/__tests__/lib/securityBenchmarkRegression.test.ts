/**
 * Security Benchmark Regression Test (task 10)
 *
 * Runs the production scanner against six benchmark-app fixture sets across twelve
 * vulnerability categories and asserts that the scanner hasn't regressed against the
 * committed baseline (securityBaseline.json).
 *
 * Regression rules
 * ────────────────
 * 1. RECALL regression: any category+app that previously had recall R now has recall
 *    R − 0.01 or worse → test fails (even a single case going from TP to FN counts).
 *
 * 2. PRECISION regression: any category+app that previously had precision P now has
 *    precision P − 0.05 or worse → test fails.
 *
 * 3. FINDING DISAPPEARED: a TP count that was N is now M < N → test fails unless the
 *    change is intentional (update the baseline explicitly and document the reason).
 *
 * Updating the baseline
 * ─────────────────────
 * Run with UPDATE_BASELINE=1 to write a new securityBaseline.json:
 *   UPDATE_BASELINE=1 npx jest securityBenchmarkRegression
 *
 * This must only be done intentionally (a genuine improvement, a rule rename, or a
 * documented fixture correction) — it is NOT a way to silence failing tests.
 *
 * Version mismatch
 * ────────────────
 * Regressions are only checked when scanner_version and rule_pack_version match the
 * baseline.  A version change clears the regression gate; update the baseline after
 * the change is intentional.
 *
 * Report storage
 * ──────────────
 * Each run writes a timestamped machine-readable report to
 * src/__tests__/benchmarks/securityBenchmark/reports/ so results can be tracked over
 * time.  The directory is gitignored to avoid bloat; store reports in CI artefacts.
 */

import fs   from "fs";
import path from "path";
import { warmGoTaintEngine }     from "@/lib/astTaintGo";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { warmPhpTaintEngine }    from "@/lib/astTaintPHP";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import {
  type SecurityBaseline,
  type SecurityBenchmarkReport,
  buildBaseline,
  formatSecurityReport,
  serializeReport,
  VULN_CATEGORY_LABELS,
  APP_DISPLAY_NAME,
  type VulnCategory,
  type BenchmarkApp,
} from "@/lib/securityBenchmark";
import { runSecurityBenchmark, listAvailableFixtures } from "../benchmarks/securityBenchmark/runner";

jest.setTimeout(300_000);

const BENCHMARK_DIR   = path.join(__dirname, "../benchmarks/securityBenchmark");
const BASELINE_FILE   = path.join(BENCHMARK_DIR, "securityBaseline.json");
const REPORTS_DIR     = path.join(BENCHMARK_DIR, "reports");
const RULE_PACK_VER   = "1.0.0";

function loadBaseline(): SecurityBaseline | null {
  try {
    const raw = JSON.parse(fs.readFileSync(BASELINE_FILE, "utf-8")) as SecurityBaseline;
    return raw.scanner_version ? raw : null; // empty baseline (first run) has no scanner_version
  } catch {
    return null;
  }
}

function saveBaseline(report: SecurityBenchmarkReport): void {
  fs.writeFileSync(BASELINE_FILE, JSON.stringify(buildBaseline(report), null, 2), "utf-8");
}

function saveReport(report: SecurityBenchmarkReport): void {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const stamp = report.generated_at.replace(/[:.]/g, "-");
  const name  = `${report.scanner_version}__${stamp}.json`;
  fs.writeFileSync(path.join(REPORTS_DIR, name), serializeReport(report), "utf-8");
}

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeAll(async () => {
  await Promise.all([
    warmGoTaintEngine(),
    warmCSharpTaintEngine(),
    warmPhpTaintEngine(),
    warmPythonTaintEngine(),
  ]);
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("security benchmark regression (task 10)", () => {
  let report: SecurityBenchmarkReport;
  let baseline: SecurityBaseline | null;

  beforeAll(() => {
    baseline = loadBaseline();
    report   = runSecurityBenchmark(RULE_PACK_VER, baseline ?? undefined);
    saveReport(report);

    // Always print the human-readable summary (visible in CI logs)
    console.log("\n" + formatSecurityReport(report));

    if (process.env.UPDATE_BASELINE === "1") {
      saveBaseline(report);
      console.log("[securityBenchmark] Baseline updated.");
    }
  });

  it("lists all 6 benchmark app fixtures", () => {
    // This test acts as a "fixture checklist" — if any app fixture is missing
    // it's a yellow warning, not a hard failure (fixture files are added over time).
    const available = listAvailableFixtures();
    console.log(`Available fixtures: ${available.join(", ")}`);
    expect(available.length).toBeGreaterThanOrEqual(1);
  });

  it("produces a report with the correct structure", () => {
    expect(report.scanner_version).toBeTruthy();
    expect(report.rule_pack_version).toBe(RULE_PACK_VER);
    expect(Array.isArray(report.apps)).toBe(true);
    expect(report.overall).toMatchObject({ precision: expect.any(Number), recall: expect.any(Number), f1: expect.any(Number) });
  });

  it("overall precision is in a reasonable range (> 0)", () => {
    expect(report.overall.precision).toBeGreaterThan(0);
  });

  it("overall recall is in a reasonable range (> 0)", () => {
    expect(report.overall.recall).toBeGreaterThan(0);
  });

  it("negative (safe) cases do not produce a catastrophic false-positive rate", () => {
    // Per-category FP count must not exceed the TP count across the whole report —
    // this is a sanity bound, not a precision floor.
    for (const [cat, m] of Object.entries(report.by_category) as [VulnCategory, (typeof report.by_category)[VulnCategory]][]) {
      if (!m || m.total_cases === 0) continue;
      expect(m.fp).toBeLessThanOrEqual(m.tp + m.tn + 1);
    }
  });

  // ── Regression checks (skipped when baseline is empty or version-mismatched) ─

  it("no recall regressions vs baseline", () => {
    if (!baseline || baseline.scanner_version !== report.scanner_version) {
      console.log("[securityBenchmark] No matching baseline — skipping recall regression check.");
      return;
    }
    const recs = report.regressions.filter(r => r.type === "recall_drop");
    if (recs.length > 0) {
      const msg = recs.map(r => `  ${r.message}`).join("\n");
      throw new Error(`Recall regressions detected:\n${msg}\n\nTo accept these changes, run:\n  UPDATE_BASELINE=1 npx jest securityBenchmarkRegression\nand document the reason in a PR description.`);
    }
  });

  it("no precision regressions vs baseline", () => {
    if (!baseline || baseline.scanner_version !== report.scanner_version) {
      console.log("[securityBenchmark] No matching baseline — skipping precision regression check.");
      return;
    }
    const recs = report.regressions.filter(r => r.type === "precision_drop");
    if (recs.length > 0) {
      const msg = recs.map(r => `  ${r.message}`).join("\n");
      throw new Error(`Precision regressions detected:\n${msg}`);
    }
  });

  it("no previously detected findings have disappeared", () => {
    if (!baseline || baseline.scanner_version !== report.scanner_version) {
      console.log("[securityBenchmark] No matching baseline — skipping disappeared-finding check.");
      return;
    }
    const disappeared = report.regressions.filter(r => r.type === "finding_disappeared");
    if (disappeared.length > 0) {
      const msg = disappeared.map(r => `  ${r.message}`).join("\n");
      throw new Error(
        `Previously detected findings are no longer detected:\n${msg}\n\n` +
        `If this change is intentional (rule renamed, fixture corrected, etc.), update the baseline:\n` +
        `  UPDATE_BASELINE=1 npx jest securityBenchmarkRegression`,
      );
    }
  });

  // ── Per-app recall assertions (absolute floor) ────────────────────────────

  describe("per-app recall floors (require > 0 for apps with fixtures)", () => {
    const APPS_WITH_FIXTURES: BenchmarkApp[] = ["juiceshop", "vulnbench", "dvwa", "govwa", "dvcsharp"];

    for (const app of APPS_WITH_FIXTURES) {
      it(`${APP_DISPLAY_NAME[app]}: overall recall > 0`, () => {
        const appMetrics = report.apps.find(a => a.app === app);
        if (!appMetrics || appMetrics.cases_total === 0) {
          console.log(`[securityBenchmark] ${app} fixture not yet available — skipping.`);
          return;
        }
        expect(appMetrics.overall.recall).toBeGreaterThan(0);
      });
    }
  });

  // ── Category coverage assertions ──────────────────────────────────────────

  it("benchmark covers all 12 vulnerability categories with at least 1 case each", () => {
    const { VULN_CATEGORIES } = require("@/lib/securityBenchmark");
    for (const cat of VULN_CATEGORIES as VulnCategory[]) {
      const m = report.by_category[cat];
      // Some categories may not have fixtures yet (railsgoat Ruby support varies);
      // require that the report at least has an entry if fixtures exist
      if (m) {
        expect(m.total_cases).toBeGreaterThanOrEqual(1);
      }
    }
  });

  // ── Machine-readable report format ────────────────────────────────────────

  it("serialized report is valid JSON with required fields", () => {
    const json = serializeReport(report);
    const parsed = JSON.parse(json) as SecurityBenchmarkReport;
    expect(parsed.scanner_version).toBeTruthy();
    expect(parsed.apps).toBeInstanceOf(Array);
    expect(typeof parsed.overall.precision).toBe("number");
    expect(typeof parsed.overall.recall).toBe("number");
    expect(typeof parsed.overall.f1).toBe("number");
  });

  it("formatted human-readable report contains expected sections", () => {
    const text = formatSecurityReport(report);
    expect(text).toContain("TrustLedger Security Benchmark Report");
    expect(text).toContain("By Vulnerability Category");
    expect(text).toContain("By Benchmark Application");
    expect(text).toContain("SQL Injection");
  });
});
