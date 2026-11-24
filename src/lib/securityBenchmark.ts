/**
 * TrustLedger Security Benchmark Framework (task 10)
 *
 * Evaluates the scanner against six well-known vulnerable application archetypes
 * across twelve vulnerability categories, producing per-category, per-app, and
 * per-language precision / recall / F1 metrics that are stored by scanner version
 * and rule-pack version for regression tracking.
 *
 * Design constraints:
 *   - Reuses runScan() — no new external services or dependencies.
 *   - Fixture files follow the existing // NN case-marker convention.
 *   - Negative (safe) cases are kept in separate fixtures so they don't
 *     skew the existing recall-only regression baseline.
 *   - Reports are machine-readable JSON and human-readable text; both are
 *     generated from the same evaluation run.
 *   - Comparisons across runs are only valid when scanner_version and
 *     rule_pack_version are identical (enforced by detectRegressions()).
 */

// ── Vocabulary ────────────────────────────────────────────────────────────────

export const VULN_CATEGORIES = [
  "sqli",
  "cmdi",
  "xss",
  "ssrf",
  "path-traversal",
  "insecure-deserialization",
  "auth-weakness",
  "authz-weakness",
  "prototype-pollution",
  "template-injection",
  "redos",
  "secrets-exposure",
] as const;

export type VulnCategory = (typeof VULN_CATEGORIES)[number];

export const VULN_CATEGORY_LABELS: Record<VulnCategory, string> = {
  "sqli":                    "SQL Injection",
  "cmdi":                    "Command Injection",
  "xss":                     "Cross-site Scripting",
  "ssrf":                    "Server-Side Request Forgery",
  "path-traversal":          "Path Traversal",
  "insecure-deserialization":"Insecure Deserialization",
  "auth-weakness":           "Authentication Weakness",
  "authz-weakness":          "Authorization Weakness",
  "prototype-pollution":     "Prototype Pollution",
  "template-injection":      "Template Injection",
  "redos":                   "ReDoS",
  "secrets-exposure":        "Secrets Exposure",
};

/** Which scanner indicator IDs map to each vulnerability category. */
export const CATEGORY_INDICATOR_IDS: Record<VulnCategory, readonly string[]> = {
  "sqli": [
    "sql-injection", "nosql-injection", "ldap-injection", "xpath-injection",
  ],
  "cmdi": [
    "command-injection", "eval-exec", "code-injection",
  ],
  "xss": [
    "xss", "header-injection", "open-redirect",
  ],
  "ssrf": [
    "ssrf",
  ],
  "path-traversal": [
    "path-traversal", "file-inclusion",
  ],
  "insecure-deserialization": [
    "insecure-deserialization",
  ],
  "auth-weakness": [
    "jwt-none-alg", "weak-jwt", "weak-crypto", "timing-attack",
    "hardcoded-credentials", "missing-auth",
  ],
  "authz-weakness": [
    "bola-missing-ownership-check", "mass-assignment", "missing-authz",
  ],
  "prototype-pollution": [
    "prototype-pollution",
  ],
  "template-injection": [
    "ssti", "template-injection",
  ],
  "redos": [
    "redos", "catastrophic-regex",
  ],
  "secrets-exposure": [
    "secret-in-code", "hardcoded-secret", "weak-signing-secret",
    "plaintext-password-storage",
  ],
};

export const BENCHMARK_APPS = [
  "juiceshop",
  "vulnbench",
  "dvwa",
  "railsgoat",
  "govwa",
  "dvcsharp",
] as const;

export type BenchmarkApp = (typeof BENCHMARK_APPS)[number];

export const APP_LANGUAGE: Record<BenchmarkApp, string> = {
  juiceshop: "typescript",
  vulnbench: "python",
  dvwa:      "php",
  railsgoat: "ruby",
  govwa:     "go",
  dvcsharp:  "csharp",
};

export const APP_DISPLAY_NAME: Record<BenchmarkApp, string> = {
  juiceshop: "OWASP Juice Shop",
  vulnbench: "VulnBench",
  dvwa:      "DVWA",
  railsgoat: "RailsGoat",
  govwa:     "GoVWA",
  dvcsharp:  "DVCSharp API",
};

// ── Case metadata ─────────────────────────────────────────────────────────────

/** Annotation for one case inside a fixture file. */
export interface CaseMeta {
  /** Vulnerability category this case tests. */
  category: VulnCategory;
  /** CWE number (informational). */
  cwe?: number;
  /** True = safe code that MUST NOT produce a finding. */
  negative: boolean;
  /** Short human label (optional). */
  label?: string;
}

/** Per-fixture metadata file shape (loaded as JSON alongside the fixture). */
export interface FixtureMeta {
  app:    BenchmarkApp;
  /** Synthetic path the fixture is scanned under (determines language detection). */
  path:   string;
  /** Case label → annotation. */
  cases:  Record<string, CaseMeta>;
}

// ── Per-case scanner result ────────────────────────────────────────────────────

export interface CaseOutcome {
  label:          string;
  meta:           CaseMeta;
  /** indicator IDs that fired in this case. */
  firedIds:       string[];
  /** Whether any fired indicator matches the expected category. */
  categoryMatch:  boolean;
  /** True positive / false positive / true negative / false negative classification. */
  classification: "tp" | "fp" | "tn" | "fn";
  latency_ms?:    number;
}

// ── Metrics ───────────────────────────────────────────────────────────────────

export interface CategoryMetrics {
  category:    VulnCategory;
  tp:          number;
  fp:          number;
  tn:          number;
  fn:          number;
  precision:   number;
  recall:      number;
  f1:          number;
  /** Mean scanner latency in ms per case. */
  latency_ms:  number;
  /** Fraction of cases that produced at least one indicator (any kind). */
  file_coverage: number;
  /** Number of cases evaluated in this category. */
  total_cases: number;
}

export interface AppMetrics {
  app:          BenchmarkApp;
  language:     string;
  categories:   Partial<Record<VulnCategory, CategoryMetrics>>;
  /** Overall over all categories for this app. */
  overall:      { precision: number; recall: number; f1: number };
  cases_total:  number;
}

export interface SecurityBenchmarkReport {
  /** `CURRENT_ENGINE_VERSION` from scanner.ts at the time of this run. */
  scanner_version:   string;
  /** Semver or hash of the detector/rule-pack definitions. */
  rule_pack_version: string;
  generated_at:      string;    // ISO 8601
  apps:              AppMetrics[];
  /** Rolled-up across all apps, per category. */
  by_category:       Partial<Record<VulnCategory, CategoryMetrics>>;
  /** Overall precision / recall / F1 across everything. */
  overall:           { precision: number; recall: number; f1: number };
  /** Cases that regressed from the loaded baseline (empty when no baseline loaded). */
  regressions:       SecurityRegression[];
}

export interface SecurityRegression {
  type:        "recall_drop" | "precision_drop" | "finding_disappeared";
  category:    VulnCategory;
  app:         BenchmarkApp;
  language:    string;
  metric:      string;
  baseline_value: number;
  current_value:  number;
  /** Human-readable description. */
  message:     string;
}

// ── Baseline shape (stored in securityBaseline.json) ─────────────────────────

export interface SecurityBaseline {
  scanner_version:   string;
  rule_pack_version: string;
  generated_at:      string;
  /** app → category → { precision, recall, f1, tp, fn } */
  by_app: Record<string, Record<string, {
    precision: number;
    recall:    number;
    f1:        number;
    tp:        number;
    fn:        number;
  }>>;
}

// ── Evaluation core ───────────────────────────────────────────────────────────

function f1Score(precision: number, recall: number): number {
  return precision + recall === 0 ? 0 : 2 * precision * recall / (precision + recall);
}

/** Build per-category metrics from a flat list of case outcomes. */
export function computeCategoryMetrics(
  outcomes: CaseOutcome[],
  category: VulnCategory,
): CategoryMetrics {
  const catCases = outcomes.filter(o => o.meta.category === category);
  let tp = 0, fp = 0, tn = 0, fn = 0;
  let totalLatency = 0, latencyCount = 0, coveredCount = 0;

  for (const c of catCases) {
    if (c.classification === "tp") tp++;
    else if (c.classification === "fp") fp++;
    else if (c.classification === "tn") tn++;
    else fn++;

    if (c.latency_ms !== undefined) { totalLatency += c.latency_ms; latencyCount++; }
    if (c.firedIds.length > 0) coveredCount++;
  }

  const precision  = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall     = tp + fn === 0 ? 0 : tp / (tp + fn);
  return {
    category, tp, fp, tn, fn,
    precision, recall, f1: f1Score(precision, recall),
    latency_ms:    latencyCount ? totalLatency / latencyCount : 0,
    file_coverage: catCases.length ? coveredCount / catCases.length : 0,
    total_cases:   catCases.length,
  };
}

/** Aggregate an app's per-category metrics into an overall summary. */
export function aggregateApp(categories: Partial<Record<VulnCategory, CategoryMetrics>>): {
  precision: number; recall: number; f1: number;
} {
  let tp = 0, fp = 0, fn = 0;
  for (const m of Object.values(categories)) {
    if (!m) continue;
    tp += m.tp; fp += m.fp; fn += m.fn;
  }
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall    = tp + fn === 0 ? 0 : tp / (tp + fn);
  return { precision, recall, f1: f1Score(precision, recall) };
}

/** Build the by_category roll-up from per-app results. */
export function rollupByCategory(
  appMetrics: AppMetrics[],
): Partial<Record<VulnCategory, CategoryMetrics>> {
  const acc: Partial<Record<VulnCategory, { tp: number; fp: number; tn: number; fn: number; latencySum: number; latencyN: number; coveredSum: number; total: number }>> = {};

  for (const app of appMetrics) {
    for (const [cat, m] of Object.entries(app.categories) as [VulnCategory, CategoryMetrics][]) {
      if (!m) continue;
      const a = acc[cat] ?? (acc[cat] = { tp: 0, fp: 0, tn: 0, fn: 0, latencySum: 0, latencyN: 0, coveredSum: 0, total: 0 });
      a.tp += m.tp; a.fp += m.fp; a.tn += m.tn; a.fn += m.fn;
      a.latencySum += m.latency_ms * (m.total_cases || 1);
      a.latencyN   += m.total_cases || 1;
      a.coveredSum += m.file_coverage * (m.total_cases || 1);
      a.total      += m.total_cases;
    }
  }

  const result: Partial<Record<VulnCategory, CategoryMetrics>> = {};
  for (const [cat, a] of Object.entries(acc) as [VulnCategory, typeof acc[VulnCategory]][]) {
    if (!a) continue;
    const precision = a.tp + a.fp === 0 ? 1 : a.tp / (a.tp + a.fp);
    const recall    = a.tp + a.fn === 0 ? 0 : a.tp / (a.tp + a.fn);
    result[cat] = {
      category: cat as VulnCategory,
      tp: a.tp, fp: a.fp, tn: a.tn, fn: a.fn,
      precision, recall, f1: f1Score(precision, recall),
      latency_ms:    a.latencyN ? a.latencySum / a.latencyN : 0,
      file_coverage: a.total    ? a.coveredSum / a.total    : 0,
      total_cases:   a.total,
    };
  }
  return result;
}

// ── Regression detection ──────────────────────────────────────────────────────

const PRECISION_DROP_THRESHOLD = 0.05; // 5pp drop triggers a regression
const RECALL_DROP_THRESHOLD    = 0.01; // any recall drop (≥ 1pp) triggers a regression

export function detectRegressions(
  current:  SecurityBenchmarkReport,
  baseline: SecurityBaseline,
): SecurityRegression[] {
  if (current.scanner_version !== baseline.scanner_version ||
      current.rule_pack_version !== baseline.rule_pack_version) {
    // Cross-version comparison is intentionally rejected: different versions
    // legitimately change the detector set, so a "regression" might just be
    // a renamed rule. Callers must update the baseline explicitly.
    return [];
  }

  const regressions: SecurityRegression[] = [];

  for (const appMetrics of current.apps) {
    const appBaseline = baseline.by_app[appMetrics.app];
    if (!appBaseline) continue;

    for (const [cat, m] of Object.entries(appMetrics.categories) as [VulnCategory, CategoryMetrics][]) {
      if (!m) continue;
      const b = appBaseline[cat];
      if (!b) continue;

      if (b.recall - m.recall >= RECALL_DROP_THRESHOLD) {
        regressions.push({
          type: "recall_drop",
          category: cat as VulnCategory,
          app: appMetrics.app as BenchmarkApp,
          language: appMetrics.language,
          metric: "recall",
          baseline_value: b.recall,
          current_value:  m.recall,
          message: `${APP_DISPLAY_NAME[appMetrics.app as BenchmarkApp]} / ${VULN_CATEGORY_LABELS[cat as VulnCategory]}: recall dropped from ${(b.recall * 100).toFixed(1)}% → ${(m.recall * 100).toFixed(1)}%`,
        });
      }

      if (b.precision - m.precision >= PRECISION_DROP_THRESHOLD) {
        regressions.push({
          type: "precision_drop",
          category: cat as VulnCategory,
          app: appMetrics.app as BenchmarkApp,
          language: appMetrics.language,
          metric: "precision",
          baseline_value: b.precision,
          current_value:  m.precision,
          message: `${APP_DISPLAY_NAME[appMetrics.app as BenchmarkApp]} / ${VULN_CATEGORY_LABELS[cat as VulnCategory]}: precision dropped from ${(b.precision * 100).toFixed(1)}% → ${(m.precision * 100).toFixed(1)}%`,
        });
      }

      // A TP that was present in the baseline but is now FN = disappeared finding
      if (b.tp > m.tp && b.fn <= m.fn) {
        regressions.push({
          type: "finding_disappeared",
          category: cat as VulnCategory,
          app: appMetrics.app as BenchmarkApp,
          language: appMetrics.language,
          metric: "tp_count",
          baseline_value: b.tp,
          current_value:  m.tp,
          message: `${APP_DISPLAY_NAME[appMetrics.app as BenchmarkApp]} / ${VULN_CATEGORY_LABELS[cat as VulnCategory]}: ${b.tp - m.tp} previously detected finding(s) are no longer detected — review rule or fixture changes`,
        });
      }
    }
  }

  return regressions;
}

// ── Baseline builder ──────────────────────────────────────────────────────────

/** Convert a full report into the compact baseline format. */
export function buildBaseline(report: SecurityBenchmarkReport): SecurityBaseline {
  const by_app: SecurityBaseline["by_app"] = {};
  for (const app of report.apps) {
    by_app[app.app] = {};
    for (const [cat, m] of Object.entries(app.categories) as [VulnCategory, CategoryMetrics][]) {
      if (!m) continue;
      by_app[app.app][cat] = {
        precision: m.precision, recall: m.recall, f1: m.f1,
        tp: m.tp, fn: m.fn,
      };
    }
  }
  return {
    scanner_version:   report.scanner_version,
    rule_pack_version: report.rule_pack_version,
    generated_at:      report.generated_at,
    by_app,
  };
}

// ── Report serialisation ──────────────────────────────────────────────────────

/** Machine-readable JSON output. */
export function serializeReport(report: SecurityBenchmarkReport): string {
  return JSON.stringify(report, null, 2);
}

/** Human-readable summary. */
export function formatSecurityReport(report: SecurityBenchmarkReport): string {
  const lines: string[] = [];

  lines.push("╔══════════════════════════════════════════════════════════════╗");
  lines.push("║          TrustLedger Security Benchmark Report               ║");
  lines.push("╚══════════════════════════════════════════════════════════════╝");
  lines.push(`  Scanner:    ${report.scanner_version}`);
  lines.push(`  Rule pack:  ${report.rule_pack_version}`);
  lines.push(`  Generated:  ${report.generated_at}`);
  lines.push("");

  lines.push("── Overall ───────────────────────────────────────────────────");
  lines.push(`  Precision ${pct(report.overall.precision)}  Recall ${pct(report.overall.recall)}  F1 ${pct(report.overall.f1)}`);
  lines.push("");

  lines.push("── By Vulnerability Category ──────────────────────────────────");
  const header = "  Category                        Prec    Rec     F1      TP  FP  FN";
  lines.push(header);
  lines.push("  " + "─".repeat(66));
  for (const cat of VULN_CATEGORIES) {
    const m = report.by_category[cat];
    if (!m) continue;
    const name = VULN_CATEGORY_LABELS[cat].padEnd(32);
    lines.push(
      `  ${name}${pct(m.precision)}  ${pct(m.recall)}  ${pct(m.f1)}  ${String(m.tp).padStart(3)} ${String(m.fp).padStart(3)} ${String(m.fn).padStart(3)}`,
    );
  }
  lines.push("");

  lines.push("── By Benchmark Application ───────────────────────────────────");
  for (const app of report.apps) {
    lines.push(`  ${APP_DISPLAY_NAME[app.app as BenchmarkApp]} (${app.language})`);
    lines.push(`    Overall  Prec ${pct(app.overall.precision)}  Rec ${pct(app.overall.recall)}  F1 ${pct(app.overall.f1)}  (${app.cases_total} cases)`);
    for (const cat of VULN_CATEGORIES) {
      const m = app.categories[cat];
      if (!m || m.total_cases === 0) continue;
      lines.push(`    ${VULN_CATEGORY_LABELS[cat].padEnd(30)}  Prec ${pct(m.precision)}  Rec ${pct(m.recall)}  F1 ${pct(m.f1)}  lat ${m.latency_ms.toFixed(0)}ms`);
    }
    lines.push("");
  }

  if (report.regressions.length > 0) {
    lines.push("── Regressions ────────────────────────────────────────────────");
    for (const r of report.regressions) {
      const icon = r.type === "finding_disappeared" ? "🔴" : r.type === "recall_drop" ? "🟡" : "🟠";
      lines.push(`  ${icon}  ${r.message}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`.padStart(6);
}
