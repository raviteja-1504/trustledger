/**
 * TrustLedger Exploitability & Reachability Scoring Engine
 *
 * Converts raw vulnerability indicators into an exploitability score using a
 * CVSS v3.1-inspired model with reachability amplification from the call graph.
 *
 * Score formula:
 *   exploitability = base_score × reachability_multiplier × context_multiplier
 *
 * Base score factors (0–1):
 *   - Attack Vector (AV):    Network > Adjacent > Local > Physical
 *   - Attack Complexity (AC): Low > High
 *   - Privileges Required (PR): None > Low > High
 *   - User Interaction (UI):  None > Required
 *   - Scope (S):             Changed > Unchanged
 *   - Impact (I):            Critical > High > Medium > Low
 *
 * Reachability amplifier:
 *   - Unreachable from entry points → score × 0.30
 *   - Reachable but not from tainted path → score × 0.65
 *   - Reachable and on tainted data path → score × 1.0
 *   - Directly at entry point → score × 1.15 (capped at 1.0)
 *
 * Context modifiers:
 *   - Auth-protected endpoint → × 0.70
 *   - Rate-limited endpoint   → × 0.85
 *   - Sandboxed environment   → × 0.40
 */

import type { CallGraphResult } from "./callGraph";
import type { ScanIndicator } from "./scanner";

// ── Types ─────────────────────────────────────────────────────────────────────

export type AttackVector      = "NETWORK" | "ADJACENT" | "LOCAL" | "PHYSICAL";
export type AttackComplexity  = "LOW" | "HIGH";
export type PrivilegesRequired = "NONE" | "LOW" | "HIGH";
export type UserInteraction   = "NONE" | "REQUIRED";
export type Scope             = "CHANGED" | "UNCHANGED";

export interface CVSSVector {
  AV:  AttackVector;
  AC:  AttackComplexity;
  PR:  PrivilegesRequired;
  UI:  UserInteraction;
  S:   Scope;
  C:   number;  // Confidentiality impact 0–1
  I:   number;  // Integrity impact 0–1
  A:   number;  // Availability impact 0–1
}

export interface ExploitabilityScore {
  vuln_id:              string;
  label:                string;
  base_score:           number;  // 0–10 CVSS-equivalent
  exploitability_score: number;  // 0–10 after reachability
  reachability:         "unreachable" | "reachable" | "tainted-path" | "entry-point";
  cvss_vector:          CVSSVector;
  is_critical_path:     boolean;
  auth_protected:       boolean;
  rate_limited:         boolean;
  cwe?:                 string;
  remediation_urgency:  "immediate" | "sprint" | "backlog" | "monitor";
}

export interface ReachabilityReport {
  scores:           ExploitabilityScore[];
  critical_count:   number;
  exploitable_count: number;  // score >= 7.0
  mean_score:       number;
  top_risks:        ExploitabilityScore[];
}

// ── CVSS base score calculation ───────────────────────────────────────────────
// Simplified CVSS v3.1 base score formula

const AV_WEIGHTS:  Record<AttackVector,       number> = { NETWORK:0.85, ADJACENT:0.62, LOCAL:0.55, PHYSICAL:0.20 };
const AC_WEIGHTS:  Record<AttackComplexity,   number> = { LOW:0.77, HIGH:0.44 };
const PR_WEIGHTS:  Record<PrivilegesRequired, number> = { NONE:0.85, LOW:0.62, HIGH:0.27 };
const UI_WEIGHTS:  Record<UserInteraction,    number> = { NONE:0.85, REQUIRED:0.62 };

function cvssBase(v: CVSSVector): number {
  const iss  = 1 - (1 - v.C) * (1 - v.I) * (1 - v.A);
  const impact = v.S === "CHANGED"
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const exploitability = 8.22 * AV_WEIGHTS[v.AV] * AC_WEIGHTS[v.AC] * PR_WEIGHTS[v.PR] * UI_WEIGHTS[v.UI];
  if (impact <= 0) return 0;
  const base = v.S === "CHANGED"
    ? Math.min(10, 1.08 * (impact + exploitability))
    : Math.min(10, impact + exploitability);
  return Math.round(base * 10) / 10;
}

// ── Vulnerability CVSS profiles ───────────────────────────────────────────────
// Each known vulnerability ID maps to a CVSS vector based on its typical exploitability.

const VULN_PROFILES: Record<string, CVSSVector & { cwe?: string }> = {
  "sql-injection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0.56, cwe:"CWE-89",
  },
  "xss": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"REQUIRED", S:"CHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-79",
  },
  "command-injection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0.56, cwe:"CWE-78",
  },
  "path-traversal": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.22, A:0, cwe:"CWE-22",
  },
  "eval-exec": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0.56, cwe:"CWE-95",
  },
  "ssrf": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.22, A:0, cwe:"CWE-918",
  },
  "hardcoded-secret": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0.22, cwe:"CWE-798",
  },
  "insecure-deserialization": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0.56, cwe:"CWE-502",
  },
  "weak-crypto": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.22, A:0, cwe:"CWE-327",
  },
  "prototype-pollution": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0.22, cwe:"CWE-1321",
  },
  "open-redirect": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"REQUIRED", S:"UNCHANGED",
    C:0.22, I:0.22, A:0, cwe:"CWE-601",
  },
  "insecure-randomness": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.22, A:0, cwe:"CWE-338",
  },
  "weak-cors": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"REQUIRED", S:"CHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-942",
  },
  "backdoor-detection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0.56, cwe:"CWE-506",
  },
  "pii-in-logs": {
    AV:"LOCAL",   AC:"LOW", PR:"LOW",  UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0,   A:0, cwe:"CWE-532",
  },
  "timing-attack": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0,   A:0, cwe:"CWE-208",
  },
  "cookie-insecurity": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"REQUIRED", S:"UNCHANGED",
    C:0.22, I:0.22, A:0, cwe:"CWE-614",
  },
  "header-injection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.22, A:0, cwe:"CWE-113",
  },
  "nosql-injection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-943",
  },
  "ldap-injection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.22, A:0, cwe:"CWE-90",
  },
  "jwt-bypass": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-347",
  },
  "ssti": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0.56, cwe:"CWE-1336",
  },
  "xxe": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.22, A:0.22, cwe:"CWE-611",
  },
  "mass-assignment": {
    AV:"NETWORK", AC:"LOW", PR:"LOW",  UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.56, A:0, cwe:"CWE-915",
  },
  "redos": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0,    I:0,   A:0.56, cwe:"CWE-1333",
  },
};

const DEFAULT_PROFILE: CVSSVector = {
  AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
  C:0.22, I:0.22, A:0,
};

// ── Context detection (auth, rate-limit) ──────────────────────────────────────

function detectContext(content: string, line: number): { auth: boolean; rateLimited: boolean } {
  const window = content.split("\n").slice(Math.max(0, line - 20), line + 5).join("\n");
  const auth = /\b(?:authenticate|authorize|verifyToken|checkAuth|requireAuth|isAuthenticated|passport\.authenticate|jwt\.verify|session\.user)\b/.test(window);
  const rl   = /\b(?:rateLimit|throttle|rateLimiter|rate_limit|checkRateLimit)\b/.test(window);
  return { auth, rateLimited: rl };
}

// ── Reachability lookup ───────────────────────────────────────────────────────

function classifyReachability(
  vulnFn:   string,
  graph:    CallGraphResult | null,
): ExploitabilityScore["reachability"] {
  if (!graph) return "reachable";  // no graph = assume worst case
  if (graph.entry_points.includes(vulnFn))       return "entry-point";
  if (!graph.reachable.has(vulnFn))               return "unreachable";
  if (graph.taint_paths.some(p => p.path.includes(vulnFn))) return "tainted-path";
  return "reachable";
}

const REACH_MULTIPLIERS: Record<ExploitabilityScore["reachability"], number> = {
  "unreachable":  0.30,
  "reachable":    0.65,
  "tainted-path": 1.00,
  "entry-point":  1.15,
};

// ── Main scoring function ─────────────────────────────────────────────────────

export function scoreExploitability(
  indicators: ScanIndicator[],
  content:    string,
  graph:      CallGraphResult | null = null,
  containingFunction = "unknown",
): ReachabilityReport {
  const securityIndicators = indicators.filter(i =>
    !i.id.startsWith("ai-") &&
    !["ngram-fingerprint","structural-clones","error-message-phrasing","identifier-length",
      "blank-line-regularity","token-frequency","prompt-leakage","style-drift",
      "watermark-detection","hallucinated-api","copy-paste-pattern"].includes(i.id)
  );

  const scores: ExploitabilityScore[] = securityIndicators.map(ind => {
    const profile  = VULN_PROFILES[ind.id] ?? DEFAULT_PROFILE;
    const base     = cvssBase(profile);
    const reach    = classifyReachability(containingFunction, graph);
    const ctx      = detectContext(content, ind.line ?? 1);
    let   adjScore = base * REACH_MULTIPLIERS[reach];
    if (ctx.auth)        adjScore *= 0.70;
    if (ctx.rateLimited) adjScore *= 0.85;

    const urgency: ExploitabilityScore["remediation_urgency"] =
      adjScore >= 8.0 ? "immediate" :
      adjScore >= 6.0 ? "sprint"    :
      adjScore >= 4.0 ? "backlog"   : "monitor";

    return {
      vuln_id:              ind.id,
      label:                ind.label,
      base_score:           base,
      exploitability_score: Math.min(10, Math.round(adjScore * 10) / 10),
      reachability:         reach,
      cvss_vector:          profile,
      is_critical_path:     reach === "entry-point" || reach === "tainted-path",
      auth_protected:       ctx.auth,
      rate_limited:         ctx.rateLimited,
      cwe:                  "cwe" in profile ? (profile as CVSSVector & { cwe?: string }).cwe : undefined,
      remediation_urgency:  urgency,
    };
  });

  scores.sort((a, b) => b.exploitability_score - a.exploitability_score);

  return {
    scores,
    critical_count:    scores.filter(s => s.exploitability_score >= 9.0).length,
    exploitable_count: scores.filter(s => s.exploitability_score >= 7.0).length,
    mean_score: scores.length
      ? scores.reduce((s, e) => s + e.exploitability_score, 0) / scores.length
      : 0,
    top_risks: scores.slice(0, 5),
  };
}
