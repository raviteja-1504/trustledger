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
 *   - Unknown (the call graph can't place the code) → score × 0.65
 *   - Reachable and on tainted data path → score × 1.0
 *   - Directly at entry point → score × 1.15 (capped at 1.0)
 *
 * Evidence first: a finding whose own data-flow trace starts at outside input is on a tainted path whatever the
 * call graph says -- the trace IS the proof the input reaches the sink. A parameter the engine only assumed
 * untrusted is "reachable" (unconfirmed). Input read from the environment / command line / stdin makes the attack
 * local (AV:L), not network. The call graph only decides for findings with no trace, and "unreachable" is kept for
 * code it can place in a function nothing calls; code it can't place at all is "unknown".
 *
 * Context:
 *   - Auth-protected endpoint (route middleware, an authorisation annotation / attribute / filter, an auth call in
 *     the code -- never a comment) → Privileges Required: Low (any logged-in user can still exploit it)
 *   - Rate-limited endpoint → × 0.85, only for findings that need many requests (timing, guessing, enumeration)
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
  // The indicator's own line -- needed by callers to match a score back to a
  // specific ScanIndicator instance. scores[] is sorted by
  // exploitability_score before this function returns (see below), and the
  // same vuln_id can legitimately appear at multiple lines in one file with
  // different reachability outcomes, so (vuln_id, line) is the only
  // unambiguous join key back to the original indicators array.
  line?:                number;
  base_score:           number;  // 0–10 CVSS-equivalent
  exploitability_score: number;  // 0–10 after reachability
  reachability:         "unreachable" | "reachable" | "tainted-path" | "entry-point" | "unknown";
  /** Why: the evidence the reachability came from, and what changed the score (shown on the finding). */
  reachability_reason:  string;
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
  // Real impact depends on the TARGET PROGRAM's own flags (rsync --rsh, tar --checkpoint-action, ...) rather
  // than guaranteed shell metacharacter execution -- lower C/I/A than command-injection, same reachability shape.
  "argument-injection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.22, I:0.22, A:0.22, cwe:"CWE-88",
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
  // A forged entry misleads whoever reads the log: integrity only.
  "log-injection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0, I:0.22, A:0, cwe:"CWE-117",
  },
  "nosql-injection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-943",
  },
  // Choosing which method / class runs: often a step from code execution.
  "unsafe-reflection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.56, A:0.22, cwe:"CWE-470",
  },
  // Loading a request-chosen source file runs it.
  "file-inclusion": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0.56, cwe:"CWE-98",
  },
  // Whatever the overwritten variable controls (often an authorisation flag).
  "variable-overwrite": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.56, A:0, cwe:"CWE-621",
  },
  // A comparison that accepts the wrong value: usually an authentication / token check bypass.
  "type-juggling": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.22, A:0, cwe:"CWE-1024",
  },
  // Corrupted shared state / a crashed process under concurrent requests.
  "race-condition": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0, I:0.22, A:0.56, cwe:"CWE-362",
  },
  // A panic per request (net/http recovers it; other servers may not).
  "input-validation": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0, I:0, A:0.22, cwe:"CWE-129",
  },
  // The victim's browser performs the state change for the attacker.
  "csrf": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"REQUIRED", S:"UNCHANGED",
    C:0, I:0.56, A:0, cwe:"CWE-352",
  },
  // Browsable folder: confidentiality of whatever sits in it.
  "directory-listing": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0, A:0, cwe:"CWE-548",
  },
  // Needs content loaded into the WebView first; then local files / other origins are readable.
  "webview-insecure-settings": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"REQUIRED", S:"CHANGED",
    C:0.56, I:0.22, A:0, cwe:"CWE-749",
  },
  // C/C++ memory corruption: write primitives that commonly end in code execution.
  "format-string": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.56, A:0.56, cwe:"CWE-134",
  },
  "buffer-overflow": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.56, A:0.56, cwe:"CWE-120",
  },
  "use-after-free": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.56, A:0.56, cwe:"CWE-416",
  },
  "double-free": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.56, A:0.56, cwe:"CWE-415",
  },
  // Availability first: a huge size exhausts memory; a wrapped one under-allocates.
  "integer-overflow": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0, I:0.22, A:0.56, cwe:"CWE-789",
  },
  // A panic per request in debug builds; a wrapped value (wrong size / price / index) in release.
  "arithmetic-overflow": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0, I:0.22, A:0.22, cwe:"CWE-190",
  },
  // Local: another app (external storage), a backup or a rooted device reads the file.
  "cleartext-sensitive-storage": {
    AV:"LOCAL", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0, A:0, cwe:"CWE-312",
  },
  "sensitive-clipboard": {
    AV:"LOCAL", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0, A:0, cwe:"CWE-200",
  },
  // The attacker needs the victim to log in on a session id the attacker set.
  "session-fixation": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"REQUIRED", S:"UNCHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-384",
  },
  // Any logged-in user runs an admin function.
  "missing-function-level-authz": {
    AV:"NETWORK", AC:"LOW", PR:"LOW", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-285",
  },
  // Unlimited guesses against whatever the limiter protects (login, reset, OTP).
  "rate-limit-bypass": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.22, A:0, cwe:"CWE-348",
  },
  // Read-only internals: routes, versions, load, sometimes configuration.
  "unauthenticated-diagnostics": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0, A:0, cwe:"CWE-497",
  },
  "null-dereference": {
    AV:"LOCAL", AC:"HIGH", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0, I:0, A:0.56, cwe:"CWE-690",
  },
  "mismatched-deallocation": {
    AV:"LOCAL", AC:"HIGH", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.22, A:0.56, cwe:"CWE-762",
  },
  "insecure-temp-file": {
    AV:"LOCAL", AC:"HIGH", PR:"LOW", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.56, A:0, cwe:"CWE-377",
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
  "trust-boundary": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.22, A:0, cwe:"CWE-501",
  },
  "mass-assignment": {
    AV:"NETWORK", AC:"LOW", PR:"LOW",  UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.56, A:0, cwe:"CWE-915",
  },
  "redos": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0,    I:0,   A:0.56, cwe:"CWE-1333",
  },

  // The following 14 ids previously fell through to the generic,
  // understating DEFAULT_PROFILE below -- confirmed via direct grep that
  // none had an entry here, several (idor/bola-*) exactly the kind of
  // high-impact finding that should score HIGH exploitability, not a
  // generic low default. Vectors reasoned from each id's existing
  // INDICATOR_CWE_MAP (cweMap.ts) CWE class and consistency with sibling
  // profiles already in this table.
  "idor": {
    AV:"NETWORK", AC:"LOW", PR:"LOW", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-639",
  },
  "bola-identity-mismatch": {
    AV:"NETWORK", AC:"LOW", PR:"LOW", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-639",
  },
  "bola-missing-ownership-check": {
    AV:"NETWORK", AC:"LOW", PR:"LOW", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-639",
  },
  "csrf-protection-disabled": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"REQUIRED", S:"CHANGED",
    C:0.22, I:0.56, A:0.22, cwe:"CWE-352",
  },
  "debug-mode-enabled": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.22, A:0, cwe:"CWE-489",
  },
  "graphql-injection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-943",
  },
  "insecure-file-upload": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0.56, cwe:"CWE-434",
  },
  // Same class of flaw (a forgeable/absent signature check on a JWT) as
  // the existing jwt-bypass profile above -- deliberately identical vector.
  "jwt-none-alg": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0, cwe:"CWE-347",
  },
  "php-missing-session-guard": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.56, A:0.22, cwe:"CWE-306",
  },
  "plaintext-password-storage": {
    AV:"NETWORK", AC:"HIGH", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.22, A:0, cwe:"CWE-256",
  },
  "sensitive-url-data": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0, A:0, cwe:"CWE-598",
  },
  "verbose-error": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0, A:0, cwe:"CWE-209",
  },
  "toctou": {
    AV:"LOCAL", AC:"HIGH", PR:"LOW", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.22, A:0.22, cwe:"CWE-367",
  },
  "xpath-injection": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"CHANGED",
    C:0.56, I:0.22, A:0, cwe:"CWE-643",
  },
  // Any registered user makes themselves an administrator.
  "privilege-escalation": {
    AV:"NETWORK", AC:"LOW", PR:"LOW", UI:"NONE", S:"UNCHANGED",
    C:0.56, I:0.56, A:0.22, cwe:"CWE-269",
  },
  // Availability only: one request sized to exhaust memory or CPU.
  "resource-exhaustion": {
    AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
    C:0, I:0, A:0.56, cwe:"CWE-770",
  },
  // A local user / process replaces or tampers with the file.
  "insecure-permissions": {
    AV:"LOCAL", AC:"LOW", PR:"LOW", UI:"NONE", S:"UNCHANGED",
    C:0.22, I:0.56, A:0.22, cwe:"CWE-732",
  },
};

const DEFAULT_PROFILE: CVSSVector = {
  AV:"NETWORK", AC:"LOW", PR:"NONE", UI:"NONE", S:"UNCHANGED",
  C:0.22, I:0.22, A:0,
};

// ── Context detection (auth, rate-limit) ──────────────────────────────────────

/** The code of a line with its comment removed (`// TODO: authenticate` must not count as authentication). */
function codeOnly(line: string): string {
  if (/^\s*(?:\/\/|#(?!\[)|\*|\/\*|--)/.test(line)) return "";
  return line.replace(/\s\/\/.*$/, "").replace(/\/\*.*?\*\//g, "").replace(/\s#\s.*$/, "");
}

// Authorisation the handler runs before the code: route middleware, an annotation / attribute / decorator / filter,
// or an auth call in the code itself.
const AUTH_RE = new RegExp([
  String.raw`\b(?:requireAuth|requireLogin|ensureAuthenticated|ensureLoggedIn|isAuthenticated|isLoggedIn|authenticate|authorize|verifyToken|checkAuth|authMiddleware|passport\.authenticate|jwt\.verify|session\.user)\b`,
  String.raw`@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|login_required|jwt_required|permission_required|UseGuards|Authenticated)\b`,
  String.raw`\[Authorize\b`,
  String.raw`\bbefore_action\s+:(?:authenticate\w*|require_\w*login\w*|require_user|authorize\w*)`,
  String.raw`->middleware\(\s*\[?\s*['"]auth`,
  String.raw`\bDepends\(\s*(?:get_current_user|get_current_active_user|current_user)\b`,
].join("|"));
const RATE_LIMIT_RE = /\b(?:rateLimit|throttle|rateLimiter|rate_limit|checkRateLimit|RateLimiter|Throttle)\b/;

function detectContext(content: string, line: number): { auth: boolean; rateLimited: boolean } {
  const window = content.split("\n").slice(Math.max(0, line - 20), line + 5).map(codeOnly).join("\n");
  return { auth: AUTH_RE.test(window), rateLimited: RATE_LIMIT_RE.test(window) };
}

/** Findings whose attack needs many requests -- the only ones a rate limit slows down. */
const RATE_SENSITIVE = new Set([
  "timing-attack", "redos", "insecure-randomness", "rate-limit-bypass", "idor", "bola-identity-mismatch",
  "bola-missing-ownership-check", "weak-crypto", "type-juggling", "jwt-bypass",
]);

// ── Reachability lookup ───────────────────────────────────────────────────────

type Reach = ExploitabilityScore["reachability"];

function classifyReachability(
  vulnFn:   string,
  graph:    CallGraphResult | null,
): Reach {
  if (!graph) return "reachable";  // no graph = assume worst case
  if (vulnFn === ROUTE_HANDLER)                   return "entry-point";
  if (graph.entry_points.includes(vulnFn))       return "entry-point";
  // code the graph can't place in a function it models (module level, an anonymous callback, a language it doesn't
  // parse): it can't tell either way
  if (!graph.functions.some(f => f.name === vulnFn)) return "unknown";
  if (!graph.reachable.has(vulnFn))               return "unreachable";
  if (graph.taint_paths.some(p => p.path.includes(vulnFn))) return "tainted-path";
  return "reachable";
}

/**
 * A function nothing outside this file can call: a `private` method (Java / C# / PHP / Kotlin), a Rust `fn` without
 * `pub`, a Python `_name`, or a JS function that isn't exported from a file that exports. When such a function has
 * no caller in the file it is dead code, whatever its own trace says the input would do if it ran. Anything else
 * (a Django view, a Go handler registered in routes.go) may be called from another file, so its trace decides.
 */
function provablyPrivate(fnName: string, graph: CallGraphResult, content: string): boolean {
  const fn = graph.functions.find(f => f.name === fnName);
  if (!fn) return false;
  const sig = fn.body.split("\n")[0] ?? "";
  if (/\bprivate\b/.test(sig)) return true;
  if (/^\s*(?:async\s+)?def\s+_\w/.test(sig)) return true;
  if (/^\s*(?:async\s+)?(?:unsafe\s+)?fn\s/.test(sig)) return true;   // a `pub fn` doesn't start with `fn`
  return /^\s*(?:async\s+)?function\b/.test(sig) && !fn.is_exported && /^\s*export\s|\bmodule\.exports\b|^\s*exports\.\w+/m.test(content);
}

/** The name a caller's resolver gives a callback passed straight to a route registration (`app.get("/x", (req, res) => ...)`). */
export const ROUTE_HANDLER = "<route-handler>";

// Input read from the process itself -- the environment, the command line, the terminal: whoever can set those
// already runs code on the machine, so the attack is local.
const LOCAL_SOURCE_RE = /\b(?:getenv|secure_getenv|_wgetenv|GetEnvironmentVariable|argv|ARGV|GetCommandLine\w*|std::env::(?:var|args)|env::(?:var|args)|os\.Getenv|os\.Args|os\.environ|sys\.argv|System\.getenv|process\.env|process\.argv|ENV\[|stdin|STDIN|fgets|gets|scanf|readline|getchar|cin)\b/;

/** Findings that are outside input reaching a sink: their trace starts at that input. (Other findings may carry a
 * trace too -- how a temp file's name was built, where a weak key came from -- which proves nothing about input.) */
const INPUT_DRIVEN = new Set([
  "sql-injection", "nosql-injection", "command-injection", "argument-injection", "xss", "path-traversal", "eval-exec",
  "ssrf", "open-redirect", "header-injection", "log-injection", "ldap-injection", "xpath-injection", "graphql-injection",
  "ssti", "xxe", "unsafe-reflection", "file-inclusion", "insecure-deserialization", "prototype-pollution", "redos",
  "mass-assignment", "variable-overwrite", "trust-boundary", "format-string", "buffer-overflow", "integer-overflow",
  "arithmetic-overflow", "input-validation", "insecure-file-upload", "resource-exhaustion",
]);

/** What the finding's own data-flow trace proves about how input reaches it. */
function evidenceOf(ind: ScanIndicator): { reach: Reach; local: boolean; reason: string } | null {
  const first = ind.trace?.[0];
  if (!first || first.kind !== "source" || !INPUT_DRIVEN.has(ind.id)) return null;
  const local = LOCAL_SOURCE_RE.test(first.label);
  const from = first.label.length > 60 ? `${first.label.slice(0, 57)}...` : first.label;
  if (ind.sourceAssumed) {
    return { reach: "reachable", local, reason: `The data-flow trace starts at '${from}', a parameter assumed to carry outside input (no request read was seen)` };
  }
  return {
    reach: "tainted-path", local,
    reason: local
      ? `The data-flow trace shows '${from}' (input from the environment, command line or terminal) reaching this sink`
      : `The data-flow trace shows outside input '${from}' reaching this sink`,
  };
}

const REACH_RANK: Record<Reach, number> = { "unknown": 0, "unreachable": 1, "reachable": 2, "tainted-path": 3, "entry-point": 4 };

const GRAPH_REASON: Record<Reach, string> = {
  "entry-point":  "Runs inside an entry point — a request handler, route, controller action or main (call graph)",
  "tainted-path": "The call graph traces outside input along the calls to this code",
  "reachable":    "Reachable from an entry point (call graph); no input was traced to it",
  "unreachable":  "No caller from any entry point was found in this file (call graph) — possibly dead code",
  "unknown":      "The call graph can't place this code in a function it models, so reachability is unknown",
};

const REACH_MULTIPLIERS: Record<Reach, number> = {
  "unreachable":  0.30,
  "unknown":      0.65,
  "reachable":    0.65,
  "tainted-path": 1.00,
  "entry-point":  1.15,
};

// ── Main scoring function ─────────────────────────────────────────────────────

export function scoreExploitability(
  indicators: ScanIndicator[],
  content:    string,
  graph:      CallGraphResult | null = null,
  // Resolves which function/method a given indicator's line actually falls
  // inside, so reachability is classified per-indicator rather than once
  // for the whole file. Previously this took a single `containingFunction`
  // string applied to every indicator -- found (via direct investigation)
  // to always be called with the literal default "unknown" (no real
  // function is ever named that), which made classifyReachability() return
  // "unreachable" for every single finding in every file, forever,
  // regardless of what the real BFS/taint-propagation graph actually
  // computed. A single string could never have fixed this correctly even
  // with a real value plugged in -- one function's reachability doesn't
  // apply to every other finding in the file -- hence the signature change
  // rather than just passing a non-"unknown" default.
  resolveContainingFunction: (line: number) => string = () => "unknown",
): ReachabilityReport {
  const securityIndicators = indicators.filter(i =>
    !i.id.startsWith("ai-") &&
    !["ngram-fingerprint","structural-clones","error-message-phrasing","identifier-length",
      "blank-line-regularity","token-frequency","prompt-leakage","style-drift",
      "watermark-detection","hallucinated-api","copy-paste-pattern"].includes(i.id)
  );

  const scores: ExploitabilityScore[] = securityIndicators.map(ind => {
    const ctx      = detectContext(content, ind.line ?? 1);
    const fnName = resolveContainingFunction(ind.line ?? 1);
    const graphReach = classifyReachability(fnName, graph);
    const evidence = evidenceOf(ind);
    // dead code stays dead: a private function nothing in the file calls never runs, whatever its trace shows
    const dead = graphReach === "unreachable" && !!graph && provablyPrivate(fnName, graph, content);
    // otherwise the stronger of the two: the trace proves input reaches the sink; the call graph may see an entry point
    const reach: Reach = !dead && evidence && REACH_RANK[evidence.reach] > REACH_RANK[graphReach] ? evidence.reach : graphReach;
    const reasons = [evidence && reach === evidence.reach ? evidence.reason
      : dead && evidence ? `Outside input would reach this sink, but '${fnName}' is private and nothing in the file calls it — dead code` : GRAPH_REASON[reach]];
    const own      = VULN_PROFILES[ind.id] ?? DEFAULT_PROFILE;
    // input from the environment / command line: a local attack; behind authentication: any logged-in user
    const profile: CVSSVector & { cwe?: string } = {
      ...own,
      ...(evidence?.local && own.AV === "NETWORK" ? { AV: "LOCAL" as const } : {}),
      ...(ctx.auth && own.PR === "NONE" ? { PR: "LOW" as const } : {}),
    };
    if (evidence?.local && own.AV === "NETWORK") reasons.push("local attack vector");
    if (ctx.auth) reasons.push("behind authentication: any logged-in user can exploit it");
    const base     = cvssBase(profile);
    let   adjScore = base * REACH_MULTIPLIERS[reach];
    const rateLimited = ctx.rateLimited && RATE_SENSITIVE.has(ind.id);
    if (rateLimited) { adjScore *= 0.85; reasons.push("rate-limited"); }

    const urgency: ExploitabilityScore["remediation_urgency"] =
      adjScore >= 8.0 ? "immediate" :
      adjScore >= 6.0 ? "sprint"    :
      adjScore >= 4.0 ? "backlog"   : "monitor";

    return {
      vuln_id:              ind.id,
      label:                ind.label,
      line:                 ind.line,
      base_score:           base,
      exploitability_score: Math.min(10, Math.round(adjScore * 10) / 10),
      reachability:         reach,
      reachability_reason:  reasons.join("; "),
      cvss_vector:          profile,
      is_critical_path:     reach === "entry-point" || reach === "tainted-path",
      auth_protected:       ctx.auth,
      rate_limited:         rateLimited,
      cwe:                  profile.cwe,
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
