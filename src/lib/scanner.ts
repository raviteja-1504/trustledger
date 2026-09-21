/**
 * TrustLedger Code Scanner v6  —  Enterprise Edition
 *
 * AI detection: 47 independent signals → noisy-OR ensemble → sigmoid output
 *   P(AI) = 1 − ∏ (1 − qᵢ × sᵢ)
 *
 * Security:  35 detectors across OWASP Top 10 + modern API attack surface
 *            Taint propagation: single-hop (hasTaintNearby) + named-variable
 *            (extractTaintedVars) + assignment-chain analysis
 *
 * v6 adds over v5:s
 *   +6 AI signals: prompt leakage, style drift, watermark detection, backdoor detection,
 *     hallucinated API, copy-paste / StackOverflow pattern detection
 *   +5 engine integrations: call graph + interprocedural taint (callGraph.ts),
 *     compliance engine (compliance.ts), exploitability scoring
 *     (reachability.ts), precision/recall evaluation framework (benchmark.ts)
 *   +2 ScanOutput fields: cross_file_consistency, repository_trust_score
 *   +1 incremental scanning: changedFiles in ScanInput skips unchanged hashes
 */

import crypto from "crypto";
import { attributeCode, type AttributionResult } from "./aiAttribution";
import { buildCallGraph }        from "./callGraph";
import { aggregateComplianceReports, evaluateCompliance } from "./compliance";
import type { ComplianceReport }  from "./compliance";
import { scoreExploitability }   from "./reachability";
import type { ReachabilityReport } from "./reachability";
import {
  parseSourceFile, scanAstTaint, findNodeAtPosition, findEnclosingFunctionName, astTaintSeverity, astTaintLabel,
  computeExportTaintSummary, buildImportBindings,
} from "./astTaint";
import type { ParamShape } from "./astTaint";
import { resolveImportPath } from "./semanticGraph";
import type * as ts from "typescript";
import {
  parsePythonSourceSync, isPythonParserReady, scanAstTaintPython,
  findEnclosingFunctionNamePy, findNodeAtRowPy, astTaintPySeverity, astTaintPyLabel,
} from "./astTaintPython";
import type { Node as PySyntaxNode } from "web-tree-sitter";
import { parseJavaSource, scanAstTaintJava, astTaintJavaSeverity, astTaintJavaLabel, findEnclosingFunctionNameJava } from "./astTaintJava";
import type { CstNode as JavaCstNode } from "java-parser";
import {
  parseGoSourceSync, isGoParserReady, scanAstTaintGo,
  findEnclosingFunctionNameGo, findNodeAtRowGo, astTaintGoSeverity, astTaintGoLabel,
} from "./astTaintGo";
import type { Node as GoSyntaxNode } from "web-tree-sitter";
import {
  parseCSharpSourceSync, isCSharpParserReady, scanAstTaintCSharp,
  findEnclosingFunctionNameCSharp, findNodeAtRowCSharp, astTaintCSharpSeverity, astTaintCSharpLabel,
} from "./astTaintCSharp";
import type { Node as CSharpSyntaxNode } from "web-tree-sitter";
import {
  parsePhpSourceSync, isPhpParserReady, scanAstTaintPHP,
  findEnclosingFunctionNamePHP, findNodeAtRowPHP, astTaintPHPSeverity, astTaintPHPLabel,
} from "./astTaintPHP";
import type { Node as PhpSyntaxNode } from "web-tree-sitter";
import { parseAst }              from "./ast";
import type { AstMetrics, AstRisk } from "./ast";
import { buildSSA, extractFunctionBody } from "./ssa";
import type { TaintPath }        from "./ssa";
import { buildSemanticGraph }    from "./semanticGraph";
import type { SemanticGraph }    from "./semanticGraph";
import { analyzeGitProvenance }  from "./gitProvenance";
import type { ProvenanceSummary as GitProvenanceSummary } from "./gitProvenance";
import { classifyCode }          from "./mlClassifier";
import type { MLScoreResult }    from "./mlClassifier";
import { detectorRegistry }      from "./detectorRegistry";
// Side-effecting import: registers the IaC security Phase 3 detectors
// (Terraform + Kubernetes) through detectorRegistry above -- see
// iacDetectors.ts's own docblock. Importing here (rather than relying on
// some other module to import it first) guarantees registration has
// happened before any scan runs, regardless of import ordering elsewhere.
import "./iacDetectors";
// Side-effecting import: registers the Container security phase detectors
// (Dockerfile + docker-compose.yml) through detectorRegistry above -- see
// containerDetectors.ts's own docblock. Same reasoning as iacDetectors.ts
// above: import here, not left to another module's import order.
import "./containerDetectors";
import { cweFor as cweEntryFor } from "./cweMap";
import { scanHallucinatedMethodCalls } from "./hallucinatedMethodCall";
import { scanLicenseContamination } from "./licenseContamination";
import { isDockerfilePath } from "./scannableFiles";

// Registered once at module load (detectorRegistry.register() throws on a
// duplicate id, so this must not live inside analyzeFile). First real
// consumer of detectorRegistry.ts's plugin point -- see hallucinatedMethodCall.ts.
detectorRegistry.register({
  id: "hallucinated-method-call",
  category: "security",
  scan: scanHallucinatedMethodCalls,
});
detectorRegistry.register({
  id: "license-header-contamination",
  category: "security",
  scan: scanLicenseContamination,
});

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ScanIndicator {
  id:           string;
  label:        string;
  severity:     "critical" | "high" | "medium" | "low" | "info";
  line?:        number;
  detail?:      string;
  // 0-100. How specific was the match, not how severe the vuln class is:
  // a named-taint match (a variable traced from request input to a sink) is
  // more confident than a same-line keyword-co-occurrence regex, which is
  // more confident than a bare pattern match with no taint context at all.
  confidence?:  number;
  // "third_party" for a match inside vendored/minified code, "test_code" for
  // a match inside a test file -- both preserved as evidence but excluded
  // from risk-level escalation (see calculateRisk). hardcoded-secret and
  // high-entropy-secret are never downgraded this way (see attachEvidence) --
  // a real leaked key in a vendor bundle or test fixture is still real.
  codeCategory?: "application" | "third_party" | "test_code";
  cwe?:         string;
  // Which detector(s) independently flagged this same id+line -- populated
  // when analyzeFile's dedup pass collapses multiple hits into one finding.
  supportingDetectors?: string[];
  // Per-instance call-graph reachability, merged in from the file-level
  // ReachabilityReport (see the scoreExploitability() call below) after it
  // runs. Lives on the individual finding rather than only on the file-level
  // aggregate because the same rule id can be reachable at one line and dead
  // code at another within the same file -- see signalClassification.ts's
  // realReachability() for how the UI is meant to read this.
  reachability?:         "unreachable" | "reachable" | "tainted-path" | "entry-point";
  exploitability_score?: number;
  remediation_urgency?:  "immediate" | "sprint" | "backlog" | "monitor";
}

export interface FixSuggestion {
  vuln_id:      string;
  title:        string;
  description:  string;
  code_before?: string;
  code_after?:  string;
  cwe?:         string;
  effort:       "low" | "medium" | "high";
}

export interface WatermarkHit {
  type:   "unicode-zwsp" | "unicode-zwj" | "unicode-zwnj" | "soft-hyphen" | "word-joiner" | "comment-hash" | "ai-tag";
  line:   number;
  detail: string;
}

export interface SupplyChainRisk {
  score:         number;  // 0–1
  risky_imports: string[];
  typosquats:    string[];
  suspicious:    string[];
}

export interface BehavioralRisk {
  score:                 number;  // 0–1
  logic_bombs:           number;
  exfiltration_patterns: number;
  timing_channels:       number;
  hidden_channels:       number;
}

export interface ProvenanceInfo {
  drift_score:       number;  // 0–1: AI style shift within file
  temporal_risk:     number;  // 0–1: rushed / cut-paste patterns
  agentic_artifacts: string[];  // detected AI agent session markers
}

export interface ExplainedSignal {
  id:           string;
  label:        string;
  tier:         "CORE" | "SECONDARY" | "STYLE";
  value:        number;
  contribution: number;  // estimated fractional share of final AI score
  detail:       string;
}

export interface CICDTrustScore {
  score:            number;  // 0–1 (1 = fully trusted)
  findings:         string[];
  dangerous_steps:  string[];
  pinned_actions:   boolean;
  secret_scanning:  boolean;
}

export interface AIToolingArtifact {
  tool:   string;  // "Cursor" | "Windsurf" | "Claude Code" | etc.
  file:   string;  // matched file path
  label:  string;  // human-readable description of what was detected
}

export interface FileAnalysis {
  file_path:          string;
  language:           string;
  ai_percentage:      number;
  risk_score:         RiskLevel;
  risk_indicators:    string[];
  indicators:         ScanIndicator[];
  content_hash:       string;
  line_count:         number;
  attribution:        AttributionResult;
  scan_quality:       number;
  fix_suggestions:    FixSuggestion[];
  watermarks:         WatermarkHit[];
  supply_chain:       SupplyChainRisk;
  behavioral_risk:    BehavioralRisk;
  provenance:         ProvenanceInfo;
  line_attribution:   number[];
  explained_signals:  ExplainedSignal[];
  exploitability:     ReachabilityReport | null;
  compliance:         ComplianceReport | null;
  ast_metrics:        AstMetrics | null;
  ast_risks:          AstRisk[];
  ssa_taint_paths:    TaintPath[];
  ml_score:           MLScoreResult | null;
}

// ── Language detection ─────────────────────────────────────────────────────────

const LANG_MAP: Record<string, string> = {
  py: "python",   ts: "typescript", tsx: "typescript",
  js: "javascript", jsx: "javascript",
  rb: "ruby",     go: "golang",     rs: "rust",
  java: "java",   kt: "kotlin",     cs: "csharp",   cshtml: "csharp",
  php: "php",     cpp: "cpp",       c:   "c",
  swift: "swift", yaml: "yaml",     yml: "yaml",
  json: "json",   sh: "shell",      sql: "sql",
  md: "markdown", tf: "terraform",  ex: "elixir",
  xml: "xml",     properties: "properties", gradle: "gradle",
  tfvars: "terraform",
};

export function detectLanguage(path: string): string {
  // Dockerfile has no extension at all -- LANG_MAP above is purely
  // extension-keyed, so a basename check has to run first (isDockerfilePath
  // also matches Dockerfile.<env> variants like Dockerfile.prod, which
  // `"Dockerfile.prod".split(".").pop()` alone would resolve to "prod", not
  // "dockerfile").
  if (isDockerfilePath(path)) return "dockerfile";
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  return LANG_MAP[ext] ?? "text";
}

// ── File-type metadata (drives priors + skip logic) ───────────────────────────

interface FileTypeMeta {
  skipAI:      boolean;
  isGenerated: boolean;
  isTestFile:  boolean;
  aiPriorBias: number;  // added to noisyOr before sigmoid
}

function getFileTypeMeta(filePath: string): FileTypeMeta {
  const lower   = filePath.toLowerCase();
  const base    = lower.split(/[\\/]/).pop() ?? lower;
  const ext     = base.split(".").pop() ?? "";

  const SKIP_EXTS = new Set(["json","yaml","yml","toml","ini","env","lock","csv","sql","md","txt","xml","svg","png","jpg","ico","woff","woff2","properties","gradle","tf","tfvars"]);
  // Dockerfile is extensionless (base.split(".").pop() only resolves to
  // "dockerfile" for the bare filename, not Dockerfile.prod-style variants)
  // -- docker-compose.yml already skips via the "yaml" entry above.
  if (SKIP_EXTS.has(ext) || isDockerfilePath(filePath)) return { skipAI:true, isGenerated:false, isTestFile:false, aiPriorBias:0 };

  const isGenerated =
    /[.-](?:d\.ts|min\.js|min\.css|bundle\.js)$/.test(lower) ||
    /\.pb\.(?:ts|js|go)$/.test(lower) ||
    base.includes(".generated.") || base.includes("_pb.") ||
    base.includes("_generated.") || base.endsWith(".gen.ts") ||
    base.endsWith(".gen.js");
  if (isGenerated) return { skipAI:true, isGenerated:true, isTestFile:false, aiPriorBias:0 };

  const isTestFile =
    /\.(test|spec)\.[jt]sx?$/.test(lower) ||
    /_test\.[a-z]+$/.test(lower) ||
    /_spec\.[a-z]+$/.test(lower) ||
    /[Tt]est\.[a-z]+$/.test(lower) ||
    /^test_/.test(base) ||
    lower.endsWith("_test.go") ||
    lower.endsWith("_test.rb");

  return {
    skipAI:      false,
    isGenerated: false,
    isTestFile,
    aiPriorBias: isTestFile ? 0.08 : 0,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// SECURITY DETECTORS
// All patterns compiled once at module level for throughput.
// ══════════════════════════════════════════════════════════════════════════════

interface SecretPattern {
  re: RegExp;
  label: string;
  severity: ScanIndicator["severity"];
  // Generic word-keyed patterns (password=, secret=, token=) have no fixed
  // structure unlike branded prefixes (sk_live_, AKIA, ghp_) — they need an
  // extra randomness check on the captured value to avoid flagging English
  // phrases, validation messages, and readable test fixtures. The regex must
  // capture the value in group 1 when this is set.
  genericValue?: boolean;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { re: /(?:sk_live|sk_test)_[A-Za-z0-9]{20,}/,                               label: "Stripe API key",              severity: "critical" },
  { re: /AKIA[0-9A-Z]{16}/,                                                    label: "AWS Access Key ID",           severity: "critical" },
  { re: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}/,                           label: "GitHub token",                severity: "critical" },
  { re: /glpat-[A-Za-z0-9_-]{20}/,                                             label: "GitLab token",                severity: "critical" },
  { re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/,                          label: "SendGrid API key",            severity: "critical" },
  { re: /xox[baprs]-[0-9A-Za-z-]+/,                                            label: "Slack token",                 severity: "critical" },
  { re: /AIza[0-9A-Za-z_-]{35}/,                                               label: "Google API key",              severity: "high"     },
  { re: /AC[a-z0-9]{32}/,                                                       label: "Twilio Account SID",          severity: "critical" },
  { re: /SK[a-z0-9]{32}/,                                                       label: "Twilio Auth Token",           severity: "critical" },
  { re: /npm_[A-Za-z0-9]{36}/,                                                  label: "NPM access token",            severity: "critical" },
  // Word-boundary guards required: without them, "s." + 24 alnum chars matches
  // ANY property access on an object name ending in "s" followed by a long
  // property name (values.someVeryLongPropertyName, options.anotherFieldHere,
  // settings.xyz) — extremely common JS/TS syntax, not a Vault token shape.
  // Also excludes a following "(" — Go's idiomatic single-letter receiver `s`
  // (s *Server, s *Service) makes s.SomeLongMethodName(...) syntactically
  // identical to a real Vault token by shape alone; a real token value is
  // never itself a function call, and every Go method/function call requires
  // "(" even with zero arguments, so this exclusion is safe.
  { re: /(?<![\w.])s\.[A-Za-z0-9]{24,}(?![.\w(])/,                             label: "HashiCorp Vault token",       severity: "critical" },
  { re: /(?:DD_API_KEY|DATADOG_API_KEY)[^=\n]*=\s*["'][A-Za-z0-9]{32,}["']/i, label: "Datadog API key",             severity: "high"     },
  { re: /xkeysib-[a-f0-9]{64}-[A-Za-z0-9_-]+/,                                label: "Brevo API key",               severity: "critical" },
  { re: /key-[a-f0-9]{32}/,                                                     label: "Mailgun API key",             severity: "critical" },
  { re: /shpat_[A-Za-z0-9]{32}/,                                                label: "Shopify access token",        severity: "critical" },
  { re: /(?:HEROKU_API_KEY)[^=\n]*=\s*["'][A-Za-z0-9-]{36}["']/i,             label: "Heroku API key",              severity: "critical" },
  { re: /Basic\s+[A-Za-z0-9+/]{20,}={0,2}/,                                    label: "HTTP Basic Auth header",      severity: "high"     },
  { re: /Bearer\s+ey[A-Za-z0-9_-]{20,}/,                                        label: "Hardcoded Bearer token",      severity: "high"     },
  { re: /(?:eyJ[A-Za-z0-9_-]{10,}\.){2}[A-Za-z0-9_-]+/,                       label: "Hardcoded JWT",               severity: "high"     },
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY/,                   label: "Private key",                 severity: "critical" },
  { re: /(?:private_key|private_key_id)\s*:\s*["'][-\w /+]+["']/i,            label: "Service account key",         severity: "critical" },
  { re: /postgresql:\/\/[^@\s]+:[^@\s]+@/,                                     label: "Postgres credentials",        severity: "critical" },
  { re: /mongodb(?:\+srv)?:\/\/[^@\s]+:[^@\s]+@/,                              label: "MongoDB credentials",         severity: "critical" },
  { re: /mysql:\/\/[^@\s]+:[^@\s]+@/,                                          label: "MySQL credentials",           severity: "critical" },
  { re: /jdbc:[a-z]+:\/\/[^\s"']+password=[^\s&"']+/i,                         label: "DB connection string",        severity: "critical" },
  // Generic word-keyed patterns — value captured in group 1, checked by
  // looksLikeRealSecret() in findSecrets() before being reported. Variable
  // name allows a _KEY/_TOKEN/_VALUE suffix to catch real-world names like
  // SECRET_KEY (Django/Flask/Rails) and AUTH_TOKEN without using a greedy
  // \w* that would also match unrelated names like "secretary_name".
  { re: /(?:password|passwd|pwd)\s*=\s*["']([^"']{8,})["']/i,                  label: "Hardcoded password",          severity: "critical", genericValue: true },
  { re: /(?:api_key|apikey|api_secret)\s*=\s*["']([^"']{8,})["']/i,            label: "Hardcoded API key",           severity: "critical", genericValue: true },
  { re: /(?:secret|token)(?:_?key|_?token|_?value)?\s*=\s*["']([^"']{12,})["']/i, label: "Hardcoded secret",          severity: "high",     genericValue: true },
  { re: /(?:access_token|ACCESS_TOKEN)\s*=\s*["']([A-Za-z0-9_\-]{20,})["']/i, label: "Hardcoded access token",      severity: "high",     genericValue: true },
];

// Well-known dummy/placeholder values used throughout test suites and demos —
// never real secrets even though they pass the length check.
const DUMMY_SECRET_VALUES_RE = /^(?:12345678|01234567890?|0{6,}|1{6,}|abcdefgh\w*|qwerty\w*|password\d*|letmein\d*|changeme\d*|changeit\d*|admin123\w*|test1234\w*|secret123\w*|foobar\w*|your[-_]?(?:key|token|secret|password)\w*)$/i;

// Real secrets are high-entropy, randomly-generated strings that typically mix
// character classes (upper+lower+digit, or +symbol). English words, validation
// messages, and readable test fixtures are low-entropy and usually a single
// character class. This check is applied only to the 4 generic word-keyed
// patterns above — branded formats (sk_live_, AKIA, ghp_) are already
// unambiguous from their structure and don't need it.
function looksLikeRealSecret(value: string): boolean {
  if (/\s/.test(value)) return false;                       // secrets don't contain spaces
  if (DUMMY_SECRET_VALUES_RE.test(value)) return false;      // known placeholder values
  if (/^(.)\1{5,}$/.test(value)) return false;               // repeated-char filler (aaaaaa, xxxxxx)
  const hasUpper  = /[A-Z]/.test(value);
  const hasLower  = /[a-z]/.test(value);
  const hasDigit  = /[0-9]/.test(value);
  const hasSymbol = /[^A-Za-z0-9]/.test(value);
  const classCount = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;
  if (classCount < 2) return false;                          // single-class strings read as English/numeric, not secrets
  return shannonEntropy(value) > 2.8;
}

// Files whose content is test/fixture/mock data — generic word-keyed secret
// patterns (password=, secret=, token=) are extremely noisy here since test
// suites routinely hardcode fake credentials for mocking. Branded/structural
// patterns (Stripe keys, AWS keys, private keys, DB URLs) still fire since a
// real leaked key checked into a test file is still a real exposed credential.
const TEST_FILE_RE = /(?:^|\/)(?:__tests__|__mocks__|tests?|fixtures?|mocks?|specs?)\/|\.(?:test|spec)\.[jt]sx?$|(?:^|\/)test_\w+\.py$|_test\.(?:py|go)$/i;

// Well-known placeholder/example credentials used throughout official docs,
// SDKs, and tutorials (e.g. AWS's canonical "EXAMPLE" key pair). These are
// never real secrets — flagging them is a pure false positive.
const KNOWN_PLACEHOLDER_SECRET_RE = /AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/;

// Quoted string literals of 4+ chars — used to inspect *values* assigned to
// secret-shaped variables, rather than the whole line (which would also match
// the variable name itself, e.g. "...PASSWORD...").
const QUOTED_VALUE_RE = /["']([^"']{4,})["']/g;

// A quoted value containing one of these markers is a synthetic/demo
// placeholder, not a real credential: "..." truncation, "xxxx" filler, or
// words that only appear in sample/demo/test data.
// `password` is word-bounded (\bpassword\b), unlike the other bare markers
// here -- without the boundary, a real, specific secret value that merely
// CONTAINS "password" as part of a compound word (e.g. a MySQL connection
// string literally embedding "SuperSecretPassword" as the actual password)
// was being treated as placeholder text and silently suppressed entirely,
// defeating every branded SECRET_PATTERNS entry on that line (confirmed via
// a real benchmark). The already-existing `\byour[-_]?\w*password\w*`
// alternative below still catches the legitimate placeholder shapes this
// word-boundary version would otherwise miss (your_password_here, etc.).
const PLACEHOLDER_VALUE_RE = /\.\.\.|[xX]{4,}|trustledger|\bpassword\b|demo|sample|fake|dummy|placeholder|example|exmp|\btest\w*|\bmock\w*|\bstub\b|\bfixture\b|changeme|change[-_]me|changeit|\btbd\b|\bn\/?a\b|\bfoo\b|\bbar\b|\bbaz\b|\byour[-_]?\w*(?:key|token|secret|password)\w*|insert[-_]?your|<[^<>]+>|\{\{[^{}]+\}\}|redacted|masked|undefined|^null$|_here$|^enter[-_]/i;

// A quoted value that is purely a human-readable label (letters/spaces only)
// is a UI string, not a credential — e.g. private_key: "Private Key".
const LABEL_VALUE_RE = /^[A-Za-z][A-Za-z ]{2,29}$/;

function isPlaceholderSecretLine(line: string): boolean {
  if (KNOWN_PLACEHOLDER_SECRET_RE.test(line)) return true;
  QUOTED_VALUE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = QUOTED_VALUE_RE.exec(line))) {
    const v = m[1];
    if (PLACEHOLDER_VALUE_RE.test(v) || LABEL_VALUE_RE.test(v)) return true;
  }
  return false;
}

// Source files whose entire content is fixture/demo data describing
// *other* (fictional) findings for the demo UI and test suite — not this
// app's own runtime logic. Secret-shaped strings here are intentional demo
// content, not exposed credentials.
const DEMO_DATA_FILE_RE = /\/(seed|seedFileSamples|vulnCatalog)\.ts$|\/secrets\/page\.tsx$/;

// Shannon entropy — detects novel secret formats that match no known pattern
function shannonEntropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  const n = s.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / n;
    return sum + p * Math.log2(p);
  }, 0);
}

const ENTROPY_CRED_RE = /\b(?:key|secret|token|password|passwd|auth|credential|api[\s_-]?key|private[\s_-]?key|access[\s_-]?token|hmac|jwt|seed|salt|signing[\s_-]?key|bearer)\s*(?:=|:)/i;
const ENTROPY_STRING_RE = /["']([A-Za-z0-9+/=_\-~]{20,})["']/g;

// Multi-line taint: user input assigned near a dangerous sink
const TAINT_SOURCES = [
  /\breq\.(?:query|body|params|headers)\b/,
  /\brequest\.(?:query|body|params|headers)\b/,
  /\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b/,
  /\bparams(?:\[|\.)\b/,
  /\binput(?:\[|\.)\b/,
  /\bsearch[Pp]arams\.get\b/,
  /\bformData\.get\b/,
  /\buserInput\b|\buserData\b/,
  // Java/Kotlin (Servlet + Spring MVC)
  /\brequest\.getParameter\b|\brequest\.getHeader\b/,
  /@(?:PathVariable|RequestParam|RequestBody|RequestHeader)\b/,
  // Go (net/http + gin/echo/fiber/chi)
  /\br\.URL\.Query\(\)|r\.FormValue\b|r\.PostFormValue\b|mux\.Vars\(r\)/,
  /\bc\.(?:Param|Params|Query|QueryParam|PostForm)\s*\(/,  // gin/echo/fiber context
  /\bchi\.URLParam\s*\(\s*r\s*,/,  // chi router
  // C# (ASP.NET) — Ruby's params[...] is already covered by the generic
  // /\bparams(?:\[|\.)\b/ pattern above.
  /\bRequest\.(?:Query|Form)\[|\[From(?:Query|Route|Body|Header)\]/,
];

function hasTaintNearby(lines: string[], sinkLine: number, window = 12): boolean {
  const start = Math.max(0, sinkLine - window);
  for (let i = start; i < sinkLine; i++) {
    if (TAINT_SOURCES.some(re => re.test(lines[i]))) return true;
  }
  return false;
}

// Named-variable taint tracker: extracts variable names assigned from user input.
// Catches patterns like:  const url = req.query.url;  fetch(url);
// Collapse a Prettier-style multi-line destructuring assignment —
//   const {
//       userId,
//       benefitStartDate
//   } = req.body;
// — into one logical line so the single-line regexes below can see the
// whole statement. Without this, every taint-tracking detector (SSRF/XSS/
// IDOR named-variable passes) silently misses any request field destructured
// across multiple lines, which is the default wrap style for 2+ properties
// in Prettier/most JS/TS formatters and extremely common in practice.
function toLogicalLines(lines: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (/\b(?:const|let|var)\s*\{\s*$/.test(lines[i].trim())) {
      let merged = lines[i].trim();
      let j = i + 1;
      while (j < lines.length && j < i + 12 && !lines[j].includes("}")) {
        merged += " " + lines[j].trim();
        j++;
      }
      if (j < lines.length && lines[j].includes("}")) {
        merged += " " + lines[j].trim();
        i = j;
      }
      out.push(merged);
      continue;
    }
    out.push(lines[i]);
  }
  return out;
}

const CSHARP_ENTRY_ATTR_LINE_RE = /^\s*\[(?:Http(?:Get|Post|Put|Delete|Patch)|Route)\b/;
const CSHARP_SIG_PARAMS_RE = /\b(?:public|private|protected|internal)\s+(?:static\s+)?(?:async\s+)?[\w<>[\],.\s]+?\s+\w+\s*\(([^)]*)\)/;
const CSHARP_SIMPLE_TYPE_PARAM_RE = /^(?:string|int|long|short|byte|bool|double|float|decimal|char|Guid|DateTime|byte\[\])\??\s+(\w+)/;

function extractTaintedVars(rawLines: string[]): Set<string> {
  const tainted = new Set<string>();
  const lines = toLogicalLines(rawLines);
  // C#: [HttpGet("users/{id}")] on its own line (Allman-brace convention
  // puts the entry-point attribute directly above the signature, not on
  // it), tracked via one line of lookback state -- same shape as
  // phpExtractTripped below. Mirrors astTaintCSharp.ts's own
  // extractMethodInfo fix: a simple-type parameter with NO [From*]
  // attribute at all, on an entry-point method, is still bound from the
  // route/query string by ASP.NET Core's implicit convention --
  // GetUser(int id) is exactly as attacker-controlled as
  // GetUser([FromRoute] int id). Best-effort like the rest of this
  // function: only recognizes the attribute on the IMMEDIATELY preceding
  // line (a second attribute, e.g. [Authorize], between the entry marker
  // and the signature is an accepted, undetected edge case here).
  let pendingCSharpEntryMethod = false;
  // PHP: extract($_GET)/extract($_POST)/... bulk-taints an UNBOUNDED,
  // UNNAMED set of local variables from array keys -- genuinely different
  // from every other source pattern here (all of which bind one specific,
  // readable name). No way for a text scan to know the key names (runtime-
  // determined, attacker-controlled). Mechanism: a file-scoped flag, set
  // once extract() on a superglobal is seen; every bare $var referenced on
  // a LATER line is then added to `tainted` directly.
  // ACCEPTED IMPRECISION (recall-favoring, not a silent gap): once tripped,
  // this treats essentially every variable used for the rest of the file as
  // taintable -- there's no way to know which extracted names were really
  // GET/POST-derived vs. declared locally afterward for unrelated reasons.
  // A file calling extract() on request data is already a strong code
  // smell in its own right, so the extra findings this produces in that one
  // file are an acceptable price for not silently missing the extraction
  // entirely.
  let phpExtractTripped = false;
  for (const line of lines) {
    if (isNonExecutableLine(line)) continue;
    if (phpExtractTripped) {
      for (const m of line.matchAll(/\$(\w+)/g)) tainted.add(m[1]);
    }
    const phpExtractCall = /\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/.exec(line);
    if (phpExtractCall) { phpExtractTripped = true; continue; }
    // const/let/var x = req.query.x
    const single = /\b(?:const|let|var)\s+(\w+)\s*=\s*(?:req|request)\.(?:query|body|params|headers)\b/.exec(line);
    if (single) { tainted.add(single[1]); continue; }
    // const command = "cat " + req.query.file -- req.X embedded anywhere in
    // a concatenation RHS, not assigned to its own variable first (as
    // opposed to `single` above, which requires req.X to be the entire RHS
    // on its own). A single-hop sibling of the "second-hop propagation"
    // check further down, needed because that one only recognizes an
    // already-tainted *variable name* on the RHS, not an inline req.X
    // property access.
    const inlineConcatSource = /\b(?:const|let|var)\s+(\w+)\s*=\s*.*(?:req|request)\.(?:query|body|params|headers)\b/.exec(line);
    if (inlineConcatSource) { tainted.add(inlineConcatSource[1]); continue; }
    // const { a, b } = req.query
    const destruct = /\b(?:const|let|var)\s+\{([^}]+)\}\s*=\s*(?:req|request)\.(?:query|body|params|headers)\b/.exec(line);
    if (destruct) {
      destruct[1].split(",").forEach(v => {
        const name = v.trim().split(/\s*:\s*|\s+as\s+/)[0].trim();
        if (/^\w+$/.test(name)) tainted.add(name);
      });
      continue;
    }
    // Python: url = request.args.get(...)
    // Covers both the attribute form (request.json, request.args) and the
    // extremely common Flask method-call form (request.get_json(),
    // request.get_data()) -- found missing via a real VAmPI benchmark, where
    // `request_data = request.get_json()` is the actual idiom used
    // throughout the app and was silently invisible to every named-taint
    // detector that depends on this function.
    const pyAssign = /^(\w+)\s*=\s*request\.(?:args|form|json|data|POST|GET|get_json|get_data)\s*\(?/.exec(line.trim());
    if (pyAssign) { tainted.add(pyAssign[1]); continue; }
    // PHP: $url = $_GET['url']
    const phpAssign = /^\$(\w+)\s*=\s*\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\s*\[/.exec(line.trim());
    if (phpAssign) { tainted.add(phpAssign[1]); continue; }
    // PHP: $url = filter_input(INPUT_GET, 'url') / filter_input(INPUT_POST,
    // 'url', FILTER_...) -- PHP's modern, commonly-recommended way to read
    // request input. Structurally invisible to phpAssign above (no
    // `$_GET[` on the line at all) and to every PHP named-taint function
    // downstream, so code using filter_input() previously got ZERO PHP
    // named-taint coverage.
    const phpFilterInput = /^\$(\w+)\s*=\s*filter_input\s*\(\s*INPUT_(?:GET|POST|COOKIE|SERVER|ENV)\s*,/.exec(line.trim());
    if (phpFilterInput) { tainted.add(phpFilterInput[1]); continue; }
    // Java/Kotlin: String url = request.getParameter("url");  or  val url = call.parameters["url"]
    const javaAssign = /\b(?:String|Long|Integer|int|long|val|var)\s+(\w+)\s*=\s*request\.getParameter\s*\(/.exec(line.trim());
    if (javaAssign) { tainted.add(javaAssign[1]); continue; }
    // Go: url := r.URL.Query().Get("url")  or  url := r.FormValue("url")  or
    // vars := mux.Vars(r)  or  id := chi.URLParam(r, "id")  or gin/echo/fiber's
    // id := c.Param("id"). Accepts both `:=` (the dominant Go form) and a
    // bare `=` (occasionally used with `var`).
    const goAssign = /\b(\w+)\s*(?::=|=)\s*(?:r\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue)\s*\(|mux\.Vars\s*\(\s*r\s*\)|chi\.URLParam\s*\(\s*r\s*,|c\.(?:Param|Params|Query|QueryParam|PostForm)\s*\()/.exec(line.trim());
    if (goAssign) { tainted.add(goAssign[1]); continue; }
    // Go: id, err := strconv.Atoi(idStr) -- narrow multi-return carve-out for
    // the single most common idiom (numeric route/query param conversion),
    // not general multi-return taint propagation. Only taints the LHS if the
    // value being converted is already tainted.
    const goStrconvAssign = /^(\w+)\s*,\s*\w+\s*:=\s*strconv\.(?:Atoi|ParseInt|ParseFloat|ParseBool)\s*\(\s*(\w+)/.exec(line.trim());
    if (goStrconvAssign && tainted.has(goStrconvAssign[2])) { tainted.add(goStrconvAssign[1]); continue; }
    // C#: var url = Request.Query["url"];
    const csAssign = /\b(?:var|string)\s+(\w+)\s*=\s*Request\.(?:Query|Form)\s*\[/.exec(line.trim());
    if (csAssign) { tainted.add(csAssign[1]); continue; }
    // C#: public IActionResult GetUser([FromRoute] int id, [FromQuery] string name)
    // Method-PARAMETER taint source, not an assignment -- [FromRoute]/
    // [FromQuery]/[FromBody]/[FromHeader]-attributed parameters are ASP.NET
    // Core's model-binding idiom for pulling untrusted route/query/body/
    // header data directly into a named parameter, with no local variable
    // assignment anywhere (unlike every branch above, which all key on
    // `= request.X`). Uses matchAll (not exec) since a single method
    // signature routinely declares more than one bound parameter on one
    // line. Same file-wide-flat-Set imprecision as every other language
    // here: two different C# methods reusing a parameter name (e.g. both
    // taking `id`) share taint state -- an accepted, pre-existing tradeoff.
    const csParams = [...line.matchAll(/\[From(?:Route|Query|Body|Header)\]\s+[\w.]+(?:<[^>]+>)?\??\s+(\w+)/g)];
    if (csParams.length > 0) { csParams.forEach(m => tainted.add(m[1])); }
    // C# implicit-binding param source -- consumed regardless of whether
    // csParams also matched on this same line (a signature can mix
    // attributed and unattributed params, e.g. `([FromBody] Dto dto, int
    // id)`), so this deliberately does NOT `continue` inside the csParams
    // branch above.
    if (pendingCSharpEntryMethod) {
      pendingCSharpEntryMethod = false;
      const sigMatch = CSHARP_SIG_PARAMS_RE.exec(line);
      if (sigMatch) {
        for (const rawParam of sigMatch[1].split(",")) {
          const p = rawParam.trim();
          if (!p || p.startsWith("[")) continue; // already-attributed param, handled above
          const m = CSHARP_SIMPLE_TYPE_PARAM_RE.exec(p);
          if (m) tainted.add(m[1]);
        }
      }
    }
    if (CSHARP_ENTRY_ATTR_LINE_RE.test(line)) { pendingCSharpEntryMethod = true; continue; }
    if (csParams.length > 0) continue;
    // Second-hop taint propagation -- var2 = <expr referencing var1>, where
    // var1 is already tainted, covers the single most common real-world
    // shape across every sink this file cares about: a command string built
    // by concatenation (command = "ping -c 1 " + host), a template literal
    // (html = `<h1>Hello ${name}</h1>`), or a value threaded through a
    // helper/library call (filePath = path.join(base, filename)). None of
    // the direct-source patterns above can see any of these since the RHS
    // isn't a literal request access. Deliberately generic (any assignment
    // referencing an already-tainted identifier propagates, regardless of
    // the operator) rather than special-casing each shape -- same "accept
    // some imprecision for better recall" tradeoff already made throughout
    // this taint tracker (no de-tainting on reassignment, no sanitizer
    // recognition). Skips comparisons (==/!=) so an `if (a == b)` line isn't
    // misread as an assignment. Order-safe since this loop runs top-to-bottom.
    // `:?=` also accepts Go's `:=` short variable declaration -- the
    // dominant Go assignment form at function scope -- in addition to the
    // plain `=` every other language here uses. Verified safe for existing
    // languages: JS/Java/C#/PHP never use a bare `:` immediately before `=`;
    // Ruby doesn't use `:=` at all; Python's only `:=` use (the walrus
    // operator) is semantically the same "assign and use" shape this
    // fallback already generalizes over. Also can't mis-fire on a Go
    // struct-literal field line (`ID: id,`) -- there's no `=` immediately
    // after that colon, so the mandatory `=` half still gates the match.
    if (tainted.size > 0) {
      const assign = /^(?:(?:const|let|var)\s+)?(\w+)\s*:?=\s*(.+?);?$/.exec(line.trim());
      if (assign && !assign[2].includes("==") && !assign[2].includes("!=") && !tainted.has(assign[1])) {
        const rhsVars = [...assign[2].matchAll(/\b(\w+)\b/g)].map(m => m[1]);
        if (rhsVars.some(v => tainted.has(v))) { tainted.add(assign[1]); continue; }
      }
    }
  }
  return tainted;
}

// Individual detector patterns — module-level compilation
const SQL_INJECTION_RE = [
  // f-string / template-literal SQL queries — require a real SQL clause
  // PAIR (SELECT...FROM, DELETE FROM, UPDATE...SET, INSERT INTO), not just
  // an isolated keyword. A single word like "from"/"where"/"update" is
  // common in plain English (e.g. "valid from {date}", "please update your
  // profile") and must not trigger this on its own.
  /f["'][^"']*\b(?:select\b[\s\S]*?\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b)[\s\S]*\{/i,
  // String concatenation + SQL clause pair, in either order
  // ("SELECT ... FROM " + var or var + " WHERE id = " + var + "...").
  /(?=[\s\S]*["']\s*\+\s*\w+)(?=[\s\S]*\b(?:select\b[\s\S]*?\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b))/i,
  /cursor\.execute\s*\(\s*(?:f["']|["'][^?])/i,
  /db\.query\s*\(\s*(?:`[^`]*\$\{|['"][^?][^'"]*\+)/i,
  /(?:execute|query)\s*\(\s*["'].*\+\s*\w/i,
  /(?:select\b[\s\S]*?\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b)[\s\S]*\$\{/i,
  /knex\.raw\s*\(`[^`]*\$\{/i,
  /sequelize\.query\s*\(\s*`[^`]*\$\{/i,
  // Ruby/Rails ActiveRecord — .where()/.find_by_sql() etc. accept a raw SQL
  // (fragment) string directly, so unlike other ORMs there's no need for a
  // full SELECT...FROM pair to appear -- interpolating a variable into the
  // string at all is the vulnerable pattern (e.g. .where("id = '#{params...}'")).
  // Found missing entirely via a real OWASP railsgoat benchmark
  // (users_controller.rb) -- every other pattern here uses ${} (JS) or is
  // otherwise ecosystem-specific; none recognize Ruby's #{} interpolation.
  // Order-agnostic (both substrings anywhere on the line, like the
  // concatenation pattern above) rather than requiring #{ to directly follow
  // the opening quote -- SQL string literals routinely wrap the interpolated
  // value in single quotes first (as in the real example above), which a
  // strict adjacency match would miss.
  /(?=[\s\S]*\.(?:where|find_by_sql|order|group|having|pluck|select|calculate)\s*\()(?=[\s\S]*#\{)/,
  // C# — SqlCommand/SqlDataAdapter constructed with concatenated SQL, or
  // .CommandText set via concatenation. Already incidentally matched by the
  // generic "..." + var concatenation entry above (verified) -- made
  // explicit/deliberate here so C# coverage is a real, documented detector.
  /(?:new\s+Sql(?:Command|DataAdapter)|\.CommandText)\s*[=(][\s\S]{0,150}?["']\s*\+\s*\w/i,
  // C#'s $"..." interpolated-string SQL query -- structurally identical gap
  // to the f-string entry above (no + operator for the generic concat
  // pattern to key on). CRITICAL: explicitly excludes EF Core's
  // FromSqlInterpolated/ExecuteSqlInterpolated -- EF's SAFE parameterized-
  // interpolation APIs, which compile the identical $"...{id}" syntax into
  // a real parameterized query (unlike FromSqlRaw/ExecuteSqlRaw, which run
  // it as literal raw SQL). Nothing about the $"..." syntax itself
  // distinguishes safe from unsafe -- only the wrapping method name does,
  // hence the leading negative lookahead rather than a syntax-level check.
  /^(?!.*(?:FromSqlInterpolated|ExecuteSqlInterpolated)).*\$["'][^"']*\b(?:select\b[\s\S]*?\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b)[\s\S]*\{/i,
];

const EVAL_EXEC_RE = [
  /\beval\s*\(/,
  /new\s+Function\s*\(/,
  /subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True/,
  /os\.system\s*\(/,
  /child_process\.exec\s*\(/,
  /\bexecSync\s*\(/,
];

// "ignoreExpiration" must be set to true to be a bypass — the bare keyword
// also appears when explicitly disabled (ignoreExpiration: false), which is
// the secure default and must NOT be flagged.
const JWT_BYPASS_RE =
  /(?:algorithms?\s*[:=]\s*\[.*["']none["']|verify\s*=\s*False|ignoreExpiration\s*[:=]\s*true|{"alg"\s*:\s*"none"}|["']?verify_signature["']?\s*:\s*False)/i;

// A hardcoded JWT/session signing secret -- unlike the SECRET_PATTERNS
// generic-word detectors above (which require the value to LOOK like a real
// random secret, to avoid flagging placeholder text), this flags ANY literal
// string assigned as a signing key regardless of how it looks: a short,
// guessable value (found via a real VAmPI benchmark: app.config['SECRET_KEY']
// = 'random') is itself the vulnerability, and even a strong-looking literal
// is still compromised the moment it's committed to source control -- best
// practice is always to load it from an environment variable / secrets
// manager, so any quoted-literal assignment here is a finding either way.
const WEAK_SIGNING_SECRET_RE = [
  // Flask/Python: app.config['SECRET_KEY'] = 'literal'  (dict-key assignment
  // shape, not a bare variable -- SECRET_PATTERNS' generic entries only
  // match `secret_key = "..."`, never `config['SECRET_KEY'] = "..."`)
  /(?:\.config|app\.config)\s*\[\s*["'](?:SECRET_KEY|JWT_SECRET_KEY|JWT_SECRET)["']\s*\]\s*=\s*["'][^"']+["']/,
  // Flask: app.secret_key = 'literal'
  /\bapp\.secret_key\s*=\s*["'][^"']+["']/,
  // Django settings.py / bare module-level constant, or JS/TS
  // const/let/var JWT_SECRET = "literal" -- the optional prefix group is
  // what makes this also match the extremely common Node.js declaration
  // style, which the bare Django-style pattern alone couldn't.
  /^\s*(?:(?:const|let|var)\s+)?(?:SECRET_KEY|JWT_SECRET_KEY|JWT_SECRET)\s*=\s*["'][^"']+["']/,
  // Node/Express (jsonwebtoken): jwt.sign(payload, 'literal', ...) / jwt.verify(token, 'literal', ...)
  /jwt\.(?:sign|verify)\s*\(\s*[^,]+,\s*["'][^"']+["']/,
  // C#: private const string JwtSecret = "literal" -- same "name+literal
  // is a finding either way" philosophy as the bare-constant pattern
  // above, just with C#'s modifier-chain prefix (public/private/internal/
  // protected, static, readonly) allowed before `const string`, and a
  // broader secret-shaped name (\w*Secret\w*/\w*SigningKey\w*) rather
  // than the exact Django/Node constant names above.
  /^\s*(?:(?:private|public|internal|protected)\s+)*(?:static\s+)?(?:readonly\s+)?const\s+string\s+\w*(?:Secret|SigningKey)\w*\s*=\s*"[^"]+"/i,
];

// PHP: hash_hmac($algo, $data, 'literal') -- same "skip an arg, require a
// bare literal at the target position" idea as the jwt.sign/verify branch
// above, just at position 3 (hash_hmac's key arg is last), length-capped so
// a long/random-looking literal doesn't also match. Its own function rather
// than an array entry because real calls routinely span several lines (one
// argument per line, the $data arg often itself a nested call) -- a
// single-line regex can't see those; same forward-window-join technique the
// cookie-insecurity branches use.
const PHP_HASH_HMAC_LITERAL_KEY_RE = /hash_hmac\s*\(\s*["'][^"']+["']\s*,[\s\S]*?,\s*["']([^"']{1,20})["']\s*\)/i;

function findWeakSigningSecretPHPHmac(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    if (!/hash_hmac\s*\(/i.test(lines[i])) continue;
    const block = lines.slice(i, Math.min(lines.length, i + 8)).join(" ");
    if (!PHP_HASH_HMAC_LITERAL_KEY_RE.test(block)) continue;
    found.push({ id:"weak-signing-secret", label:"Hardcoded JWT/Session Signing Secret", severity:"critical", line:i+1,
      detail:"Signing key is a short literal committed to source control — anyone with repo access can forge valid tokens; load it from an environment variable or secrets manager" });
  }
  return found;
}

function findWeakSigningSecret(lines: string[]): ScanIndicator[] {
  return runDetector(lines, WEAK_SIGNING_SECRET_RE, "weak-signing-secret", "Hardcoded JWT/Session Signing Secret", "critical",
    "Signing key is a literal committed to source control — anyone with repo access can forge valid tokens; load it from an environment variable or secrets manager");
}

// Java (and other statement-per-line-wrapped code) commonly splits the
// declaration from its value across two lines:
//   private static final String JWT_SECRET =
//           "literal-value";
// -- neither WEAK_SIGNING_SECRET_RE's modifier-agnostic bare-constant
// pattern nor its Java-specific field modifiers can see this, since the
// value never shares a line with the field name. Joins each line ending in
// a bare "=" with the next line before re-testing the same patterns, rather
// than duplicating them for a two-line form.
function findWeakSigningSecretSplitLine(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length - 1; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    if (!/(?:JWT_SECRET|SECRET_KEY|JWT_SECRET_KEY)\s*=\s*$/.test(lines[i].trim())) continue;
    const joined = `${lines[i].trim()} ${lines[i + 1].trim()}`;
    if (!/=\s*["'][^"']+["']/.test(joined)) continue;
    found.push({ id:"weak-signing-secret", label:"Hardcoded JWT/Session Signing Secret", severity:"critical", line:i+1,
      detail:"Signing key is a literal committed to source control — anyone with repo access can forge valid tokens; load it from an environment variable or secrets manager" });
  }
  return found;
}

const CMD_INJECTION_RE = [
  /subprocess\.(?:call|run)\s*\([^)]*f["']/,
  /os\.popen\s*\(\s*(?:f["']|[^)]*\+)/,
  /execSync\s*\(`[^`]*\$\{/,
  /child_process\.exec\s*\(`[^`]*\$\{/,
  /spawn\s*\([^,)]*\$\{[^}]+\}/,
  /\bexec\s*\(\s*`[^`]*\$\{/,
  // Java/Kotlin — Runtime.exec / ProcessBuilder built from concatenated request input
  /Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\([^)]*\+\s*request\.getParameter\s*\(/i,
  /new\s+ProcessBuilder\s*\([^)]*request\.getParameter\s*\(/i,
  // Go — exec.Command/CommandContext with a query/form/route-param-derived argument
  /exec\.Command(?:Context)?\s*\([^)]*(?:r\.(?:URL\.Query\(\)|FormValue\b|PostFormValue\b)|c\.(?:Param|Params|Query|QueryParam|PostForm)\s*\(|chi\.URLParam\s*\(\s*r\s*,)/i,
  // PHP -- guarded via a negative lookahead against escapeshellarg()/
  // escapeshellcmd() ANYWHERE on the same line: PHP's standard sanitizers
  // for exactly this sink family. Without this, shell_exec("ping -c 1 " .
  // escapeshellarg($_GET['ip'])) -- properly-sanitized, safe code -- was a
  // confirmed false positive. Line-granularity guard (matches this
  // codebase's existing guard precedent, e.g. C#'s FromSqlInterpolated
  // lookahead) -- accepted imprecision: if $_GET appears twice on one line,
  // one wrapped and one not, this suppresses both. Extended with
  // proc_open (a real, commonly-used PHP shell-invocation sink, previously
  // entirely absent from both this array and PHP_CMD_SINK_RE below).
  /(?:shell_exec|system|passthru|popen|proc_open)\s*\(\s*(?![^)]*\bescapeshell(?:arg|cmd)\s*\()[^)]*\$_(?:GET|POST|REQUEST)\b/i,
  // PHP backtick execution operator -- `` `cmd $var` `` is PHP's syntactic
  // alias for shell_exec(), a distinct syntax (no function-call token) no
  // existing regex matches. Backtick content is parsed like a double-quoted
  // string (direct $var interpolation only, no function calls inside), so
  // the escapeshellarg() guard doesn't apply the same way -- deliberately
  // NOT guarded here; sanitizing a backtick-interpolated value requires
  // pre-escaping on an earlier line, a separate problem this phase doesn't
  // attempt.
  /`[^`]*\$_(?:GET|POST|REQUEST)\b[^`]*`/,
  // Ruby — backtick/system() with interpolated params
  /`[^`]*#\{\s*params\[/,
  /\bsystem\s*\([^)]*params\[/i,
  // C#
  /Process\.Start\s*\([^)]*Request\.(?:Query|Form)\b/i,
];

const SSRF_RE = [
  /(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.)\w+/i,
  /new\s+URL\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.)\w+/i,
  /https?\.(?:get|request)\s*\(\s*(?:req\.|request\.|body\.|params\.)\w+/i,
  /got\s*\(\s*(?:req\.|body\.|params\.|query\.)\w+/i,
  /(?:needle|superagent)(?:\.(?:get|post|put|delete|patch|head))?\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.)\w+/i,
  /axios\s*\(\s*\{\s*url\s*:\s*(?:req\.|body\.|params\.)\w+/i,
  // Java/Kotlin — RestTemplate/URL/HttpClient built from request input
  /RestTemplate\s*\(\s*\)\s*\.\s*(?:getForObject|getForEntity|postForObject|exchange)\s*\([^)]*request\.getParameter\s*\(/i,
  /new\s+URL\s*\(\s*request\.getParameter\s*\(/i,
  // Go
  /http\.(?:Get|Post|Head)\s*\(\s*(?:r\.(?:URL\.Query\(\)|FormValue\b)|c\.(?:Param|Params|Query|QueryParam|PostForm)\s*\(|chi\.URLParam\s*\(\s*r\s*,)/i,
  // PHP — curl target URL from user input
  /curl_setopt\s*\(\s*\$\w+\s*,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)\b/i,
  // Python requests library
  /requests\.(?:get|post|put|delete|head)\s*\(\s*request\.(?:args|form|GET|POST)\b/i,
  // C# — HttpClient inline call with a request-derived URL argument.
  /\.(?:GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync)\s*\([^)]*Request\.(?:Query|Form)\b/i,
  /WebRequest\.Create\s*\([^)]*Request\.(?:Query|Form)\b/i,
];

const PATH_TRAVERSAL_RE = [
  /path\.(?:join|resolve)\s*\([^)]*(?:req\.|request\.|body\.|params\.|query\.)\w+/i,
  /fs\.(?:readFile|writeFile|readdir|stat|unlink|createReadStream|createWriteStream)\s*\([^)]*(?:req\.|params\.|body\.|query\.)\w+/i,
  /__dirname\s*\+\s*(?:req\.|params\.|body\.|query\.)\w+/i,
  /path\.join\s*\([^)]*['"]\.\.['"]/,
  // Java/Kotlin — File/Paths/Files built from a request-derived path segment
  /new\s+File\s*\([^)]*request\.getParameter\s*\(/i,
  /Paths\.get\s*\([^)]*request\.getParameter\s*\(/i,
  /Files\.(?:newInputStream|newOutputStream|readAllBytes|newBufferedReader|newBufferedWriter|delete)\s*\([^)]*request\.getParameter\s*\(/i,
  /new\s+FileInputStream\s*\([^)]*\+\s*request\.getParameter\s*\(/i,
  // Python — open()/os.path.join() with a request-derived component
  /\bopen\s*\([^)]*\+\s*request\.(?:args|form|GET|POST)\b/i,
  /os\.path\.join\s*\([^)]*request\.(?:args|form|GET|POST)\b/i,
  // Go
  /(?:os\.(?:Open|Create|OpenFile|ReadFile)|ioutil\.ReadFile|filepath\.Join)\s*\([^)]*(?:r\.(?:URL\.Query\(\)|FormValue\b|PostFormValue\b)|c\.(?:Param|Params|Query|QueryParam|PostForm)\s*\(|chi\.URLParam\s*\(\s*r\s*,)/i,
  // PHP
  /(?:fopen|file_get_contents|readfile|include|include_once|require|require_once)\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST)\b/i,
  // Ruby
  /File\.(?:read|open|new|delete)\s*\([^)]*\bparams\[/i,
  // C# — broadened beyond the original File.*-only, Request.Query/Form-only
  // entry with Path.Combine. The [FromRoute]/[FromQuery] attribute form is
  // deliberately NOT added here -- attributes annotate parameters, they
  // don't appear as call arguments, so that coverage comes entirely from
  // extractTaintedVars' attribute-parameter fix feeding the named-taint
  // function below, not from a new inline entry.
  /File\.(?:ReadAllText|ReadAllBytes|OpenRead|OpenWrite|Delete)\s*\([^)]*Request\.(?:Query|Form)\b/i,
  /Path\.Combine\s*\([^)]*Request\.(?:Query|Form)\b/i,
];

const PROTO_POLLUTION_RE = [
  /\w+\[(?:req\.|params\.|body\.|query\.)\w+\]\s*=/i,
  /Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.|body\.|params\.|query\.)\w+/i,
  /\{\s*\.\.\.\s*(?:req\.body|req\.query|req\.params)\s*\}/i,
  /(?:_|lodash)\.merge\s*\([^)]*(?:req\.|body\.)\w+/i,
  /deepmerge\s*\([^)]*(?:req\.|body\.)\w+/i,
];

const INSECURE_RANDOM_RE = [
  /(?:token|secret|key|password|salt|nonce|csrf|iv)\s*=.*Math\.random\(\)/i,
  /Math\.random\(\).*(?:token|secret|key|auth|session|cookie)/i,
  // Java/Kotlin/C# — java.util.Random / System.Random are not CSPRNGs
  /(?:token|secret|key|password|salt|nonce|csrf|iv)\w*\s*=.*\bnew\s+Random\s*\(\s*\)/i,
  // Python
  /(?:token|secret|key|password|salt|nonce|csrf|iv)\w*\s*=.*\brandom\.random\s*\(\s*\)/i,
  // Go — math/rand instead of crypto/rand. Matches real rand.<Func>() usage,
  // not the literal import-path string "math/rand" (the previous version of
  // this entry required that exact substring, which only appears in an
  // import statement and never in actual call sites -- confirmed dead code
  // via a real benchmark). Only the zero-arg rand.Int() form is matched
  // (not bare "rand.Int(" with arguments) because crypto/rand.Int(reader,
  // max) shares the same call syntax under the same package name "rand" but
  // always takes 2 arguments -- requiring empty parens specifically avoids
  // flagging the secure package. The other function names (Intn/Int31/
  // Int63/Float32/Float64/Perm/Shuffle) don't exist in crypto/rand at all,
  // so they're unambiguous on their own.
  /(?:token|secret|key|password|salt|nonce|csrf|iv)\w*\s*(?::=|=).*\brand\.(?:Int\(\)|Intn|Int31\b|Int63\b|Int31n|Int63n|Float32|Float64|Perm|Shuffle)\s*\(?/i,
  // PHP
  /(?:token|secret|key|password|salt|nonce|csrf|iv)\w*\s*=.*\b(?:rand|mt_rand)\s*\(/i,
  // Ruby
  /(?:token|secret|key|password|salt|nonce|csrf|iv)\w*\s*=.*\bKernel\.rand\b|\brand\s*\(\s*\d/i,
];

const REDOS_RE = [
  /new\s+RegExp\s*\(\s*(?:req\.|body\.|params\.|query\.)\w+/i,
  // Nested quantifiers — group containing +/* immediately re-quantified with
  // +/*, e.g. /(a+)+/ or /(\w+)*/ — the classic catastrophic-backtracking shape.
  // Requires the quantifier to follow the group's closing paren directly, so
  // ordinary regex literals like /(?:pub\s+)?struct\s+\w+/ don't match.
  /\/\([^)]*[+*][^)]*\)[+*]/,
];

const OPEN_REDIRECT_RE = [
  /res\.redirect\s*\(\s*(?:req\.query|req\.body|req\.params)[\.[]/i,
  /(?:redirect|location)\s*\(\s*(?:req\.|body\.|params\.|query\.)\w+/i,
  /window\.location(?:\.href)?\s*=\s*(?:params|query|search|url)\b/i,
  // Java/Kotlin — response.sendRedirect(request.getParameter(...))
  /response\.sendRedirect\s*\([^)]*request\.getParameter\s*\(/i,
  // Python Flask/Django
  /\bredirect\s*\(\s*request\.(?:args|GET|form)\b/i,
  // PHP
  /header\s*\(\s*["']Location:\s*["']\s*\.\s*\$_(?:GET|POST|REQUEST)\b/i,
  // Ruby on Rails
  /redirect_to\s+params\[/i,
  // Go — http.Redirect(w, r, target, ...) with a request-derived target
  // inline as the 3rd argument.
  /http\.Redirect\s*\([^,]+,[^,]+,\s*(?:r\.(?:URL\.Query\(\)|FormValue\b|PostFormValue\b)|c\.(?:Param|Params|Query|QueryParam|PostForm)\s*\(|chi\.URLParam\s*\(\s*r\s*,)/i,
];

// Require one side of the comparison to be clearly request-derived
// (req./body./params./query./request./headers.) — without this, the old
// unconstrained `\w+` fallback matched ANY equality comparison where either
// side merely contained "key"/"hash"/"token" as a substring, e.g.
// `cacheKey === expectedKey` or `hashCode === obj.hashCode()`, which have
// nothing to do with timing-safe credential comparison. "key" alone was
// dropped — it's too generic a name even when paired with taint (e.g. a
// non-secret object/map key looked up from a query param).
// Keyword allows a \w* prefix/suffix so compound names (storedPassword,
// expectedToken) still match — only the bare "key" alone was dropped from
// the keyword list since it's too generic even with the taint requirement.
const TIMING_ATTACK_RE = [
  /(?:token|secret|password|hash|hmac|signature)\s*(?:===|==)\s*(?:req\.|body\.|params\.|query\.|request\.|headers\.)\w+/i,
  /(?:req\.|body\.|params\.|request\.|headers\.)[\w.]+\s*(?:===|==)\s*\w*(?:token|secret|password|hash|hmac|signature)\w*/i,
];

// Plaintext password storage — a request-derived value assigned directly to
// a .password/.passwd/.pwd attribute with no hashing function anywhere on
// the line. Found via a real VAmPI benchmark (api_views/users.py: `user.password
// = request_data.get('password')`, then straight to db.session.commit() —
// no bcrypt/argon2/pbkdf2/hashlib call anywhere in the function). Requires
// confirmed taint (inline request.*/req.*/body.* or a variable already
// tracked by extractTaintedVars) rather than flagging every bare assignment,
// so a value hashed on an earlier line and stored in a plain-looking
// variable name isn't penalized just for lacking a hash call on this
// specific line — same taint-confirmation discipline as the named-taint
// detectors elsewhere in this file.
const HASH_FUNCTION_NEARBY_RE = /bcrypt|scrypt|argon2?|pbkdf2|generate_password_hash|check_password_hash|hashlib|password_hash|\bcrypt\s*\(/i;
const PASSWORD_ASSIGN_SINK_RE = /\.(?:password|passwd|pwd)\s*=(?!=)/i;

function findPlaintextPasswordStorage(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (!PASSWORD_ASSIGN_SINK_RE.test(line)) continue;
    if (HASH_FUNCTION_NEARBY_RE.test(line)) continue;
    const inlineTaint = /(?:request\.|req\.|body\.)\w+/i.test(line);
    const namedTaint = tainted.size > 0 && [...line.matchAll(/\b(\w+)\b/g)].some(m => tainted.has(m[1]));
    if (!inlineTaint && !namedTaint) continue;
    found.push({ id:"plaintext-password-storage", label:"Plaintext Password Storage", severity:"high", line:i+1,
      detail:"Password assigned directly from request input with no hashing — store only a salted hash (bcrypt/argon2/pbkdf2), never the plaintext value" });
  }
  return found;
}

// C#: a call-shaped variant of the plaintext-password check above --
// Database.SavePassword(username, password) rather than a field
// assignment (.password = value). Different shape, same id/severity and
// the same HASH_FUNCTION_NEARBY_RE-absence gate.
const CSHARP_PASSWORD_CALL_SINK_RE = /\.(?:Save|Set|Store|Update)\w*Password\w*\s*\(/i;

function findPlaintextPasswordStorageCSharpCall(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (!CSHARP_PASSWORD_CALL_SINK_RE.test(line)) continue;
    if (HASH_FUNCTION_NEARBY_RE.test(line)) continue;
    const namedTaint = tainted.size > 0 && [...line.matchAll(/\b(\w+)\b/g)].some(m => tainted.has(m[1]));
    if (!namedTaint) continue;
    found.push({ id:"plaintext-password-storage", label:"Plaintext Password Storage", severity:"high", line:i+1,
      detail:"Password passed directly from request input into a storage call with no hashing — store only a salted hash (bcrypt/argon2/pbkdf2), never the plaintext value" });
  }
  return found;
}

// SSTI — server-side template injection
const SSTI_RE = [
  /(?:ejs|nunjucks|pug|jade)\.render(?:File)?\s*\(\s*(?:req|request)\.(?:query|body|params)\b/i,
  /(?:Handlebars|Mustache|swig)\.compile\s*\(\s*(?:req|request)\.(?:query|body|params)\b/i,
  /Template\s*\(\s*(?:req|request)\.(?:query|body|params)\b/i,
  /render_template_string\s*\(\s*(?:request\.data|request\.json|request\.args)/i,
  /env\.from_string\s*\(\s*(?:request\.|req\.)\w+/i,
  /\.render\s*\(\s*(?:req|request)\.(?:body|query)\.\w+/i,
  // Java — Velocity/FreeMarker evaluating a string built from request input
  /Velocity\.evaluate\s*\([^)]*request\.getParameter\s*\(/i,
  /new\s+Template\s*\([^)]*request\.getParameter\s*\(/i,
  // Go — text/template parsing a query/form-derived string
  /template\.(?:New|Must)\s*\([^)]*\)\s*\.\s*Parse\s*\(\s*r\.(?:URL\.Query\(\)|FormValue\b)/i,
];

// HTTP Header Injection (CRLF injection into response headers)
const HEADER_INJECT_RE = [
  /res\.(?:setHeader|header)\s*\([^,]+,\s*(?:req|request)\.(?:query|body|params|headers)\b/i,
  /res\.setHeader\s*\(\s*["'](?:Location|Refresh|Set-Cookie)["'],\s*(?:req|request)\./i,
  /response\.headers\s*\[["'][\w-]+["']\]\s*=\s*(?:req|request)\./i,
  /headers\s*\[(?:req|request)\.(?:query|body|params)\b/i,
  // Java/Kotlin
  /response\.(?:setHeader|addHeader)\s*\([^,]+,\s*request\.getParameter\s*\(/i,
];

// Weak CORS policy
const WEAK_CORS_RE = [
  /Access-Control-Allow-Origin["']?\s*[,:]\s*["']?\*/,
  // Python/Flask dict-bracket assignment: response.headers["Access-Control-
  // Allow-Origin"] = "*" -- the comma/colon forms above don't match this
  // shape (a "]" then "=" follows the header name, not "," or ":").
  /Access-Control-Allow-Origin["']?\s*\]\s*=\s*["']?\*/,
  /cors\s*\(\s*\{\s*origin\s*:\s*["']\*["']/,
  /res\.(?:header|setHeader)\s*\(\s*["']Access-Control-Allow-Origin["'],\s*["']\*["']\)/,
  /app\.use\s*\(\s*cors\s*\(\s*\)\s*\)/,
  /allowedOrigins\s*=\s*\[\s*["']\*["']/,
  // Java Spring
  /@CrossOrigin\s*\(\s*origins\s*=\s*["']\*["']/i,
  /\.allowedOrigins\s*\(\s*["']\*["']\s*\)/i,
];

// IDOR — insecure direct object reference (no ownership check)
const IDOR_RE = [
  /\.findById\s*\(\s*(?:req|request)\.(?:params|query|body)\b/i,
  /\.findOne\s*\(\s*\{[^}]{0,80}_?id\s*:\s*(?:req|request)\.(?:params|query|body)\b/i,
  /(?:db|conn|pool|client)\.(?:get|find|query)\s*\(\s*(?:req|request)\.(?:params|query)\b/i,
  /SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+(?:id|user_id|owner_id)\s*=\s*\$\{(?:req|request)\./i,
  /\bgetById\s*\(\s*(?:req|request)\.(?:params|query)\b/i,
];

// XPath injection — user input concatenated into an XPath expression
const XPATH_INJECT_RE = [
  /XPathExpression\s*\w*\s*=[\s\S]{0,200}\+\s*request\.getParameter\s*\(/i,
  /\.evaluate\s*\(\s*["'][^"']*["']\s*\+\s*(?:req|request)\.(?:query|body|params)\b/i,
  /\.evaluate\s*\(\s*["'][^"']*["']\s*\+\s*request\.getParameter\s*\(/i,
  /xpath\.evaluate\s*\([^)]*\+\s*(?:request\.|req\.)/i,
];

// CSRF protection explicitly disabled at the framework level — a high-
// confidence positive pattern, unlike detecting "missing" protection
// (which regex can't do reliably without producing constant false positives).
const CSRF_DISABLED_RE = [
  /\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)/i,   // Spring Security: http.csrf().disable()
  /@csrf_exempt/i,                                 // Django
  /CSRF_ENABLED\s*=\s*False/i,                     // Flask-WTF
  /protect_from_forgery\s+with:\s*:null_session/i, // Rails, common misconfiguration
];

// Sensitive data exposed in URL query string
const SENSITIVE_URL_RE = [
  /[?&](?:password|passwd|pwd|secret|token|api_key|apikey|access_token|auth_token|private_key)=/i,
  /(?:url|href|src|location)\s*=.*[?&](?:password|secret|token|key|auth)=/i,
  /res\.redirect\s*\([^)]*[?&](?:password|token|secret|key)=/i,
];

// NoSQL injection ($where, $regex, raw model.find with user input)
const NOSQL_INJECT_RE = [
  /\$where\s*:\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/i,
  /\.find(?:One|Many)?\s*\(\s*\{\s*\$(?:where|expr|function)\s*:/i,
  /\$regex\s*:\s*(?:req|request)\.(?:query|body|params)\b/i,
  /(?:Model|collection|db)\s*\.find\s*\(\s*(?:req|request)\.(?:body|query)\b/i,
  /\.where\s*\(\s*`[^`]*\$\{(?:req|request)\./i,
  /\$(?:lt|gt|lte|gte|ne|in|nin|not)\s*:\s*(?:req|request)\.(?:query|body|params)\b/i,
];

// Verbose error disclosure (stack traces / raw messages to client)
// Removed overly-broad patterns:
//   - error.message in res.send(): used in error middleware to pass clean messages
//   - JSON.stringify(error): common in server-side logging, not a client disclosure
const VERBOSE_ERROR_RE = [
  /(?:res\.json|res\.send|res\.status\s*\(\s*\d+\s*\)\.json)\s*\([^)]*(?:error|err|e)\.stack\b/i,
  /(?:NextResponse|Response)\.json\s*\([^)]*(?:error|err|e)\.(?:stack|message)\b/i,
  /(?:message|detail|error|stack)\s*:\s*(?:error|err|e)\.stack\b/,
  // Sending the entire error object (not just message) in a response body
  /(?:res\.json|res\.send)\s*\(\s*(?:error|err|e)\s*\)/i,
  /(?:res\.status\s*\([^)]+\)\s*\.json|NextResponse\.json)\s*\(\s*(?:\{[^}]*\})?\s*(?:error|err|e)\s*\)/i,
  // Java — stack trace or exception message written directly to the servlet response
  /(?:e|ex|exception)\.printStackTrace\s*\(\s*response\.getWriter\s*\(\s*\)\s*\)/i,
  /response\.getWriter\s*\(\s*\)\.print\s*\([^)]*(?:e|ex|exception)\.getMessage\s*\(\s*\)/i,
  // Python Flask — exception message returned in a JSON response
  /jsonify\s*\(\s*\{[^}]*(?:error|message)\s*:\s*str\s*\(\s*e\s*\)/i,
  // PHP — a secret-named variable concatenated directly into a thrown
  // exception's own message (throw new Exception("Database password: " .
  // $dbPassword)). A different shape from every entry above (those are all
  // about a CAUGHT exception's .stack/.message being sent back in an HTTP
  // response); this is about the sensitive value being baked into the
  // message itself at construction time -- confirmed no existing pattern
  // in any language did this.
  /throw\s+new\s+\w*Exception\s*\([^)]*\.\s*\$(?:password|passwd|pwd|secret|token|api[_]?key|dbPassword)\b/i,
];

// GraphQL injection (user input in query template)
const GRAPHQL_INJECT_RE = [
  /gql`[^`]*\$\{(?:req|request)\.(?:query|body|params)\b/i,
  /graphql\s*\(\s*\w+\s*,\s*(?:req|request)\.(?:body|query)\.\w+/i,
  /`\s*(?:query|mutation)\s+\w+[^`]*\$\{(?:req|request)\./i,
  /graphqlQuery\s*=\s*`[^`]*\$\{/,
  /makeExecutableSchema\s*\(\s*\{[^}]*typeDefs\s*:\s*`[^`]*\$\{(?:req|request)\./i,
];

// GraphQL introspection/IDE left enabled -- a real, common, single-line
// misconfiguration across every major GraphQL server library (graphene/
// flask-graphql's graphiql=, Apollo Server's introspection:/playground:,
// graphql-yoga, Ariadne, Django's GRAPHIQL setting). Exposing this in
// production hands an attacker the complete schema (every type, field,
// mutation and argument) for reconnaissance with zero effort. Found missing
// entirely via a real Damn Vulnerable GraphQL Application benchmark
// (core/views.py registers a /graphiql route with graphiql=True).
const GRAPHQL_INTROSPECTION_RE = [
  /\bgraphiql\s*[:=]\s*True\b/i,
  /\bgraphiql\s*:\s*true\b/,
  /\bintrospection\s*:\s*true\b/,
  /\bplayground\s*:\s*true\b/,
  /\bGRAPHIQL\s*=\s*True\b/,
];

// XML External Entity injection
const XXE_RE = [
  /new\s+DOMParser\s*\(\s*\)[\s\S]{0,100}\.parseFromString\s*\(\s*(?:req|request)\./i,
  /DocumentBuilderFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,300}setFeature\s*\([^)]*FEATURE_SECURE_PROCESSING)/,
  /SAXParserFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,300}setFeature)/,
  /XMLReaderFactory\.createXMLReader\s*\(\s*\)/,
  // StAX (XMLInputFactory) -- a third Java XML parsing API alongside DOM and
  // SAX above, missing entirely until a real-WebGoat benchmark (XXE lesson's
  // CommentsCache.parseXml()) surfaced that it uses this one specifically.
  // Same "no nearby hardening call" shape as the DocumentBuilderFactory
  // check; XMLInputFactory defaults IS_SUPPORTING_EXTERNAL_ENTITIES to true.
  /XMLInputFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,300}setProperty\s*\([^)]*ACCESS_EXTERNAL_DTD)/,
  /etree\.(?:fromstring|parse)\s*\(\s*(?:req|request)\./i,
  /lxml\.etree\.(?:fromstring|parse)\s*\(\s*(?:req|request)\./i,
  /libxml\.parseXml(?:String)?\s*\(\s*(?:req|request)\./i,
  // JS/Node XML libraries (libxml2-wasm, libxmljs/libxmljs2) require the
  // caller to explicitly opt into entity expansion and DTD loading — unlike
  // the Java parsers above, which are unsafe unless hardened, these default
  // safe and only become XXE-vulnerable when a caller turns these flags on.
  // Found via a real OWASP Juice Shop benchmark (lib/xml.ts intentionally
  // sets both flags for its XXE challenges).
  /XML_PARSE_NOENT|XML_PARSE_DTDLOAD/,
  /\b(?:noent|dtdload|resolveExternalEntities|loadExternalEntities)\s*:\s*true\b/i,
  // PHP — DOMDocument::loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD). PHP's
  // own libxml constant spelling, distinct from the generic XML_PARSE_*
  // names above.
  /LIBXML_NOENT|LIBXML_DTDLOAD/,
];

// LDAP injection (filter construction with user input)
const LDAP_INJECT_RE = [
  /(?:searchFilter|filter|ldapFilter)\s*[:=]\s*`[^`]*\$\{/i,
  /(?:searchFilter|filter)\s*[:=]\s*['"][^'"]*['"]\s*\+\s*(?:req|request)\./i,
  /(?:ldap|ad)\.(?:search|query|findUser|bind)\s*\([^)]*\+\s*(?:req|request)\./i,
  /\(\s*(?:cn|uid|mail|sAMAccountName)\s*=\s*['"]?\s*\+\s*(?:req|request)\./i,
  /\.search(?:Entries)?\s*\([^)]*(?:req|request)\.(?:query|body|params)\b/i,
  // Java — javax.naming.directory DirContext.search with a concatenated filter
  /(?:DirContext|InitialDirContext)[\s\S]{0,200}\.search\s*\([^)]*\+\s*request\.getParameter\s*\(/i,
  /String\s+\w*[Ff]ilter\w*\s*=\s*["'][^"']*["']\s*\+\s*request\.getParameter\s*\(/i,
];

// Insecure file upload (missing MIME/size validation)
const FILE_UPLOAD_RE = [
  /multer\s*\(\s*\{\s*dest\s*:(?![^}]*(?:fileFilter|limits))[^}]*\}\s*\)/,
  /multer\s*\(\s*\{(?![^}]*fileFilter)[^}]*storage\s*:/,
  /upload\.single\s*\([^)]+\)(?![\s\S]{0,200}(?:mimetype|fileFilter|MIME_TYPES|allowedTypes))/,
  /req\.files?\.\w+\.mv\s*\(/i,
  /busboy[\s\S]{0,100}on\s*\(\s*['"]file['"](?![\s\S]{0,500}(?:mimetype|content.?type|size))/i,
];

// Race condition: TOCTOU (check then act without atomic guarantee)
// Detected as: existsSync/access/stat on same path followed by read/write/delete
const TOCTOU_SOURCE_RE = /\bfs\.(?:existsSync|accessSync|statSync)\s*\(([^)]+)\)/;
const TOCTOU_SINK_RE   = /\bfs\.(?:readFile|writeFile|unlink|rename|rmdir|mkdir|open|createReadStream|createWriteStream)(?:Sync)?\s*\(/;

// XSS patterns
const XSS_RE = [
  /\.innerHTML\s*[+=]\s*(?!\s*["']<(?:div|span|p|strong|em|br)\b)/,
  /\.innerHTML\s*=\s*`[^`]*\$\{/,
  /document\.write\s*\(\s*(?!["'])/,
  /document\.writeln\s*\(\s*(?!["'])/,
  /dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*__html\s*:/,
  /\.outerHTML\s*=\s*\w/,
  /\$\([^)]+\)\.html\s*\(\s*\w+\s*\)/,
  /\.insertAdjacentHTML\s*\([^,]+,\s*\w+/,
  /\bbypassSecurityTrustHtml\s*\(/i,
  // C# Razor — Html.Raw()/@Html.Raw() and Response.Write() are the only two
  // dangerous escape hatches in a template engine that auto-encodes output
  // by default. Deliberately NOT a broad interpolation-based pattern like
  // the JS entries above, which would misfire on completely safe,
  // auto-encoded @Model.Name-style Razor output.
  /(?:@?Html\.Raw|Response\.Write)\s*\([^)]*Request\.(?:Query|Form)\b/i,
  // PHP -- echo/print of an unescaped $_GET/$_POST/$_REQUEST/$_COOKIE
  // value is PHP's classic reflected-XSS shape. Guarded via a negative
  // lookahead against htmlspecialchars()/htmlentities() ANYWHERE on the
  // same statement (up to the next ';') -- PHP's idiomatic, very common
  // safe pattern (echo htmlspecialchars($_GET['name']);) must never be
  // flagged. Mirrors the escapeshellarg-guard/FromSqlInterpolated-guard
  // precision discipline established elsewhere in this phase.
  /\b(?:echo|print)\b(?![^;]*\b(?:htmlspecialchars|htmlentities)\s*\()[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b/i,
];

// Insecure deserialization
const INSECURE_DESERIAL_RE = [
  /pickle\.loads?\s*\(\s*(?!b["'])/,
  /yaml\.load\s*\([^,)]+\)(?!\s*,\s*Loader\s*=\s*yaml\.(?:Safe|Full)Loader)/,
  /jsonpickle\.decode\s*\(/,
  /unserialize\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)/i,
  /Marshal\.load\s*\(\s*(?:params|request|body)/,
  /ObjectInputStream\s*\(\s*(?:request|socket)\.getInputStream/,
  /node-serialize\b.*\.unserialize/,
  /serialize-javascript.*eval\s*\(/i,
  // Go — encoding/gob decoding data sourced from an HTTP request body or a
  // raw network connection: gob can instantiate any type registered via
  // gob.Register() from the wire data, so network-controlled data selecting
  // an unexpected concrete type is an RCE-adjacent risk analogous to Python
  // pickle / Java ObjectInputStream above. encoding/json is deliberately
  // NOT included -- json.Unmarshal into a typed struct/interface{}/
  // map[string]interface{} carries no equivalent arbitrary-type-
  // instantiation risk in Go; there's no built-in "gadget chain" the way
  // pickle/ObjectInputStream have. A real, language-specific scoping
  // judgment, not an oversight.
  /gob\.NewDecoder\s*\(\s*[^)]*\.(?:Body|Conn)\b[^)]*\)\s*\.\s*Decode\s*\(/i,
  // C# — JavaScriptSerializer with a SimpleTypeResolver (or any custom
  // *TypeResolver) opts into polymorphic type instantiation from the
  // payload, the same class of risk as Json.NET's TypeNameHandling below.
  // The default no-arg constructor -- new JavaScriptSerializer() -- is safe
  // and structurally cannot match, since this requires content inside the
  // parens.
  /new\s+JavaScriptSerializer\s*\(\s*new\s+\w*TypeResolver\s*\(/,
];

// Weak cryptography
const WEAK_CRYPTO_RE = [
  /createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/i,
  /hashlib\.(?:md5|sha1)\s*\(\s*(?:password|passwd|pwd)/i,
  // PHP — bare global md5()/sha1() functions, same password-context gate
  // as the Python hashlib entry above (PHP variables carry a $ sigil).
  /\b(?:md5|sha1)\s*\(\s*\$(?:password|passwd|pwd)/i,
  /(?:MD5|SHA1|SHA128)\.new\s*\(/,
  /createCipheriv\s*\(\s*["'](?:des|rc4|rc2|bf|blowfish|idea)[-\w]*["']/i,
  /createCipheriv\s*\(\s*["']aes-\d+-ecb["']/i,
  /Cipher\.getInstance\s*\(\s*["'](?:DES|AES\/ECB|RC4|Blowfish)/i,
  /Digest\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']/i,
  /bcrypt\.(?:hash|hashSync)\s*\([^,]+,\s*[1-9]\s*[,)]/,  // rounds < 10
  // Go — crypto/md5, crypto/sha1 (broken hashes); crypto/des, crypto/rc4
  // (broken ciphers). Flat match, no "used for password" context gate --
  // matches this file's established precedent above (only the Python
  // hashlib entry is context-gated, and it's the minority pattern here).
  /\bmd5\.(?:New|Sum)\s*\(/,
  /\bsha1\.(?:New|Sum)\s*\(/,
  /\bdes\.(?:NewCipher|NewTripleDESCipher)\s*\(/,
  /\brc4\.NewCipher\s*\(/,
  // C# — System.Security.Cryptography's MD5/SHA1 factory methods and weak
  // cipher-mode/provider shapes. Flat match, no password-context gate,
  // same posture as the Go entries above.
  /\bMD5\.Create\s*\(\s*\)/,
  /\bSHA1\.Create\s*\(\s*\)/,
  /\bDES\.Create\s*\(\s*\)/,
  /CipherMode\.ECB\b/,
  /new\s+(?:MD5|SHA1|TripleDES)CryptoServiceProvider\s*\(/,
];

// PII in logs — requires the keyword to appear as a property/variable access
// (e.g. user.email, req.body.password) or inside template interpolation
// (${email}), not just anywhere in the call's arguments. The old patterns
// matched purely descriptive log messages that merely mention the word, e.g.
// console.log("sending email notification") or console.log("checking auth
// status"), with no actual PII value being logged at all.
const PII_LOG_RE = [
  /(?:console|logger|log)\.\w+\s*\([^)]*[\w\])]\.(?:email|mail)\b[^)]*\)/i,
  /(?:console|logger|log)\.\w+\s*\([^)]*[\w\])]\.(?:password|passwd|pwd|token|secret|authToken|accessToken|apiKey)\b[^)]*\)/i,
  /(?:console|logger|log)\.\w+\s*\([^)]*[\w\])]\.ssn\b[^)]*\)/i,
  /(?:console|logger|log)\.\w+\s*\([^)]*[\w\])]\.(?:creditCard|ccNum|cvv|cardNumber)\b[^)]*\)/i,
  /(?:console|logger|log)\.\w+\s*\([^)]*[\w\])]\.phone(?:Number)?\b[^)]*\)/i,
  /(?:console|logger|log)\.\w+\s*\([^)]*\$\{[^}]*\b(?:email|password|token|secret|ssn|phone|creditCard|cvv)\b[^}]*\}[^)]*\)/i,
  /logging\.(?:info|debug|warning|error)\s*\([^)]*[\w\])]\.(?:password|email|token|ssn)\b[^)]*\)/i,
  // Go — log.Printf("... password=%s ...", password): sensitive data
  // appears as a labeled %verb in the format string, not a .propertyName
  // access the way every entry above requires. Matches a log.* call whose
  // format-string literal contains a sensitive field name immediately
  // followed by = or : (a labeled field), the idiomatic Go structured-ish
  // logging shape.
  /\blog\.(?:Printf|Println|Print|Fatalf|Panicf)\s*\(\s*["'][^"']*\b(?:password|passwd|token|secret|api[_]?key|ssn|credit.?card)\b\s*[=:]/i,
  // PHP — error_log("... " . $password): PHP has no `.` property-access
  // operator, so the sensitive-named token here is a bare $-sigil
  // variable string-concatenated into the message, not a .propertyName
  // access -- same precision bar as every entry above (must be
  // concatenated in, not merely present anywhere in the call).
  /\berror_log\s*\(\s*[^)]*\.\s*\$(?:password|passwd|pwd|token|secret|ssn|api[_]?key)\b/i,
];

// Mass assignment
const MASS_ASSIGN_RE = [
  /new\s+\w+Model\s*\(\s*(?:req\.body|request\.body)\s*\)/i,
  /\w+\.create\s*\(\s*(?:req\.body|request\.body)\s*\)/i,
  /\w+\.update\s*\(\s*(?:req\.body|request\.body)\s*[,)]/i,
  /Model\.objects\.create\s*\(\s*\*\*(?:request\.data|request\.POST)/i,
  /User\.new\s*\(\s*(?:params|user_params)\s*\)/i,
  /attributes\s*=\s*(?:params|request\.params)\b/i,
  /\.update_attributes\s*\(\s*(?:params|user_params|request\.params)/i,
  // Rails strong-parameters bypass -- these two methods exist specifically
  // to opt out of the permit()-based allow-listing that's otherwise Rails'
  // default protection against mass assignment, so their mere presence is a
  // strong, low-noise signal on its own (no taint tracing needed). Found
  // missing entirely via a real OWASP railsgoat benchmark (both instances
  // are explicitly commented "VULNERABILITY: mass assignment" in-repo).
  /\.permit!\s*(?:\(\s*\))?/,
  /\.to_unsafe_h\b/,
];

// ── Detector helper: run patterns over lines, return deduped indicators ────────

// A single-line JS/TS regex literal definition, e.g.:
//   /eval\s*\(\s*require\s*\(/,               // eval(require(...))
//   const RE = /node-serialize\b.*\.unserialize/;
const REGEX_LITERAL_LINE_RE = /^(?:[\w$.\s]+=\s*)?\/(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\\n])+\/[a-z]*\s*[,;]?\s*(?:\/\/.*)?$/;

// Documentation/example fields used for fix-suggestion snippets — these hold
// illustrative "before"/"after" code as data, not executable source.
const EXAMPLE_FIELD_LINE_RE = /^["']?(?:code_before|code_after|example|sample|snippet|before|after)["']?\s*:/i;

// Lines that look like they CONTAIN a security-sensitive pattern but aren't
// actually executable code in this position — comments, regex/pattern
// definitions, and doc/example snippet fields. Security detectors should
// not fire on these, since matching here is almost always a false positive
// (e.g. a security scanner's own detector source, or fix-suggestion examples).
function isNonExecutableLine(line: string): boolean {
  const t = line.trim();
  if (t.startsWith("//") || t.startsWith("#") || t.startsWith("*") || t.startsWith("/*")) return true;
  if (REGEX_LITERAL_LINE_RE.test(t)) return true;
  if (EXAMPLE_FIELD_LINE_RE.test(t)) return true;
  return false;
}

function runDetector(
  lines: string[],
  patterns: RegExp[],
  id: string,
  label: string,
  severity: ScanIndicator["severity"],
  detail: string,
  opts?: { skipComments?: boolean; requireTaint?: boolean },
): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();

  for (const re of patterns) {
    for (let i = 0; i < lines.length; i++) {
      if (seen.has(i)) continue;
      if (isNonExecutableLine(lines[i])) continue;
      if (!re.test(lines[i])) continue;
      if (opts?.requireTaint && !hasTaintNearby(lines, i)) continue;
      seen.add(i);
      found.push({ id, label, severity, line: i + 1, detail });
    }
  }
  return found;
}

// Java's native .properties config format (db.password=supersecret123) has
// no string-quoting syntax at all, so every generic word-keyed pattern above
// — which all require a quoted ["'] value — silently misses it entirely.
// Applied only to .properties files themselves, so it can't fire on
// `String password = someVariable;`-shaped code in .java/.js/etc, where an
// unquoted right-hand side is almost always a reference, not a literal.
const PROPERTIES_SECRET_RE =
  /^\s*[\w.]*(?:password|passwd|pwd|secret|token|api[._]?key)[\w.]*\s*=\s*(\S{8,})\s*$/i;

function findSecrets(lines: string[], file_path: string): ScanIndicator[] {
  if (DEMO_DATA_FILE_RE.test(file_path)) return [];
  const isTestFile = TEST_FILE_RE.test(file_path);
  const isPropertiesFile = /\.properties$/i.test(file_path);
  const found: ScanIndicator[] = [];
  for (const { re, label, severity, genericValue } of SECRET_PATTERNS) {
    // Generic word-keyed patterns are suppressed in test/fixture/mock files —
    // branded/structural patterns still run there since a real leaked key is
    // real regardless of which file it's in.
    if (genericValue && isTestFile) continue;
    for (let i = 0; i < lines.length; i++) {
      if (isNonExecutableLine(lines[i])) continue;
      if (isPlaceholderSecretLine(lines[i])) continue;
      const m = re.exec(lines[i]);
      if (!m) continue;
      if (genericValue && !looksLikeRealSecret(m[1] ?? "")) continue;
      found.push({ id:"hardcoded-secret", label:`Hardcoded ${label}`, severity, line:i+1, detail:`${label} detected` });
    }
  }
  if (isPropertiesFile && !isTestFile) {
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].trim().startsWith("#")) continue;
      const m = PROPERTIES_SECRET_RE.exec(lines[i]);
      if (!m || !looksLikeRealSecret(m[1])) continue;
      found.push({ id:"hardcoded-secret", label:"Hardcoded credential in .properties file", severity:"critical",
        line:i+1, detail:"Unquoted key=value credential in a Java properties file — move to an environment variable or secrets manager" });
    }
  }
  return found;
}

function findHighEntropySecrets(lines: string[], file_path: string): ScanIndicator[] {
  if (DEMO_DATA_FILE_RE.test(file_path)) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isNonExecutableLine(line)) continue;
    if (!ENTROPY_CRED_RE.test(line)) continue;
    ENTROPY_STRING_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = ENTROPY_STRING_RE.exec(line)) !== null) {
      const s = m[1];
      if (s.length < 20 || /\s/.test(s) || /^https?:\/\//.test(s)) continue;
      // Skip if already caught by known patterns
      if (SECRET_PATTERNS.some(p => p.re.test(line))) continue;
      const e = shannonEntropy(s);
      if (e > 4.2) {
        found.push({ id:"high-entropy-secret", label:"High-Entropy Secret", severity:"critical", line:i+1,
          detail:`${e.toFixed(1)} bits/char entropy in credential context — likely a hardcoded key or token` });
        break; // one per line is enough
      }
    }
  }
  return found;
}

function findXSS(lines: string[]): ScanIndicator[] {
  return runDetector(lines, XSS_RE, "xss", "Cross-Site Scripting (XSS)", "critical",
    "Unsanitised HTML written to DOM — sanitize with DOMPurify or avoid innerHTML");
}

function findInsecureDeserialization(lines: string[]): ScanIndicator[] {
  return runDetector(lines, INSECURE_DESERIAL_RE, "insecure-deserialization",
    "Insecure Deserialization", "critical",
    "Deserializing untrusted data — can lead to RCE (use json.loads or SafeLoader)");
}

// Go two-step: dec := gob.NewDecoder(r.Body); ... ; dec.Decode(&x) -- the
// chained one-liner in INSECURE_DESERIAL_RE only catches
// gob.NewDecoder(...).Decode(...) on a single line; this covers the decoder
// being assigned first, a very common Go style. Does NOT fire on a
// gob.NewDecoder reading a local, trusted file (e.g. a cache) -- the source
// regex below requires the NewDecoder argument itself to end in
// `.Body`/`.Conn`, which a plain file handle variable never does (verified
// directly).
const GO_GOB_NEWDECODER_ASSIGN_RE = /\b(\w+)\s*:=\s*gob\.NewDecoder\s*\(\s*[^)]*\.(?:Body|Conn)\b/;
const GO_DECODE_CALL_RE = /\b(\w+)\s*\.\s*Decode\s*\(/;

function findInsecureDeserializationGoDecoder(lines: string[]): ScanIndicator[] {
  const decoders = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = GO_GOB_NEWDECODER_ASSIGN_RE.exec(lines[i]);
    if (m) decoders.add(m[1]);
  }
  if (decoders.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = GO_DECODE_CALL_RE.exec(lines[i]);
    if (!m || !decoders.has(m[1])) continue;
    found.push({ id:"insecure-deserialization", label:"Insecure Deserialization", severity:"critical", line:i+1,
      detail:`gob.Decoder '${m[1]}' built from a request body/connection — arbitrary registered-type decode from untrusted data; validate/restrict types or switch to encoding/json` });
  }
  return found;
}

// C# — BinaryFormatter/ObjectStateFormatter.Deserialize instantiates an
// arbitrary CLR type from the wire data, the direct equivalent of Python
// pickle/Java ObjectInputStream (RCE-adjacent, not merely data-corruption
// risk). Microsoft has deprecated/obsoleted BinaryFormatter as a security
// risk since .NET 5+ -- flat "constructor nearby + Deserialize call" match,
// no taint-source verification required (same posture as pickle.loads()
// above). Gated on a nearby constructor (not a bare ".Deserialize(" flat
// match) so this doesn't flag System.Text.Json's completely safe
// JsonSerializer.Deserialize<T>(...) calls, which share the same method name.
const CSHARP_DESERIAL_CTOR_RE = /new\s+(?:BinaryFormatter|ObjectStateFormatter)\s*\(/;
const CSHARP_DESERIAL_SINK_RE = /\.(?:Deserialize|UnsafeDeserialize)\s*\(/;

function findInsecureDeserializationCSharp(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    if (!CSHARP_DESERIAL_SINK_RE.test(lines[i])) continue;
    const windowStart = Math.max(0, i - 10);
    const window = lines.slice(windowStart, i + 1);
    if (!window.some(l => CSHARP_DESERIAL_CTOR_RE.test(l))) continue;
    found.push({ id:"insecure-deserialization", label:"Insecure Deserialization", severity:"critical", line:i+1,
      detail:"BinaryFormatter/ObjectStateFormatter deserializes data into an arbitrary CLR type from the wire — Microsoft has deprecated BinaryFormatter as a security risk; use System.Text.Json with a known DTO type instead" });
  }
  return found;
}

// C# — JsonConvert.DeserializeObject/JsonSerializer.Deserialize with
// TypeNameHandling.{All,Auto,Objects,Arrays} set nearby (not necessarily
// same line -- settings are typically built on a JsonSerializerSettings
// object a few lines before being passed in). Plain JsonConvert.
// DeserializeObject<T>(json) with NO TypeNameHandling override anywhere
// nearby is safe and must not be flagged -- mirrors the Go encoding/json
// reasoning above: deserializing into a statically-typed DTO has no
// gadget-chain risk.
const CSHARP_TYPENAME_HANDLING_RE = /TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)\b/;
const CSHARP_JSON_DESERIAL_SINK_RE = /(?:JsonConvert\.DeserializeObject|JsonSerializer\.Deserialize)\s*\(/;

function findInsecureDeserializationCSharpJsonNet(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    if (!CSHARP_JSON_DESERIAL_SINK_RE.test(lines[i])) continue;
    const windowStart = Math.max(0, i - 15);
    const window = lines.slice(windowStart, i + 1);
    if (!window.some(l => CSHARP_TYPENAME_HANDLING_RE.test(l))) continue;
    found.push({ id:"insecure-deserialization", label:"Insecure Deserialization", severity:"critical", line:i+1,
      detail:"JSON deserialization with TypeNameHandling.All/Auto lets the payload specify the concrete .NET type to instantiate — a known Json.NET RCE gadget-chain vector; remove TypeNameHandling or restrict it with a custom SerializationBinder allowlist" });
  }
  return found;
}

// PHP named-taint unserialize(): $data = $_COOKIE['data']; $obj =
// unserialize($data); -- INSECURE_DESERIAL_RE's entry only matches the
// tainted superglobal literally inline. PHP Object Injection (POI) via a
// class's __wakeup()/__destruct() gadget chain (CWE-502) was PHP's most
// RCE-relevant sink with the weakest coverage of any area in this phase --
// brought in line with the depth given to Go's gob decoder / C#'s
// BinaryFormatter work above.
const PHP_UNSERIALIZE_SINK_RE = /\bunserialize\s*\(\s*\$(\w+)\s*\)/i;

function findNamedTaintDeserializationPHP(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    const m = PHP_UNSERIALIZE_SINK_RE.exec(line);
    if (!m || !tainted.has(m[1])) continue;
    if (INSECURE_DESERIAL_RE.some(r => r.test(line))) continue;
    found.push({ id:"insecure-deserialization", label:"Insecure Deserialization", severity:"critical", line:i+1,
      detail:`Tainted variable '$${m[1]}' passed to unserialize() — a crafted payload can instantiate arbitrary classes and trigger __wakeup()/__destruct() gadget chains (PHP Object Injection); use json_decode() instead, or unserialize()'s 'allowed_classes' option` });
  }
  return found;
}

// PHP unserialize() fed by a wrapped/decoded value -- unserialize(
// base64_decode($_COOKIE['data'])) is an extremely common real-world
// idiom for cookie/session-embedded serialized data (raw serialized bytes
// don't survive a cookie/URL round-trip unencoded). Neither the inline
// entry above nor PHP_UNSERIALIZE_SINK_RE (requires a bare $var) can see
// this. Handles both direct-superglobal-inline and named-var-inside-the-
// wrapper in one regex via an alternation.
const PHP_UNSERIALIZE_WRAPPED_RE =
  /\bunserialize\s*\(\s*(?:base64_decode|gzuncompress|gzinflate|gzdecode)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)\s*\[|\$(\w+)\b)/i;

function findDeserializationPHPWrapped(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = PHP_UNSERIALIZE_WRAPPED_RE.exec(lines[i]);
    if (!m) continue;
    if (m[1] && !tainted.has(m[1])) continue; // named-var branch requires it be tainted; direct-superglobal branch (m[1] undefined) always hits
    found.push({ id:"insecure-deserialization", label:"Insecure Deserialization", severity:"critical", line:i+1,
      detail:"Tainted, decoded/decompressed value passed to unserialize() — a crafted payload can instantiate arbitrary classes and trigger __wakeup()/__destruct() gadget chains (PHP Object Injection); use json_decode() instead" });
  }
  return found;
}

// PHP phar:// stream-wrapper deserialization (CWE-502, "phar
// deserialization" gadget-chain class) -- a genuinely different attack
// shape from unserialize() above: PHP implicitly deserializes a phar
// archive's metadata when ANY of a wide set of ordinary-looking file
// functions touches a phar:// path, including read-only-looking ones
// (file_exists(), is_file(), getimagesize()) -- no unserialize() call
// appears anywhere in the vulnerable code. Confirmed zero prior coverage.
// A small, literal-substring-only regex rather than deferred -- the
// "phar://" scheme string essentially never appears by accident, so
// false-positive risk is very low, and this is a real, well-known,
// zero-existing-coverage RCE-adjacent risk class. NOT attempting named-
// taint tracing of the scheme itself (would require tracking string-
// concatenation into a URI-scheme position) -- deliberately narrow for
// phase 1. Severity capped at "high" (not "critical"), same reasoning as
// findPHPFileInclusion: real trigger depends on a gadget class existing in
// the app, unobservable by a text scan.
const PHP_PHAR_SINK_RE = /\b(?:file_exists|is_file|is_dir|file_get_contents|file_put_contents|fopen|getimagesize|filemtime|filesize|unlink|copy|md5_file|hash_file)\s*\(\s*[^)]*phar:\/\//i;

function findPHPPharDeserialization(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    if (!PHP_PHAR_SINK_RE.test(lines[i])) continue;
    found.push({ id:"insecure-deserialization", label:"PHP Object Injection via phar:// Stream Wrapper", severity:"high", line:i+1,
      detail:"An ordinary file operation on a phar:// URI triggers implicit deserialization of the archive's metadata — even read-only-looking calls (file_exists, getimagesize, etc.) can trigger PHP Object Injection if the path is attacker-influenced; validate/reject the phar:// scheme before any file operation on a user-supplied path" });
  }
  return found;
}

function findWeakCrypto(lines: string[]): ScanIndicator[] {
  return runDetector(lines, WEAK_CRYPTO_RE, "weak-crypto", "Weak Cryptography", "high",
    "MD5/SHA1/DES/ECB — broken algorithms or insufficient bcrypt rounds; use SHA-256+/AES-CBC/bcrypt≥12");
}

function findPIIInLogs(lines: string[]): ScanIndicator[] {
  return runDetector(lines, PII_LOG_RE, "pii-in-logs", "PII in Logs", "high",
    "Sensitive user data (email/password/SSN/card) passed to logger — strip before logging");
}

function findMassAssignment(lines: string[]): ScanIndicator[] {
  return runDetector(lines, MASS_ASSIGN_RE, "mass-assignment", "Mass Assignment", "high",
    "Raw request body passed to model constructor — allow-list fields explicitly");
}

// PHP: foreach ($data as $key => $value) { $obj->$key = $value; } -- a
// dynamic property-write LOOP, structurally unlike every entry in
// MASS_ASSIGN_RE above (all single-line call/constructor regexes). No
// existing loop-aware detector anywhere in this file to reuse wholesale,
// but three precedents establish the right shape -- a trigger line plus a
// bounded forward scan (TOCTOU's source->sink scan, C#'s XXE ctor->
// hardening-window check, the cookie branches' window-join): trigger on
// the foreach header (capturing its key/value loop variable names), then
// scan forward a few lines for a dynamic property write using that exact
// captured key variable.
const PHP_MASS_ASSIGN_FOREACH_RE = /foreach\s*\(\s*\$\w+\s+as\s+\$(\w+)\s*=>\s*\$(\w+)\s*\)/;

function findMassAssignmentPHPLoop(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = PHP_MASS_ASSIGN_FOREACH_RE.exec(lines[i]);
    if (!m) continue;
    const keyVar = m[1];
    const dynamicWriteRe = new RegExp(`\\$\\w+\\s*->\\s*\\$${keyVar}\\b`);
    for (let j = i + 1; j < Math.min(lines.length, i + 6); j++) {
      if (isNonExecutableLine(lines[j])) continue;
      if (dynamicWriteRe.test(lines[j])) {
        found.push({ id:"mass-assignment", label:"Mass Assignment", severity:"high", line:i+1,
          detail:`Loop writes every key from "$${keyVar}" directly onto an object property (\`->$${keyVar}\`) with no allow-list — a request-derived array can set any property, including ones the caller was never meant to control` });
        break;
      }
    }
  }
  return found;
}

// C#: a [FromBody]-bound complex-type parameter passed WHOLE (a bare
// identifier, not a specific property) into a write-shaped call --
// Database.UpdateProfile(profile) where `profile` is `[FromBody]
// UserProfile profile`, binding every field (including ones like IsAdmin/
// Role the caller was never meant to set) with no allow-listing. A
// different shape from MASS_ASSIGN_RE's array above (those all key on a
// literal req.body/request.body token appearing directly at the call
// site; C#'s bound object is just a plain variable name, which needs
// extractTaintedVars' existing [FromBody]-attribute recognition to
// resolve instead).
const CSHARP_MASS_ASSIGN_SINK_RE = /\.(?:Add|Update|Create|Save|Insert)\w*\s*\(\s*(\w+)\s*\)/;

function findMassAssignmentCSharp(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  const found: ScanIndicator[] = [];
  if (tainted.size === 0) return found;
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = CSHARP_MASS_ASSIGN_SINK_RE.exec(lines[i]);
    if (!m) continue;
    if (!tainted.has(m[1])) continue;
    found.push({ id:"mass-assignment", label:"Mass Assignment", severity:"high", line:i+1,
      detail:`"${m[1]}" is bound whole from the request body and passed directly into a persistence call — allow-list fields explicitly instead of binding the entire object` });
  }
  return found;
}

function findSQLInjection(lines: string[]): ScanIndicator[] {
  return runDetector(lines, SQL_INJECTION_RE, "sql-injection", "SQL Injection", "critical",
    "Query built with string interpolation — use parameterised queries");
}

// PHP-specific: unlike JS/Python, PHP interpolates a bare $var or {$var}
// directly inside a double-quoted string with no operator at all -- so none
// of SQL_INJECTION_RE's concatenation/template-literal patterns ever match
// PHP's most common vulnerable shape: $query = "SELECT ... WHERE id = '$id'";
// Found missing entirely via a real OWASP DVWA benchmark (sqli/source/low.php).
const SQL_CLAUSE_PAIR_RE = /\b(?:select\b[\s\S]*?\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b)\b/i;

function findSQLInjectionPHPInterpolated(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (!SQL_CLAUSE_PAIR_RE.test(line)) continue;
    if (SQL_INJECTION_RE.some(r => r.test(line))) continue; // already caught inline
    const hit = [...line.matchAll(/\{?\$(\w+)\}?/g)].find(m => tainted.has(m[1]));
    if (!hit) continue;
    found.push({ id:"sql-injection", label:"SQL Injection", severity:"critical", line:i+1,
      detail:`Tainted variable '$${hit[1]}' interpolated directly into a SQL string — use parameterised queries (mysqli_prepare/PDO)` });
  }
  return found;
}

// PHP multi-line SQL query building: $query = "SELECT ..."; $query .= $id;
// mysqli_query($conn, $query); -- none of these three lines individually
// has BOTH a SQL-clause pair AND a tainted $var (the shape
// findSQLInjectionPHPInterpolated requires), because PHP's idiomatic `.=`
// operator builds the query across multiple statements. Not caught by
// extractTaintedVars' generic second-hop propagation fallback either --
// that fallback's `^(\w+)\s*:?=\s*` anchor can never match a PHP line
// ($-prefixed variables, and `.=` isn't a recognized operator). Two-phase,
// mirroring findSQLInjectionJavaTainted/CSharpTainted's sink-list+window
// shape: (1) track which $vars are "SQL query builders" (assigned a
// literal with a real clause pair, or later `.=`-concatenated with an
// already-tainted variable); (2) flag when a tainted query-builder
// variable reaches a query-execution sink.
const PHP_QUERY_LITERAL_ASSIGN_RE = /^\$(\w+)\s*=\s*["']/;
const PHP_QUERY_CONCAT_RE = /^\$(\w+)\s*\.=\s*.*\$(\w+)/;
const PHP_QUERY_EXEC_SINK_RE = /\b(?:mysqli_query|mysql_query|pg_query)\s*\(\s*\$\w+\s*,\s*\$(\w+)\s*\)|->\s*(?:query|exec)\s*\(\s*\$(\w+)\s*\)/;

function findSQLInjectionPHPMultilineBuild(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const queryVars = new Set<string>();
  const taintedQueryVars = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i].trim();
    const lit = PHP_QUERY_LITERAL_ASSIGN_RE.exec(line);
    if (lit && SQL_CLAUSE_PAIR_RE.test(line)) { queryVars.add(lit[1]); continue; }
    const cat = PHP_QUERY_CONCAT_RE.exec(line);
    if (cat && queryVars.has(cat[1])) {
      const rhsVars = [...line.matchAll(/\$(\w+)/g)].map(m => m[1]).filter(v => v !== cat[1]);
      if (rhsVars.some(v => tainted.has(v))) taintedQueryVars.add(cat[1]);
    }
  }
  if (taintedQueryVars.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (SQL_INJECTION_RE.some(r => r.test(line))) continue;
    if (SQL_CLAUSE_PAIR_RE.test(line) && [...line.matchAll(/\{?\$(\w+)\}?/g)].some(m => tainted.has(m[1]))) continue; // already caught by findSQLInjectionPHPInterpolated
    const m = PHP_QUERY_EXEC_SINK_RE.exec(line);
    const varName = m?.[1] ?? m?.[2];
    if (!varName || !taintedQueryVars.has(varName)) continue;
    found.push({ id:"sql-injection", label:"SQL Injection", severity:"critical", line:i+1,
      detail:`Query variable '$${varName}' built via multi-line concatenation ('.=') with tainted input then executed — use a parameterised query (mysqli_prepare/PDO) instead` });
  }
  return found;
}

// Go: fmt.Sprintf building a real SQL string (SELECT...FROM/INSERT INTO/
// UPDATE...SET/DELETE FROM) with a tainted argument -- Go's idiomatic
// query-building shape, invisible to SQL_INJECTION_RE's `+`-concatenation/
// template-literal patterns since Sprintf has no `+` or `${}` on the line.
// Mirrors findSQLInjectionPHPInterpolated's structure exactly. Go's OWN
// safe, idiomatic parameterized query -- db.Query("...WHERE id=?", id) --
// has no fmt.Sprintf call anywhere on the line, so this structurally
// cannot match it (verified directly, not assumed).
const GO_SPRINTF_SQL_RE = /fmt\.Sprintf\s*\(\s*["`][^"`]*%[svd][^"`]*["`]\s*,\s*([^)]+)\)/i;

function findSQLInjectionGoSprintf(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (!SQL_CLAUSE_PAIR_RE.test(line)) continue;
    if (SQL_INJECTION_RE.some(r => r.test(line))) continue; // already caught inline
    const m = GO_SPRINTF_SQL_RE.exec(line);
    if (!m) continue;
    const args = [...m[1].matchAll(/\b(\w+)\b/g)].map(a => a[1]);
    const hit = args.find(a => tainted.has(a));
    if (!hit) continue;
    found.push({ id:"sql-injection", label:"SQL Injection", severity:"critical", line:i+1,
      detail:`Tainted variable '${hit}' interpolated into a SQL string via fmt.Sprintf — use a parameterised query instead (db.Query("...WHERE id=?", ${hit}))` });
  }
  return found;
}

function findEvalExec(lines: string[]): ScanIndicator[] {
  return runDetector(lines, EVAL_EXEC_RE, "eval-exec", "Arbitrary Code Execution", "critical",
    "eval/exec/Function constructor — severe RCE risk", { skipComments: true });
}

function findJwtBypass(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    if (JWT_BYPASS_RE.test(lines[i]))
      found.push({ id:"jwt-none-alg", label:"JWT None Algorithm", severity:"critical", line:i+1,
        detail:"JWT configured to accept 'none' algorithm — signature bypass" });
  }
  return found;
}

function findCommandInjection(lines: string[]): ScanIndicator[] {
  return runDetector(lines, CMD_INJECTION_RE, "command-injection", "Command Injection", "critical",
    "User input interpolated into shell command");
}

// Python subprocess with shell=True and a tainted variable -- the classic
// real-world Python command-injection shape (subprocess.check_output(cmd,
// shell=True) where cmd was built from request input, often via string
// concatenation on an earlier line: command = "ping -c 1 " + host). None of
// CMD_INJECTION_RE's Python entries require shell=True or accept a bare
// variable; they only match an inline f-string/concatenation directly in
// the call. shell=True is the specific flag that makes this dangerous (it
// invokes a real shell, enabling command chaining via ;/&&/|), so requiring
// it keeps this detector precise rather than flagging every subprocess call.
const PYTHON_SUBPROCESS_SHELL_RE = /subprocess\.(?:check_output|check_call|call|run|Popen)\s*\(\s*(\w+)\s*(?:,[^)]*)?shell\s*=\s*True/;

function findNamedTaintCommandInjectionPython(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = PYTHON_SUBPROCESS_SHELL_RE.exec(lines[i]);
    if (!m || !tainted.has(m[1])) continue;
    found.push({ id:"command-injection", label:"Command Injection", severity:"critical", line:i+1,
      detail:`Tainted variable '${m[1]}' passed to subprocess with shell=True — use a list of arguments and shell=False, or shlex.quote()` });
  }
  return found;
}

// PHP named-variable command injection: $target = $_REQUEST['ip']; ...
// shell_exec('ping ' . $target) -- CMD_INJECTION_RE's PHP entry only matches
// $_GET/$_POST/$_REQUEST literally inline inside the call, never a variable
// that already carries the taint from an earlier line via PHP's `.`
// concatenation operator (as opposed to JS's `+` or template literals, which
// CMD_INJECTION_RE's other entries do cover). Found missing entirely via a
// real OWASP DVWA benchmark (exec/source/low.php). Bare "exec(" is excluded
// unless it's a real PHP shell_exec-style call (i.e. not preceded by "."),
// so this doesn't collide with the extremely common regex.exec()/array.exec()
// method-call idiom in JS/TS.
// Deliberately does NOT include a bare backtick-pair alternative here (the
// way the fully-inline CMD_INJECTION_RE entry above does, scoped to
// requiring $_GET/$_POST/$_REQUEST literally inside the backticks) -- an
// UNSCOPED `` `[^`]*` `` pattern would match any JS/TS template literal,
// a real cross-language false-positive risk (e.g. Angular's `$scope`/
// jQuery's `$el` naming convention combined with an unrelated backtick
// string elsewhere in the same file could coincidentally satisfy the
// tainted-$var extraction below). The named-taint backtick case (a
// PHP variable pre-assigned, then used inside backticks) is a rarer
// real-world pattern than the fully-inline superglobal case CMD_INJECTION_RE
// already covers, so this is a deliberate, bounded recall trade-off, not
// an oversight.
const PHP_CMD_SINK_RE = /\b(?:shell_exec|system|passthru|popen|proc_open)\s*\(|(?<!\.)\bexec\s*\(/i;
const PHP_ESCAPESHELL_GUARD_RE = /\bescapeshell(?:arg|cmd)\s*\(/i;

function findNamedTaintCommandInjectionPHP(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (!PHP_CMD_SINK_RE.test(line)) continue;
    if (PHP_ESCAPESHELL_GUARD_RE.test(line)) continue; // escapeshellarg()/escapeshellcmd() -- safe
    if (CMD_INJECTION_RE.some(r => r.test(line))) continue; // already caught inline
    const hit = [...line.matchAll(/\$(\w+)/g)].find(m => tainted.has(m[1]));
    if (!hit) continue;
    found.push({ id:"command-injection", label:"Command Injection", severity:"critical", line:i+1,
      detail:`Tainted variable '$${hit[1]}' flows into a shell command — use escapeshellarg()/escapeshellcmd() or an argument array` });
  }
  return found;
}

// Node child_process named-taint: exec(command)/execSync(command) where
// command was built on an earlier line (often via the concatenation/
// template-literal propagation extractTaintedVars now tracks). CMD_INJECTION_RE
// only matches an inline template literal directly in the call. Bare "exec"/
// "spawn" require a negative lookbehind for a preceding "." so this doesn't
// collide with the common regex.exec()/array.exec() method-call idiom --
// execSync/spawnSync have no such common collision and don't need the guard.
const JS_CMD_SINK_RE = /\b(?:execSync|spawnSync)\s*\(\s*(\w+)\b|(?<!\.)\b(?:exec|spawn)\s*\(\s*(\w+)\b/;

function findNamedTaintCommandInjectionJS(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    const m = JS_CMD_SINK_RE.exec(line);
    const ident = m?.[1] ?? m?.[2];
    if (!ident || !tainted.has(ident)) continue;
    if (CMD_INJECTION_RE.some(r => r.test(line))) continue; // already caught inline
    found.push({ id:"command-injection", label:"Command Injection", severity:"critical", line:i+1,
      detail:`Tainted variable '${ident}' flows into a shell command — use execFile()/spawn() with an argument array instead of a shell string` });
  }
  return found;
}

// Go named-taint command injection: cmd := exec.Command("ping", host) where
// host was assigned from request input on an earlier line -- the inline
// CMD_INJECTION_RE Go entry only matches the tainted call as an argument
// directly in the exec.Command(...) call itself.
//
// Note on Go's real risk model: exec.Command/CommandContext invoke the
// target binary directly via execve, NOT a shell -- unlike subprocess(
// shell=True)/os.popen/shell_exec/backtick invocation (the shapes every
// other CMD_INJECTION_RE entry targets), a tainted *argument* here cannot
// inject shell metacharacters into a new shell. The real risk is argument/
// flag injection, or genuine shell injection if the command itself is
// "sh"/"bash" with "-c". This is a pre-existing scope decision already
// baked into the shipped inline Go entry above, reused as-is here.
const GO_CMD_SINK_RE = [
  /exec\.Command\s*\(\s*[^,)]+(?:,\s*([^)]+))?\)/,
  /exec\.CommandContext\s*\(\s*[^,]+,\s*[^,)]+(?:,\s*([^)]+))?\)/,
];

function findNamedTaintCommandInjectionGo(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (CMD_INJECTION_RE.some(r => r.test(line))) continue; // already caught inline
    for (const re of GO_CMD_SINK_RE) {
      const m = re.exec(line);
      if (!m || !m[1]) continue;
      const args = [...m[1].matchAll(/\b(\w+)\b/g)].map(a => a[1]);
      const hit = args.find(a => tainted.has(a));
      if (!hit) continue;
      found.push({ id:"command-injection", label:"Command Injection", severity:"critical", line:i+1,
        detail:`Tainted variable '${hit}' passed as an argument to exec.Command — validate/allowlist the value (exec.Command does not spawn a shell, but a crafted argument can still act as an unexpected flag or path)` });
      break;
    }
  }
  return found;
}

// Server-side reflected XSS: res.send(html)/res.write(html) where html is a
// raw string built from request input (often via the concatenation/template-
// literal propagation extractTaintedVars now tracks) and returned directly
// as the HTTP response body -- a completely different sink from XSS_RE's
// client-side DOM patterns (innerHTML/document.write), which this doesn't
// overlap with at all. Any framework that returns raw, un-templated HTML
// built from request data is vulnerable regardless of whether a browser's
// DOM APIs are involved.
const EXPRESS_HTML_RESPONSE_SINK_RE = /\bres\.(?:send|write|end)\s*\(\s*(\w+)\s*\)/;

function findNamedTaintReflectedXSS(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    const m = EXPRESS_HTML_RESPONSE_SINK_RE.exec(line);
    if (!m || !tainted.has(m[1])) continue;
    if (XSS_RE.some(r => r.test(line))) continue; // already caught inline
    found.push({ id:"xss", label:"Reflected XSS", severity:"critical", line:i+1,
      detail:`Tainted variable '${m[1]}' returned directly as the HTTP response body — sanitize/escape or use a templating engine with auto-escaping` });
  }
  return found;
}

// Named-taint path traversal: path.join(base, filename)/path.resolve(...)
// where filename is a tainted variable (as opposed to PATH_TRAVERSAL_RE's
// inline-only req./request. pattern). Mirrors PATH_TRAVERSAL_RE's own
// precedent of flagging the join() call itself as the vulnerable sink,
// without needing to trace all the way to a downstream fs/sendFile call.
const JS_PATH_JOIN_RE = /\bpath\.(?:join|resolve)\s*\(([^)]+)\)/;
// A second sink shape found missing via direct verification testing: a path
// built via plain string concatenation (no path.join() at all -- filePath =
// "/var/data/" + filename) fed straight into an fs.* call. JS_PATH_JOIN_RE
// only catches the path.join() wrapper form; this catches the fs sink
// directly when its sole/first argument is a bare tainted variable.
const JS_FS_SINK_RE = /\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|stat|statSync)\s*\(\s*(\w+)\b/;

function findNamedTaintPathTraversalJS(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (PATH_TRAVERSAL_RE.some(r => r.test(line))) continue; // already caught inline

    const joinMatch = JS_PATH_JOIN_RE.exec(line);
    if (joinMatch) {
      const args = [...joinMatch[1].matchAll(/\b(\w+)\b/g)].map(a => a[1]);
      const hit = args.find(a => tainted.has(a));
      if (hit) {
        found.push({ id:"path-traversal", label:"Path Traversal", severity:"critical", line:i+1,
          detail:`Tainted variable '${hit}' joined into a file path — resolve and validate the result stays within the intended base directory` });
        continue;
      }
    }

    const fsMatch = JS_FS_SINK_RE.exec(line);
    if (fsMatch && tainted.has(fsMatch[1])) {
      found.push({ id:"path-traversal", label:"Path Traversal", severity:"critical", line:i+1,
        detail:`Tainted variable '${fsMatch[1]}' passed directly to a filesystem call — resolve and validate the result stays within the intended base directory` });
    }
  }
  return found;
}

// Named-taint open redirect: res.redirect(target) where target is a tainted
// variable, as opposed to OPEN_REDIRECT_RE's inline-only req.query/req.body
// pattern.
const JS_REDIRECT_SINK_RE = /\bres\.redirect\s*\(\s*(\w+)\s*\)/;

function findNamedTaintOpenRedirectJS(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    const m = JS_REDIRECT_SINK_RE.exec(line);
    if (!m || !tainted.has(m[1])) continue;
    if (OPEN_REDIRECT_RE.some(r => r.test(line))) continue; // already caught inline
    found.push({ id:"open-redirect", label:"Open Redirect", severity:"medium", line:i+1,
      detail:`Tainted variable '${m[1]}' used as a redirect target — validate against an allowlist of known paths/origins` });
  }
  return found;
}

// Go named-taint open redirect: target := r.URL.Query().Get("next");
// http.Redirect(w, r, target, http.StatusFound) -- the dominant real-world
// shape (target assigned on an earlier line, not inline as the 3rd
// argument), which the inline OPEN_REDIRECT_RE entry can't see. Mirrors
// findNamedTaintOpenRedirectJS exactly.
const GO_REDIRECT_SINK_RE = /\bhttp\.Redirect\s*\([^,]+,[^,]+,\s*(\w+)\s*,/;

function findNamedTaintOpenRedirectGo(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    const m = GO_REDIRECT_SINK_RE.exec(line);
    if (!m || !tainted.has(m[1])) continue;
    if (OPEN_REDIRECT_RE.some(r => r.test(line))) continue; // already caught inline
    found.push({ id:"open-redirect", label:"Open Redirect", severity:"medium", line:i+1,
      detail:`Tainted variable '${m[1]}' used as a redirect target — validate against an allowlist of known paths/origins` });
  }
  return found;
}

function findSSRF(lines: string[]): ScanIndicator[] {
  return runDetector(lines, SSRF_RE, "ssrf", "Server-Side Request Forgery", "critical",
    "User-controlled URL in HTTP request — validate against allowlist or use SSRF-safe library");
}

function findPathTraversal(lines: string[]): ScanIndicator[] {
  return runDetector(lines, PATH_TRAVERSAL_RE, "path-traversal", "Path Traversal", "critical",
    "User input in file path — resolve and validate against base directory");
}

// Go named-taint path traversal, mirroring findNamedTaintPathTraversalJS's
// exact shape: a tainted variable joined into a path via filepath.Join, or
// passed directly to a filesystem call, on a DIFFERENT line than the inline
// PATH_TRAVERSAL_RE Go entry can see.
const GO_PATH_JOIN_RE = /\bfilepath\.Join\s*\(([^)]+)\)/;
const GO_FS_SINK_RE = /\b(?:os\.(?:Open|Create|OpenFile|ReadFile)|ioutil\.ReadFile)\s*\(\s*(\w+)\b/;

function findNamedTaintPathTraversalGo(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (PATH_TRAVERSAL_RE.some(r => r.test(line))) continue; // already caught inline

    const joinMatch = GO_PATH_JOIN_RE.exec(line);
    if (joinMatch) {
      const args = [...joinMatch[1].matchAll(/\b(\w+)\b/g)].map(a => a[1]);
      const hit = args.find(a => tainted.has(a));
      if (hit) {
        found.push({ id:"path-traversal", label:"Path Traversal", severity:"critical", line:i+1,
          detail:`Tainted variable '${hit}' joined into a file path via filepath.Join — resolve and validate the result stays within the intended base directory` });
        continue;
      }
    }
    const fsMatch = GO_FS_SINK_RE.exec(line);
    if (fsMatch && tainted.has(fsMatch[1])) {
      found.push({ id:"path-traversal", label:"Path Traversal", severity:"critical", line:i+1,
        detail:`Tainted variable '${fsMatch[1]}' passed directly to a filesystem call — resolve and validate the result stays within the intended base directory` });
    }
  }
  return found;
}

// C# named-taint path traversal, mirroring findNamedTaintPathTraversalGo's
// exact shape: a tainted variable joined into a path via Path.Combine, or
// passed directly to a filesystem call, on a different line than the
// inline PATH_TRAVERSAL_RE C# entries can see.
const CSHARP_PATH_COMBINE_RE = /\bPath\.Combine\s*\(([^)]+)\)/;
const CSHARP_FS_SINK_RE = /\b(?:File\.(?:ReadAllText|ReadAllBytes|OpenRead|OpenWrite|Delete|WriteAllText|WriteAllBytes)|Directory\.(?:GetFiles|Delete)|PhysicalFile)\s*\(\s*(\w+)\b/;

function findNamedTaintPathTraversalCSharp(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (PATH_TRAVERSAL_RE.some(r => r.test(line))) continue; // already caught inline

    const joinMatch = CSHARP_PATH_COMBINE_RE.exec(line);
    if (joinMatch) {
      const args = [...joinMatch[1].matchAll(/\b(\w+)\b/g)].map(a => a[1]);
      const hit = args.find(a => tainted.has(a));
      if (hit) {
        found.push({ id:"path-traversal", label:"Path Traversal", severity:"critical", line:i+1,
          detail:`Tainted variable '${hit}' joined into a file path via Path.Combine — resolve and validate the result stays within the intended base directory` });
        continue;
      }
    }
    const fsMatch = CSHARP_FS_SINK_RE.exec(line);
    if (fsMatch && tainted.has(fsMatch[1])) {
      found.push({ id:"path-traversal", label:"Path Traversal", severity:"critical", line:i+1,
        detail:`Tainted variable '${fsMatch[1]}' passed directly to a filesystem call — resolve and validate the result stays within the intended base directory` });
    }
  }
  return found;
}

// PHP named-taint path traversal: $file = $_GET['file']; fopen($file, 'r');
// -- PATH_TRAVERSAL_RE's PHP entry only matches the superglobal literally
// inline. Mirrors findNamedTaintPathTraversalGo/CSharp's shape.
//
// OVERLAP DECISION (deliberate): this sink list intentionally includes
// include/include_once/require/require_once, which ALSO fire under
// findPHPFileInclusion's named-taint tier (id "file-inclusion") for the
// exact same line/variable. Kept as-is: "file-inclusion" communicates the
// LFI/RFI code-execution framing (allow_url_include), "path-traversal"
// communicates the broader arbitrary-file-read/write framing -- both are
// independently actionable classifications of the same call, matching how
// this codebase already treats the pre-existing include()/require()
// dual-finding as legitimate rather than a bug. Not de-duplicated.
const PHP_PATH_SINK_RE = /\b(?:fopen|file_get_contents|readfile|include|include_once|require|require_once)\s*\(?\s*\$(\w+)\b/i;

function findNamedTaintPathTraversalPHP(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (PATH_TRAVERSAL_RE.some(r => r.test(line))) continue;
    const m = PHP_PATH_SINK_RE.exec(line);
    if (!m || !tainted.has(m[1])) continue;
    found.push({ id:"path-traversal", label:"Path Traversal", severity:"critical", line:i+1,
      detail:`Tainted variable '$${m[1]}' passed to a filesystem call — resolve and validate the result stays within the intended base directory` });
  }
  return found;
}

// Zip Slip — a distinct path-traversal taint source (CWE-22) from the
// request-parameter cases above: the tainted value is a ZIP archive entry's
// own name, which the archive's creator fully controls, so a crafted entry
// like "../../etc/cron.d/x" escapes the intended extraction directory unless
// the joined path is canonicalized and checked. Found missing entirely via a
// real WebGoat benchmark (pathtraversal/ProfileZipSlip.java) — PATH_TRAVERSAL_RE
// only recognizes req./request.-derived taint, never a zip entry's getName().
// Requires corroborating zip-extraction context nearby to avoid flagging the
// same File(dir, x.getName()) shape used for ordinary, trusted file copies.
const ZIP_SLIP_CONTEXT_RE = /\bZipEntry\b|\bZipInputStream\b|\.getNextEntry\s*\(|\.entries\s*\(\s*\)|\bunzipper\b|\badm-zip\b|\bAdmZip\b/i;
const ZIP_SLIP_SINK_RE = /(?:new\s+File|Paths\.get)\s*\([\s\S]{0,200}?\.\s*(?:getName|name)\s*\(\s*\)|path\.(?:join|resolve)\s*\([^)]*\.\s*(?:getName|name)\b/i;
// Deliberately excludes a literal "zipSlip" keyword check: WebGoat's own
// vulnerable lesson class is itself named ProfileZipSlip, so that keyword
// would match the vulnerable class name as if it were a guard.
const ZIP_SLIP_GUARD_RE = /getCanonicalPath|\.normalize\s*\(\s*\)|startsWith\s*\(|resolve\s*\([^)]*\)\.startsWith|toRealPath/i;

function findZipSlip(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    if (!ZIP_SLIP_SINK_RE.test(lines[i])) continue;
    const windowStart = Math.max(0, i - 15);
    const contextWindow = lines.slice(windowStart, i + 1);
    if (!contextWindow.some(l => ZIP_SLIP_CONTEXT_RE.test(l))) continue;
    // The containment check conventionally validates the *joined* path, so
    // it's written right after the File/Path is constructed, not before —
    // unlike contextWindow above, this has to look forward too.
    const guardWindow = lines.slice(windowStart, Math.min(lines.length, i + 8));
    if (guardWindow.some(l => ZIP_SLIP_GUARD_RE.test(l))) continue;
    found.push({ id:"path-traversal", label:"Zip Slip — Path Traversal via Archive Entry Name", severity:"critical", line:i+1,
      detail:"Archive entry name joined into an extraction path with no canonicalization/containment check — a crafted entry name (e.g. '../../etc/x') can write outside the target directory" });
  }
  return found;
}

// PHP Local/Remote File Inclusion — a request-derived value passed to
// include/include_once/require/require_once lets an attacker read arbitrary
// local files (LFI) or, if allow_url_include is enabled, execute code from a
// remote URL (RFI). A completely uncovered vulnerability class until now --
// PATH_TRAVERSAL_RE has no PHP include/require entries at all. Two tiers:
// direct inline taint ($_GET[...] literally in the call) and named-variable
// taint (assigned on an earlier line, PHP's overwhelmingly common real-world
// shape: $file = $_GET['page']; ... include($file);). Severity capped at
// "high" rather than "critical": unlike SQLi/command injection, exploit
// impact here depends on server config (allow_url_include, open_basedir)
// that a pure text scan can't observe.
const PHP_INCLUDE_SINK_RE = /\b(?:include|include_once|require|require_once)\s*\(?\s*/i;
const PHP_INCLUDE_INLINE_RE = /\b(?:include|include_once|require|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i;

function findPHPFileInclusion(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  const tainted = extractTaintedVars(lines);
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (PHP_INCLUDE_INLINE_RE.test(line)) {
      found.push({ id:"file-inclusion", label:"PHP File Inclusion", severity:"high", line:i+1,
        detail:"Request parameter passed directly to include/require — allows local (and, if allow_url_include is on, remote) file inclusion; validate against an allowlist of known filenames" });
      continue;
    }
    if (tainted.size === 0 || !PHP_INCLUDE_SINK_RE.test(line)) continue;
    const hit = [...line.matchAll(/\$(\w+)/g)].find(m => tainted.has(m[1]));
    if (!hit) continue;
    found.push({ id:"file-inclusion", label:"PHP File Inclusion", severity:"high", line:i+1,
      detail:`Tainted variable '$${hit[1]}' passed to include/require — allows local (and, if allow_url_include is on, remote) file inclusion; validate against an allowlist of known filenames` });
  }
  return found;
}

function findPrototypePollution(lines: string[]): ScanIndicator[] {
  return runDetector(lines, PROTO_POLLUTION_RE, "prototype-pollution", "Prototype Pollution", "high",
    "Unvalidated user input merged into object — may pollute Object prototype");
}

function findInsecureRandomness(lines: string[]): ScanIndicator[] {
  return runDetector(lines, INSECURE_RANDOM_RE, "insecure-randomness", "Insecure Randomness", "high",
    "Math.random() is not cryptographically secure — use crypto.randomBytes()");
}

// Go: a math/rand call inside a function whose NAME is security-sounding
// (createSessionToken(), weakRandomID(), etc.) but the rand.<Func>() call
// itself has no security keyword on its own line -- the shape
// INSECURE_RANDOM_RE's flat entry can't see, since every entry in that
// array requires the keyword and the call on the SAME line. Tracks the
// current enclosing `func Name(...)` line; if Name contains a security
// keyword, flags any insecure rand call found before the next `func` line.
// A simple, bounded approximation (no real function-boundary/brace
// tracking) consistent with this file's established precision posture
// elsewhere -- doesn't handle nested closures reassigning the "current
// function" context, which is an accepted, minor gap.
const GO_INSECURE_RANDOM_CALL_RE = /\brand\.(?:Int\(\)|Intn|Int31\b|Int63\b|Int31n|Int63n|Float32|Float64|Perm|Shuffle)\s*\(?/;
const GO_FUNC_DECL_RE = /^func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(/;
const GO_SECURITY_FUNC_NAME_RE = /token|secret|session|password|auth|csrf|nonce|key/i;

function findInsecureRandomnessGoFunc(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  let inSecurityFunc = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const funcMatch = GO_FUNC_DECL_RE.exec(line.trim());
    if (funcMatch) {
      inSecurityFunc = GO_SECURITY_FUNC_NAME_RE.test(funcMatch[1]);
      continue;
    }
    if (!inSecurityFunc) continue;
    if (isNonExecutableLine(line)) continue;
    if (INSECURE_RANDOM_RE.some(r => r.test(line))) continue; // already caught inline
    if (GO_INSECURE_RANDOM_CALL_RE.test(line)) {
      found.push({ id:"insecure-randomness", label:"Insecure Randomness", severity:"high", line:i+1,
        detail:"math/rand used inside a security-sounding function — use crypto/rand for tokens, session ids, or anything security-sensitive" });
    }
  }
  return found;
}

// C#: same shape as findInsecureRandomnessGoFunc above -- `new Random()`
// and its `.Next(...)`/`.NextDouble()`/`.NextBytes(...)` call are typically
// on separate lines (`var random = new Random(); return
// random.Next(100000, 999999);`), invisible to INSECURE_RANDOM_RE's
// same-line co-occurrence check, exactly like Go's rand.Intn() idiom.
// Method-name extraction only (no full param/modifier capture needed --
// unlike callGraph.ts's tryMatchFunc, this doesn't need is_exported/params)
// so this stays a lighter-weight regex than that one.
const CSHARP_INSECURE_RANDOM_CALL_RE = /\.Next\s*\(|\.NextDouble\s*\(|\.NextBytes\s*\(/;
const CSHARP_METHOD_DECL_RE = /^\s*(?:\[\w+(?:\([^)]*\))?\]\s*)*(?:public|private|protected|internal)\s+(?:static\s+)?(?:async\s+)?(?:override\s+)?(?:virtual\s+)?(?:sealed\s+)?[\w<>[\],.\s]+?\s+(\w+)\s*\(/;

function findInsecureRandomnessCSharpFunc(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  let inSecurityFunc = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const funcMatch = CSHARP_METHOD_DECL_RE.exec(line);
    if (funcMatch) {
      inSecurityFunc = GO_SECURITY_FUNC_NAME_RE.test(funcMatch[1]);
      continue;
    }
    if (!inSecurityFunc) continue;
    if (isNonExecutableLine(line)) continue;
    if (INSECURE_RANDOM_RE.some(r => r.test(line))) continue; // already caught inline
    if (CSHARP_INSECURE_RANDOM_CALL_RE.test(line)) {
      found.push({ id:"insecure-randomness", label:"Insecure Randomness", severity:"high", line:i+1,
        detail:"System.Random used inside a security-sounding method — use RandomNumberGenerator (System.Security.Cryptography) for tokens, session ids, or anything security-sensitive" });
    }
  }
  return found;
}

function findReDoS(lines: string[]): ScanIndicator[] {
  return runDetector(lines, REDOS_RE, "redos", "ReDoS — Regex DoS", "high",
    "Catastrophic backtracking risk or user-controlled regex");
}

function findOpenRedirect(lines: string[]): ScanIndicator[] {
  return runDetector(lines, OPEN_REDIRECT_RE, "open-redirect", "Open Redirect", "medium",
    "User-controlled URL used in redirect — validate against allowlist");
}

function findTimingAttack(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (const re of TIMING_ATTACK_RE) {
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i]) && !/crypto\.timingSafeEqual/.test(lines[i]))
        found.push({ id:"timing-attack", label:"Timing Attack", severity:"medium", line:i+1,
          detail:"Non-constant-time comparison of secrets — use crypto.timingSafeEqual()" });
    }
  }
  return found;
}

// Named-variable SSRF: const url = req.query.url; fetch(url)
function findNamedTaintSSRF(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  // Python's `requests` library added here -- found missing via a real
  // benchmark: `url = request.args.get("url"); requests.get(url)` is the
  // idiomatic Python shape (SSRF_RE's own Python entry only covers the
  // request.args literally inline in the call, not a variable assigned on
  // an earlier line).
  const HTTP_SINK_RE = /(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|got|needle(?:\.(?:get|post|put|delete|patch|head))?|superagent(?:\.(?:get|post|put|delete|patch|head))?|https?\.(?:get|request)|requests\.(?:get|post|put|delete|head|patch))\s*\(\s*(\w+)/i;
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    if (seen.has(i)) continue;
    if (isNonExecutableLine(lines[i])) continue;
    const m = HTTP_SINK_RE.exec(lines[i]);
    if (!m || !tainted.has(m[1])) continue;
    if (SSRF_RE.some(r => r.test(lines[i]))) continue; // already caught
    seen.add(i);
    found.push({ id:"ssrf", label:"SSRF via Named Variable", severity:"critical", line:i+1,
      detail:`Tainted variable '${m[1]}' flows into HTTP request — validate against allowlist` });
  }
  return found;
}

// PHP named-taint SSRF: $url = $_GET['url']; curl_setopt($ch,
// CURLOPT_URL, $url); -- SSRF_RE's inline PHP entry only matches the
// superglobal literally inline as curl_setopt's 3rd arg. Also adds two
// sink families SSRF_RE has zero PHP coverage for: file_get_contents()/
// fopen() given a tainted URL (PHP's stream wrappers make these legitimate
// HTTP fetchers -- file_get_contents('http://...') is valid, working PHP),
// and Guzzle's HTTP client, the dominant modern PHP HTTP library. Guzzle's
// ->get()/->post()/->request() are scoped to a client-name-looking
// receiver ($client/$http/$httpClient/$guzzle) -- a bare ->get($var)
// collides with an extremely common non-HTTP getter method name across
// PHP OOP code (collections, DI containers, ArrayAccess wrappers); this
// trades recall (misses Guzzle clients stored in unusually named
// variables) for not flooding every PHP codebase with false positives on
// unrelated ->get() calls.
//
// OVERLAP NOTE (deliberate): file_get_contents()/fopen() with a tainted
// variable is ALSO flagged by findNamedTaintPathTraversalPHP -- the two
// are genuinely ambiguous from a text scan (the value could be a local
// path or a remote URL). Mirrors the pre-existing, deliberately-accepted
// include()/require() dual-classification under both "file-inclusion" and
// "path-traversal" -- both ids are legitimate simultaneous classifications
// of the same risky call. Not de-duplicated.
const PHP_SSRF_SINK_RE = [
  /curl_setopt\s*\(\s*\$\w+\s*,\s*CURLOPT_URL\s*,\s*\$(\w+)\s*\)/i,
  /\b(?:file_get_contents|fopen)\s*\(\s*\$(\w+)\b/i,
  /\$(?:client|http|httpClient|guzzle)\w*\s*->\s*(?:get|post|put|delete|head|patch)\s*\(\s*\$(\w+)\b/i,
  /\$(?:client|http|httpClient|guzzle)\w*\s*->\s*request\s*\(\s*["']\w+["']\s*,\s*\$(\w+)\b/i,
];

function findNamedTaintSSRFPHP(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    if (SSRF_RE.some(r => r.test(line))) continue;
    let hit: string | undefined;
    for (const re of PHP_SSRF_SINK_RE) {
      const m = re.exec(line);
      if (m && tainted.has(m[1])) { hit = m[1]; break; }
    }
    if (!hit) continue;
    found.push({ id:"ssrf", label:"Server-Side Request Forgery", severity:"critical", line:i+1,
      detail:`Tainted variable '$${hit}' used as an outbound request URL — validate the target host against an allowlist before fetching` });
  }
  return found;
}

// Go SSRF two-step: req, _ := http.NewRequest("GET", url, nil); resp, _ :=
// client.Do(req) -- Go's idiomatic construct-then-execute pattern, which
// SSRF_RE's inline-only http.Get(url) shape can't see (the tainted URL and
// the actual send are on two different lines, often separated by error
// handling). Two regexes, not one with an optional leading arg --
// http.NewRequest(method, url, body) and http.NewRequestWithContext(ctx,
// method, url, body) have different argument counts and a single combined
// regex mis-captures the wrong argument for the WithContext variant
// (verified directly).
//
// Deliberately NOT folded into extractTaintedVars' shared `tainted` Set:
// `req` here is a *http.Request object one hop removed from a tainted
// string, a different taint "kind" -- reusing the same flat Set risks a
// same-named `req`/`client` variable elsewhere in the file cross-
// contaminating an unrelated detector's sink check.
//
// SAFE-PATTERN GUARD: a hardcoded destination -- http.NewRequest("GET",
// "https://api.example.com", nil) -- is never flagged, because the URL
// capture group requires a bare identifier, which a quoted string literal
// structurally cannot satisfy (verified directly).
const GO_NEW_REQUEST_RE = /\b(\w+)\s*,\s*\w+\s*:=\s*http\.NewRequest\s*\(\s*[^,)]+,\s*(\w+)\s*[,)]/;
const GO_NEW_REQUEST_CTX_RE = /\b(\w+)\s*,\s*\w+\s*:=\s*http\.NewRequestWithContext\s*\(\s*[^,]+,\s*[^,)]+,\s*(\w+)\s*[,)]/;
const GO_CLIENT_DO_RE = /\b\w+\.Do\s*\(\s*(\w+)\s*\)/;

function findSSRFGoNewRequest(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const taintedRequests = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = GO_NEW_REQUEST_RE.exec(lines[i]) ?? GO_NEW_REQUEST_CTX_RE.exec(lines[i]);
    if (m && tainted.has(m[2])) taintedRequests.add(m[1]);
  }
  if (taintedRequests.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = GO_CLIENT_DO_RE.exec(lines[i]);
    if (!m || !taintedRequests.has(m[1])) continue;
    found.push({ id:"ssrf", label:"Server-Side Request Forgery", severity:"critical", line:i+1,
      detail:`Request built from tainted URL via http.NewRequest and sent with '${m[1]}' — validate the target host against an allowlist before constructing the request` });
  }
  return found;
}

// C# named-taint SSRF: an HttpClient call with a tainted URL argument, on a
// different line than where the URL was assigned.
const CSHARP_HTTP_SINK_RE = /\.(?:GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|PostAsJsonAsync|PutAsJsonAsync)\s*\(\s*(\w+)\s*[,)]/;

function findNamedTaintSSRFCSharp(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = CSHARP_HTTP_SINK_RE.exec(lines[i]);
    if (!m || !tainted.has(m[1])) continue;
    if (SSRF_RE.some(r => r.test(lines[i]))) continue;
    found.push({ id:"ssrf", label:"Server-Side Request Forgery", severity:"critical", line:i+1,
      detail:`Tainted variable '${m[1]}' passed to HttpClient — validate the target host against an allowlist before sending the request` });
  }
  return found;
}

// C# SSRF two-step: var request = new HttpRequestMessage(HttpMethod.Get,
// url); var response = await client.SendAsync(request); -- mirrors
// findSSRFGoNewRequest's construct-then-send shape exactly.
// IHttpClientFactory-based HttpRequestMessage is the dominant modern
// ASP.NET Core idiom, not optional coverage. Deliberately NOT folded into
// extractTaintedVars' shared Set for the same reason as Go's `req`: `request`
// here is an HttpRequestMessage object one hop removed from a tainted
// string, a different taint "kind".
//
// SAFE-PATTERN GUARD: a hardcoded destination -- new HttpRequestMessage(
// HttpMethod.Get, "https://api.example.com") -- is never flagged, since the
// URL capture group requires a bare identifier, which a quoted string
// literal structurally cannot satisfy.
const CSHARP_NEW_REQUEST_RE = /\b(\w+)\s*=\s*new\s+HttpRequestMessage\s*\([^,]+,\s*(\w+)\s*\)/;
const CSHARP_SEND_ASYNC_RE = /\.SendAsync\s*\(\s*(\w+)\b/;

function findSSRFCSharpNewRequest(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const taintedRequests = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = CSHARP_NEW_REQUEST_RE.exec(lines[i]);
    if (m && tainted.has(m[2])) taintedRequests.add(m[1]);
  }
  if (taintedRequests.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = CSHARP_SEND_ASYNC_RE.exec(lines[i]);
    if (!m || !taintedRequests.has(m[1])) continue;
    found.push({ id:"ssrf", label:"Server-Side Request Forgery", severity:"critical", line:i+1,
      detail:`Request built from tainted URL via HttpRequestMessage and sent with '${m[1]}' — validate the target host against an allowlist before constructing the request` });
  }
  return found;
}

// Named-variable XSS: const html = req.body.html; elem.innerHTML = html
function findNamedTaintXSS(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const DOM_SINK_RE = /(?:\.innerHTML\s*[+]?=\s*|document\.write\s*\(\s*|\.outerHTML\s*=\s*)(\w+)/;
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    if (seen.has(i)) continue;
    if (isNonExecutableLine(lines[i])) continue;
    const m = DOM_SINK_RE.exec(lines[i]);
    if (!m || !tainted.has(m[1])) continue;
    if (XSS_RE.some(r => r.test(lines[i]))) continue; // already caught
    seen.add(i);
    found.push({ id:"xss", label:"XSS via Named Variable", severity:"critical", line:i+1,
      detail:`Tainted variable '${m[1]}' written to DOM — sanitize with DOMPurify` });
  }
  return found;
}

// C# named-taint XSS: a tainted variable passed to Html.Raw/Response.Write,
// bypassing Razor's default output encoding. Mirrors findNamedTaintXSS's
// shape, scoped to the same two named escape hatches as the inline XSS_RE
// entry above (see its comment for why this stays narrow rather than a
// broad interpolation pattern).
const CSHARP_XSS_SINK_RE = /(?:@?Html\.Raw|Response\.Write|\bContent)\s*\(\s*(\w+)\s*[,)]/;

function findNamedTaintXSSCSharp(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = CSHARP_XSS_SINK_RE.exec(lines[i]);
    if (!m || !tainted.has(m[1])) continue;
    if (XSS_RE.some(r => r.test(lines[i]))) continue; // already caught inline
    found.push({ id:"xss", label:"Cross-Site Scripting (XSS)", severity:"critical", line:i+1,
      detail:`Tainted variable '${m[1]}' passed to Html.Raw/Response.Write, bypassing Razor's default output encoding — remove the Raw() call or encode explicitly` });
  }
  return found;
}

// PHP named-taint XSS: $name = $_GET['name']; ... echo $name; -- named-
// variable equivalent of the inline XSS_RE entry above, same
// htmlspecialchars()/htmlentities() same-statement guard.
const PHP_ECHO_SINK_RE = /\b(?:echo|print)\b\s*(\$\w+)\b/i;
const PHP_XSS_SAFE_ESCAPE_RE = /\b(?:htmlspecialchars|htmlentities)\s*\(/i;

function findNamedTaintXSSPHP(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    const m = PHP_ECHO_SINK_RE.exec(line);
    if (!m) continue;
    const varName = m[1].slice(1);
    if (!tainted.has(varName)) continue;
    if (PHP_XSS_SAFE_ESCAPE_RE.test(line)) continue;
    if (XSS_RE.some(r => r.test(line))) continue;
    found.push({ id:"xss", label:"Cross-Site Scripting (XSS)", severity:"critical", line:i+1,
      detail:`Tainted variable '$${varName}' echoed without escaping — wrap in htmlspecialchars() before output` });
  }
  return found;
}

// Named-variable IDOR: const { userId } = req.body; someDAO.update(userId, ...)
// with no ownership check anywhere nearby. IDOR_RE only catches the tainted
// ID literally inline as `req.params`/`req.body` at the call site; once a
// route destructures/reassigns it to a local variable first (the common
// real-world shape — see OWASP NodeGoat's benefits.js) that inline pattern
// never matches. Mirrors findNamedTaintSSRF/findNamedTaintXSS's shape, with
// findIDORJava's "scan a nearby window for an auth/ownership check, and
// suppress if one is found" guard against flooding every legitimate
// DAO/repository call that happens to take a request-derived id.
const IDOR_SINK_RE = /\b\w*(?:DAO|Repository|Repo|Model)\w*\.(?:find|get|update|delete|remove)\w*\s*\(\s*(\w+)\b/i;
// Extended (beyond the original ownership-comparison terms) with role/
// permission/admin-gate language, shared with findAuthenticatedIdentityIgnored
// below -- a function gated by an admin/role check legitimately acts on
// another user's identifier by design, so both detectors need to stand down
// in its presence, not just an explicit ownership comparison.
// Extended again with Gin's identity-from-context idioms (c.MustGet(...),
// c.GetString("userID"/...)) -- safe, since this only ever suppresses more,
// never adds new sink matching, and these tokens can't appear in non-Go code.
// Extended again with C#'s [Authorize] attribute -- safe, suppression-only.
// Extended again with PHP/Laravel auth vocabulary -- safe, suppression-only.
const IDOR_AUTH_CHECK_NEARBY_RE = /session\.\w*(?:userId|user_id|\bid\b)|req\.user\.|isOwner|checkOwnership|hasPermission|\.equals\s*\(|===\s*(?:req|current|session)\b|\badmin\b|\brole\b|\bpermission\b|@PreAuthorize|hasRole|before_action\s*:\s*:administrative|is_admin|c\.MustGet\s*\(|c\.GetString\s*\(\s*["'](?:user|userId|userID|uid)["']\s*\)|\[Authorize\b|Auth::\w+|Gate::authorize|->\s*can\s*\(|\$_SESSION\s*\[\s*['"]\w*(?:user_?id)['"]\s*\]/i;

function findNamedTaintIDOR(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const m = IDOR_SINK_RE.exec(lines[i]);
    if (!m || !tainted.has(m[1])) continue;
    if (IDOR_RE.some(r => r.test(lines[i]))) continue; // already caught inline
    const windowStart = Math.max(0, i - 15);
    const hasAuthCheck = lines.slice(windowStart, i + 1).some(l => IDOR_AUTH_CHECK_NEARBY_RE.test(l));
    if (hasAuthCheck) continue;
    // Capped at medium (vs. "high" for the literal-inline IDOR_RE match
    // above): this is a heuristic over a destructured/renamed variable with
    // no guaranteed way to tell a real owned-resource lookup (unsafe) from a
    // pre-auth uniqueness check like "is this username taken" (benign) —
    // same false-positive-risk reasoning as this session's other named-taint
    // and cross-file heuristics.
    found.push({ id:"idor", label:"Insecure Direct Object Reference", severity:"medium", line:i+1,
      detail:`Tainted variable '${m[1]}' used as a lookup/update id with no ownership check nearby — verify caller owns the resource` });
  }
  return found;
}

// Go named-taint IDOR: a route-param identifier flows into a database/sql
// or GORM lookup with no ownership check nearby. Mirrors findNamedTaintIDOR
// above exactly (same 15-line auth-check window, same "medium" severity for
// a heuristic named-taint match). Same documented limitation as this
// session's Spring BOLA work: this is loose keyword-proximity, not a real
// semantic ownership comparison -- an accepted posture for a regex-only
// phase (a real Go AST-based BOLA check is deferred/future work).
const GO_IDOR_SINK_RE = [
  /\bdb\.QueryRow\s*\([^)]*,\s*(\w+)\s*\)/,        // database/sql: db.QueryRow("...?", id)
  /\.First\s*\(\s*&\w+\s*,\s*(\w+)\s*\)/,           // GORM: db.First(&user, id)
  /\.Where\s*\(\s*["'][^"']*\?["']\s*,\s*(\w+)\s*\)/, // GORM: db.Where("id = ?", id)
];

function findNamedTaintIDORGo(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    let hit: string | undefined;
    for (const re of GO_IDOR_SINK_RE) {
      const m = re.exec(line);
      if (m) { hit = m[1]; break; }
    }
    if (!hit || !tainted.has(hit)) continue;
    const windowStart = Math.max(0, i - 15);
    if (lines.slice(windowStart, i + 1).some(l => IDOR_AUTH_CHECK_NEARBY_RE.test(l))) continue;
    found.push({ id:"idor", label:"Insecure Direct Object Reference", severity:"medium", line:i+1,
      detail:`Tainted variable '${hit}' used as a lookup id with no ownership check nearby — verify caller owns the resource` });
  }
  return found;
}

// C# named-taint IDOR/BOLA: an attribute-bound identifier flows into an EF
// or Dapper lookup with no ownership check nearby. Mirrors
// findNamedTaintIDORGo exactly (same 15-line auth-check window, same
// "medium" severity, same documented "loose keyword-proximity, not real
// semantic ownership comparison" limitation). "Sensitive action missing
// [Authorize]" detection is explicitly deferred -- ASP.NET Core commonly
// applies authorization globally (AuthorizeFilter/.RequireAuthorization()
// in Program.cs), so its absence on a single action is unknowable from one
// file in isolation, a structural blind spot, not just a false-positive
// risk to be tuned away.
const CSHARP_IDOR_SINK_RE = [
  /\.Find\s*\(\s*(\w+)\s*\)/,                                                          // EF: db.Users.Find(id)
  /\.Where\s*\(\s*\w+\s*=>\s*\w+\.\w*[Ii]d\s*==\s*(\w+)\s*\)\s*\.\s*(?:FirstOrDefault|SingleOrDefault|First|Single)\s*\(/, // EF LINQ: .Where(x => x.Id == id).FirstOrDefault()
  /Query(?:First|Single)OrDefault(?:Async)?\s*<[^>]+>\s*\([^)]*new\s*\{\s*\w+\s*=\s*(\w+)\s*\}\s*\)/, // Dapper: QueryFirstOrDefault<T>("...", new { Id = id })
];

function findNamedTaintIDORCSharp(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    let hit: string | undefined;
    for (const re of CSHARP_IDOR_SINK_RE) {
      const m = re.exec(line);
      if (m) { hit = m[1]; break; }
    }
    if (!hit || !tainted.has(hit)) continue;
    const windowStart = Math.max(0, i - 15);
    if (lines.slice(windowStart, i + 1).some(l => IDOR_AUTH_CHECK_NEARBY_RE.test(l))) continue;
    found.push({ id:"idor", label:"Insecure Direct Object Reference", severity:"medium", line:i+1,
      detail:`Tainted variable '${hit}' used as a lookup id with no ownership check nearby — verify caller owns the resource` });
  }
  return found;
}

// PHP named-taint IDOR/BOLA: an $_GET/$_POST-derived id flows into an
// Eloquent or PDO lookup with no ownership check nearby. IDOR_SINK_RE was
// confirmed to match ZERO real PHP/Laravel/PDO shapes -- defeated twice
// over by Eloquent's `::`-static-call syntax (that regex requires a
// literal `.`) and PHP's `$`-prefixed variables (its capture group
// requires a \w char immediately after `(`, which `$id` can never
// satisfy). User::find($id), User::where('id', $id)->first(), and plain
// PDO $stmt->execute(['id'=>$id]) all confirmed non-matching -- PHP had
// ZERO IDOR detection of any kind before this. Mirrors
// findNamedTaintIDORGo/CSharp exactly (reuses "idor" id, same 15-line
// auth-check window, same "medium" severity for a loose keyword-proximity
// heuristic, not real semantic ownership comparison).
const PHP_IDOR_SINK_RE = [
  /\b[A-Z]\w*::\s*find(?:OrFail)?\s*\(\s*\$(\w+)\s*\)/,                                              // Eloquent: User::find($id)
  /\b[A-Z]\w*::\s*where\s*\(\s*['"]\w*id['"]\s*,\s*\$(\w+)\s*\)\s*->\s*(?:first|get|firstOrFail)\s*\(/, // Eloquent: User::where('id', $id)->first()
  /->\s*execute\s*\(\s*\[[^\]]*['"]\w*id['"]\s*=>\s*\$(\w+)/i,                                        // PDO: $stmt->execute(['id' => $id])
];

function findNamedTaintIDORPHP(lines: string[]): ScanIndicator[] {
  const tainted = extractTaintedVars(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];
    let hit: string | undefined;
    for (const re of PHP_IDOR_SINK_RE) {
      const m = re.exec(line);
      if (m) { hit = m[1]; break; }
    }
    if (!hit || !tainted.has(hit)) continue;
    const windowStart = Math.max(0, i - 15);
    if (lines.slice(windowStart, i + 1).some(l => IDOR_AUTH_CHECK_NEARBY_RE.test(l))) continue;
    found.push({ id:"idor", label:"Insecure Direct Object Reference", severity:"medium", line:i+1,
      detail:`Tainted variable '$${hit}' used as a lookup id with no ownership check nearby — verify caller owns the resource` });
  }
  return found;
}

// BOLA (OWASP API #1): a function authenticates the caller (decodes/
// validates a token into an identity variable), then performs a write/
// delete/update using a DIFFERENT identifier instead of that identity, with
// no comparison between the two anywhere in the function. Distinct from and
// additive to findNamedTaintIDOR above: that detector fires on any raw
// request-derived id reaching a lookup, regardless of whether the function
// authenticates at all; this one specifically targets the narrower "auth was
// established, then ignored" shape, which is a stronger, more specific
// signal. Found via a real VAmPI benchmark (users.py's update_password): the
// vulnerable and safe branches differ ONLY in which variable feeds the same
// filter_by() call, which is exactly what this checks for.
const AUTH_ESTABLISHED_RE = [
  // Python: resp = token_validator(...); payload = jwt.decode(...)
  /\b(\w+)\s*=\s*(?:await\s+)?(?:token_validator|decode_auth_token|jwt\.decode|jwt\.verify)\s*\(/,
  // JS/TS: const decoded = jwt.verify(...); const payload = await verifyToken(...)
  /\b(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(?:jwt\.verify|jwt\.decode|verifyToken|decodeToken)\s*\(/,
];
const BOLA_WRITE_SINK_RE = [
  // Python/SQLAlchemy: User.query.filter_by(username=username).first() -- captured
  // group only ever matches a BARE identifier, so a correctly-scoped
  // reference like filter_by(username=resp['sub']) structurally can't match
  // here at all (the '[' breaks the \w+ capture before the closing paren).
  /\.filter_by\s*\(\s*(?:username|id|user_id)\s*=\s*(\w+)\s*\)/,
  // JS/Mongoose
  /find(?:ByIdAndUpdate|ByIdAndDelete)\s*\(\s*(\w+)/,
  // Sequelize-style
  /\.(?:update|destroy|delete)\s*\(\s*\{\s*(?:where\s*:\s*)?\{?\s*id\s*:\s*(\w+)/,
];

function findAuthenticatedIdentityIgnored(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    let authVar: string | undefined;
    for (const re of AUTH_ESTABLISHED_RE) {
      const m = re.exec(lines[i]);
      if (m) { authVar = m[1]; break; }
    }
    if (!authVar) continue;

    const windowEnd = Math.min(lines.length, i + 40);
    for (let j = i + 1; j < windowEnd; j++) {
      if (isNonExecutableLine(lines[j])) continue;
      let ident: string | undefined;
      for (const re of BOLA_WRITE_SINK_RE) {
        const m = re.exec(lines[j]);
        if (m) { ident = m[1]; break; }
      }
      if (!ident || ident === authVar) continue;

      const window = lines.slice(i, Math.min(lines.length, j + 1));
      const ownershipCompared = window.some(l =>
        (l.includes(authVar as string) && (l.includes("==") || l.includes("!=") || l.includes(".equals("))));
      if (ownershipCompared) continue;
      if (window.some(l => IDOR_AUTH_CHECK_NEARBY_RE.test(l))) continue;

      found.push({ id:"bola-identity-mismatch", label:"Broken Object Level Authorization", severity:"medium", line:j+1,
        detail:`Caller identity established via '${authVar}' on line ${i+1}, but this write uses a different identifier ('${ident}') with no ownership check — verify the caller owns the target resource` });
      break; // one finding per auth-establishment site is enough
    }
  }
  return found;
}

// Legacy/plain PHP: a sensitive action (DB write, unserialize(), or file
// write) with no session/auth guard anywhere in the preceding lines of the
// SAME script. Scoped deliberately to legacy/plain PHP's self-contained,
// no-central-router idiom -- NOT extended to Laravel-style code:
// Route::middleware('auth') registration lives in routes/web.php, not the
// controller file, so a per-controller "no guard found" signal there would
// be structurally unreliable (a false positive on code that IS protected,
// just not visibly in this file) -- identical reasoning to why this
// session's C# phase deferred a "[Authorize] missing" check for ASP.NET
// Core's global middleware model.
// "Sensitive action" = a DB write (INSERT/UPDATE/DELETE), unserialize()
// (PHP Object Injection risk), or a file write (fwrite/
// file_put_contents/move_uploaded_file). "Guard" = a conditional READ of
// $_SESSION (isset/empty/array_key_exists/??), or session_status(), in the
// preceding 15 lines -- deliberately NOT a bare assignment INTO $_SESSION
// (sets state, doesn't check it).
// KNOWN, STATED LIMITATION: an include-based guard (require
// 'auth_check.php'; at the top of the script -- a very common legacy
// pattern) is invisible to this detector, since it doesn't inline the
// included file's contents. Severity capped at "medium" given both this
// gap and the general loose-keyword-proximity imprecision already accepted
// elsewhere in this file (same rationale as IDOR's "medium").
const PHP_SENSITIVE_ACTION_RE = /\b(?:insert\s+into|update\s+\w+\s+set|delete\s+from)\b|\bunserialize\s*\(|\b(?:fwrite|file_put_contents|move_uploaded_file)\s*\(/i;
const PHP_SESSION_GUARD_RE = /\b(?:isset|empty|array_key_exists)\s*\(\s*\$_SESSION\b|\$_SESSION\s*\[[^\]]+\]\s*\?\?|session_status\s*\(\s*\)/i;

function findPHPMissingSessionGuard(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    if (!PHP_SENSITIVE_ACTION_RE.test(lines[i])) continue;
    const windowStart = Math.max(0, i - 15);
    const window = lines.slice(windowStart, i + 1);
    if (window.some(l => PHP_SESSION_GUARD_RE.test(l))) continue;
    found.push({ id:"php-missing-session-guard", label:"Sensitive Action Without Session/Auth Guard", severity:"medium", line:i+1,
      detail:"No $_SESSION-based authentication check found in the preceding 15 lines before this sensitive action (database write / unserialize / file write) — verify this script is reachable only by an authenticated request, or add an explicit session guard" });
  }
  return found;
}

function findSSTI(lines: string[]): ScanIndicator[] {
  return runDetector(lines, SSTI_RE, "ssti", "Server-Side Template Injection", "critical",
    "User input passed directly to template engine — can lead to RCE; use static templates");
}

function findHeaderInjection(lines: string[]): ScanIndicator[] {
  return runDetector(lines, HEADER_INJECT_RE, "header-injection", "HTTP Header Injection", "high",
    "User-controlled value set as response header — strip newlines (CRLF injection risk)");
}

function findWeakCORS(lines: string[]): ScanIndicator[] {
  return runDetector(lines, WEAK_CORS_RE, "weak-cors", "Weak CORS Policy", "medium",
    "Wildcard Access-Control-Allow-Origin — use explicit origin allowlist");
}

// Missing security headers -- scoped strictly to the one unambiguous,
// AFFIRMATIVE signal available to a text scan: explicit removal of a
// known security header (Response.Headers.Remove("X-Frame-Options"),
// etc.). No "detect an absence" precedent exists anywhere in this
// codebase (weak-cors above detects the PRESENCE of a wildcard, not the
// absence of a CORS policy) and this deliberately doesn't try to be the
// first -- claiming "you forgot header X" globally would require knowing
// every header-setting mechanism (middleware, reverse proxy, CDN config)
// a real app might use, none of which this scanner can see.
const MISSING_SECURITY_HEADERS_RE = /Response\.Headers\.Remove\s*\(\s*["'](?:X-Content-Type-Options|Content-Security-Policy|X-Frame-Options|Strict-Transport-Security|X-XSS-Protection)["']\s*\)/;

function findMissingSecurityHeaders(lines: string[]): ScanIndicator[] {
  return runDetector(lines, [MISSING_SECURITY_HEADERS_RE], "missing-security-headers", "Security Header Explicitly Removed", "medium",
    "A known security response header is explicitly removed — X-Content-Type-Options/Content-Security-Policy/X-Frame-Options/Strict-Transport-Security/X-XSS-Protection all defend against real, common attacks and should not be stripped");
}

// Debug mode left enabled -- exposes the interactive debugger (arbitrary
// code execution via Werkzeug's PIN-protected console, or Django's DEBUG=True
// leaking full stack traces, settings, and environment variables on every
// unhandled exception). A real, common, single-line-detectable
// misconfiguration in the same spirit as the existing GraphQL-introspection
// and CSRF-disabled checks.
const DEBUG_MODE_RE = [
  /app\.config\s*\[\s*["']DEBUG["']\s*\]\s*=\s*True\b/,
  /\.run\s*\([^)]*\bdebug\s*=\s*True\b/,
  /^\s*DEBUG\s*=\s*True\b/,
  /app\.debug\s*=\s*True\b/,
  // PHP: ini_set("display_errors", "1") -- explicit enable is the
  // affirmative, unambiguous signal this array's other entries all rely
  // on too (never absence-of-a-safe-value, which single-line regex can't
  // see).
  /ini_set\s*\(\s*["']display_errors["']\s*,\s*["']?1["']?\s*\)/i,
];

function findDebugModeEnabled(lines: string[]): ScanIndicator[] {
  return runDetector(lines, DEBUG_MODE_RE, "debug-mode-enabled", "Debug Mode Enabled", "high",
    "Framework debug mode is explicitly enabled — exposes stack traces, source code, and (Werkzeug) an interactive RCE console; disable in production");
}

function findIDOR(lines: string[]): ScanIndicator[] {
  return runDetector(lines, IDOR_RE, "idor", "Insecure Direct Object Reference", "high",
    "User-supplied ID used in DB lookup without ownership check — verify caller owns the resource");
}

function findXPathInjection(lines: string[]): ScanIndicator[] {
  return runDetector(lines, XPATH_INJECT_RE, "xpath-injection", "XPath Injection", "critical",
    "User input concatenated into an XPath expression — use XPath variable binding instead of string concatenation");
}

function findCSRFDisabled(lines: string[]): ScanIndicator[] {
  return runDetector(lines, CSRF_DISABLED_RE, "csrf-protection-disabled", "CSRF Protection Disabled", "high",
    "Framework-level CSRF protection explicitly disabled — re-enable it or add explicit token validation for state-changing endpoints");
}

// Java Spring IDOR: an @PathVariable/@RequestParam-bound identifier flowing
// into a repository lookup within the same method, with no authorization
// check in between. Requires cross-line pairing (the annotation lives on the
// method signature, the lookup a few lines later) — regex on IDOR_RE only
// sees `req.params`-style inline JS taint, so this is a dedicated pass
// rather than an array entry, mirroring findTOCTOU's block-scan shape.
const JAVA_TAINT_PARAM_RE = /@(?:PathVariable|RequestParam)(?:\([^)]*\))?\s+(?:final\s+)?\w+(?:<[^>]+>)?\s+(\w+)\b/;
const JAVA_REPO_LOOKUP_RE = /\.(?:findById|getOne|getById)\s*\(\s*(\w+)\s*\)/;
const AUTH_CHECK_NEARBY_RE = /@PreAuthorize|hasPermission|getPrincipal|isOwner|checkOwnership|\.equals\s*\(\s*(?:current|principal|auth)/i;

function findIDORJava(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const pm = JAVA_TAINT_PARAM_RE.exec(lines[i]);
    if (!pm) continue;
    const paramName = pm[1];
    for (let j = i; j < Math.min(lines.length, i + 15); j++) {
      if (AUTH_CHECK_NEARBY_RE.test(lines[j])) break; // ownership check present — not IDOR
      const lm = JAVA_REPO_LOOKUP_RE.exec(lines[j]);
      if (lm && lm[1] === paramName) {
        found.push({ id:"idor", label:"Insecure Direct Object Reference", severity:"high", line:j+1,
          detail:`'${paramName}' comes directly from @PathVariable/@RequestParam and is used in a repository lookup with no ownership check nearby` });
        break;
      }
    }
  }
  return found;
}

function findSensitiveDataInURL(lines: string[]): ScanIndicator[] {
  return runDetector(lines, SENSITIVE_URL_RE, "sensitive-url-data", "Sensitive Data in URL", "medium",
    "Credentials or tokens in URL query string — use POST body or Authorization header instead");
}

function findNoSQLInjection(lines: string[]): ScanIndicator[] {
  return runDetector(lines, NOSQL_INJECT_RE, "nosql-injection", "NoSQL Injection", "critical",
    "User input in MongoDB operator/query — validate with schema and never pass raw $where");
}

function findVerboseErrors(lines: string[]): ScanIndicator[] {
  return runDetector(lines, VERBOSE_ERROR_RE, "verbose-error", "Verbose Error Disclosure", "medium",
    "Stack trace or raw error message sent to client — log internally, return generic message");
}

function findGraphQLInjection(lines: string[]): ScanIndicator[] {
  return runDetector(lines, GRAPHQL_INJECT_RE, "graphql-injection", "GraphQL Injection", "critical",
    "User input interpolated into GraphQL query — use parameterized variables instead");
}

function findGraphQLIntrospectionEnabled(lines: string[]): ScanIndicator[] {
  return runDetector(lines, GRAPHQL_INTROSPECTION_RE, "graphql-introspection-enabled", "GraphQL Introspection Enabled", "medium",
    "GraphQL introspection/IDE (GraphiQL/Playground) is explicitly enabled — exposes the complete schema for attacker reconnaissance; disable in production");
}

function findXXE(lines: string[]): ScanIndicator[] {
  return runDetector(lines, XXE_RE, "xxe", "XML External Entity (XXE)", "critical",
    "XML parser with external entities enabled — disable DTD processing in parser config");
}

// C# — dedicated multi-line-window function rather than a flat XXE_RE
// entry. The existing Java entries' forward lookaheads ((?![\s\S]{0,300}
// setFeature...)) can only ever see hardening calls on the SAME line, since
// every regex in that array is tested one line at a time (content.split(
// "\n") strips every newline before matching) -- real code overwhelmingly
// hardens on a separate line. A deliberate precision improvement for C#,
// not a deviation from the "config-value-presence, no taint required"
// posture those entries otherwise establish.
const CSHARP_XML_DOC_CTOR_RE = /new\s+XmlDocument\s*\(\s*\)/;
const CSHARP_XML_TEXT_READER_CTOR_RE = /new\s+XmlTextReader\s*\(/;
const CSHARP_XML_RESOLVER_NULL_RE = /\.XmlResolver\s*=\s*null\b/;
const CSHARP_XML_RESOLVER_UNSAFE_RE = /\.XmlResolver\s*=\s*new\s+XmlUrlResolver\s*\(/;
const CSHARP_DTD_PARSE_RE = /DtdProcessing\s*=\s*DtdProcessing\.Parse\b/;

function findXXECSharp(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    const line = lines[i];

    if (CSHARP_XML_DOC_CTOR_RE.test(line) || CSHARP_XML_TEXT_READER_CTOR_RE.test(line)) {
      const forwardWindow = lines.slice(i, Math.min(lines.length, i + 10));
      if (!forwardWindow.some(l => CSHARP_XML_RESOLVER_NULL_RE.test(l))) {
        found.push({ id:"xxe", label:"XML External Entity (XXE)", severity:"critical", line:i+1,
          detail:"XmlDocument/XmlTextReader constructed with no XmlResolver = null nearby — external entity/DTD resolution may be enabled depending on target framework; explicitly set XmlResolver to null" });
      }
      continue;
    }
    if (CSHARP_DTD_PARSE_RE.test(line)) {
      found.push({ id:"xxe", label:"XML External Entity (XXE)", severity:"critical", line:i+1,
        detail:"XmlReaderSettings.DtdProcessing explicitly set to Parse — enables DTD/external-entity resolution; leave at the safe default (Prohibit) or use DtdProcessing.Ignore" });
      continue;
    }
    if (CSHARP_XML_RESOLVER_UNSAFE_RE.test(line)) {
      found.push({ id:"xxe", label:"XML External Entity (XXE)", severity:"critical", line:i+1,
        detail:"XmlResolver explicitly set to a live XmlUrlResolver — allows external entity/DTD resolution over the network; set XmlResolver to null instead" });
    }
  }
  return found;
}

function findLDAPInjection(lines: string[]): ScanIndicator[] {
  return runDetector(lines, LDAP_INJECT_RE, "ldap-injection", "LDAP Injection", "critical",
    "User input in LDAP filter — escape special chars or use parameterized LDAP libraries");
}

function findInsecureFileUpload(lines: string[]): ScanIndicator[] {
  return runDetector(lines, FILE_UPLOAD_RE, "insecure-file-upload", "Insecure File Upload", "high",
    "File upload without MIME validation and size limits — add fileFilter and limits to config");
}

// C# — IFormFile saved via CopyToAsync/File.Create/File.WriteAllBytes with
// no visible extension/content-type validation nearby. Needs a real
// backward-window function rather than a flat FILE_UPLOAD_RE entry (those
// use same-line-only forward lookaheads, and validation is almost always on
// a different line from the save call). Gated on IFormFile being in scope
// within the window (not a bare File.Create/CopyToAsync flat match) so this
// doesn't fire on unrelated, trusted internal file I/O that happens to
// share the same method names.
const CSHARP_FILE_UPLOAD_SINK_RE = /\.CopyToAsync\s*\(|\bFile\.(?:Create|WriteAllBytes)\s*\(/;
const CSHARP_FILE_UPLOAD_VALIDATION_RE = /allowedExtensions|AllowedExtensions|ContentType|content.?type|GetExtension|Path\.GetExtension|IsValidExtension|whitelist|allowlist|allowedTypes/i;

function findInsecureFileUploadCSharp(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;
    if (!CSHARP_FILE_UPLOAD_SINK_RE.test(lines[i])) continue;
    const windowStart = Math.max(0, i - 20);
    const window = lines.slice(windowStart, i + 1);
    if (!window.some(l => /\bIFormFile\b/.test(l))) continue;
    if (window.some(l => CSHARP_FILE_UPLOAD_VALIDATION_RE.test(l))) continue;
    found.push({ id:"insecure-file-upload", label:"Insecure File Upload", severity:"high", line:i+1,
      detail:"IFormFile saved to disk with no visible file-extension/content-type validation nearby — validate against an allowlist of extensions/MIME types and store outside the web root with a generated filename" });
  }
  return found;
}

// TOCTOU: check-then-act race (existsSync/statSync followed by fs operation within 10 lines)
function findTOCTOU(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    if (seen.has(i) || !TOCTOU_SOURCE_RE.test(lines[i])) continue;
    for (let j = i + 1; j < Math.min(lines.length, i + 10); j++) {
      if (TOCTOU_SINK_RE.test(lines[j])) {
        seen.add(i);
        found.push({ id:"toctou", label:"TOCTOU Race Condition", severity:"medium", line:i+1,
          detail:"File existence check followed by file operation — attacker can swap file in the window" });
        break;
      }
    }
  }
  return found;
}

// Cookie security: res.cookie() on session/auth cookies missing httpOnly or secure flag.
// Only flags cookies whose name suggests authentication or session data.
// Preference/analytics cookies missing these flags are low-value noise.
const AUTH_COOKIE_RE = /(?:session|sess|auth|token|jwt|sid|user[-_]?id|access[-_]?token|refresh[-_]?token|connect\.sid)/i;

function findCookieInsecurity(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    if (seen.has(i) || !/res\.cookie\s*\(/.test(lines[i])) continue;
    // Expand up to 6 lines to capture multi-line option objects
    const block = lines.slice(i, Math.min(lines.length, i + 6)).join(" ");
    if (!/res\.cookie\s*\(/.test(block)) continue;

    // Extract the cookie name from the first argument
    const nameMatch = block.match(/res\.cookie\s*\(\s*["'`]([^"'`]+)["'`]/);
    const cookieName = nameMatch?.[1] ?? "";

    // Only flag auth/session cookies — skipping analytics, preferences, etc.
    if (!AUTH_COOKIE_RE.test(cookieName)) continue;

    // Only flag if there IS an options object (third argument with {}) but flags are missing
    if (/res\.cookie\s*\([^,]+,[^,]+,\s*\{/.test(block)) {
      if (!/httpOnly\s*:\s*true/i.test(block)) {
        seen.add(i);
        found.push({ id:"cookie-no-httponly", label:"Auth Cookie Missing HttpOnly", severity:"medium",
          line:i+1, detail:`Session/auth cookie "${cookieName}" set without httpOnly:true — XSS can steal it via document.cookie` });
        continue;
      }
      if (!/secure\s*:\s*true/i.test(block)) {
        seen.add(i);
        found.push({ id:"cookie-no-secure", label:"Auth Cookie Missing Secure Flag", severity:"low",
          line:i+1, detail:`Session/auth cookie "${cookieName}" set without secure:true — transmitted over unencrypted HTTP` });
      }
    }
  }
  return found;
}

// Splits a call's raw argument-list text on top-level commas only (depth-
// tracked across (), [], {} so a nested call/array/object argument's own
// internal commas aren't mistaken for argument separators) -- needed for
// PHP's positional setcookie($name, $value, $expire, $path, $domain,
// $secure, $httponly) below, where argument POSITION (not a named
// property) carries the meaning.
function splitTopLevelArgs(argsStr: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of argsStr) {
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    if (ch === ")" || ch === "]" || ch === "}") depth--;
    if (ch === "," && depth === 0) {
      parts.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  if (current.trim().length > 0 || parts.length > 0) parts.push(current);
  return parts;
}

// Cookie security for Java (servlet Cookie built then mutated via setters,
// rather than an options-object literal) and Python Flask (set_cookie kwargs)
// — structurally different enough from res.cookie(name, val, {opts}) that
// findCookieInsecurity's block-parsing above doesn't apply.
function findCookieInsecurityOtherLangs(lines: string[]): ScanIndicator[] {
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isNonExecutableLine(lines[i])) continue;

    // Java servlet: Cookie c = new Cookie("session", value);
    const jm = /(\w+)\s*=\s*new\s+Cookie\s*\(\s*["']([^"']+)["']/.exec(lines[i]);
    if (jm && AUTH_COOKIE_RE.test(jm[2])) {
      const varName  = jm[1];
      const block    = lines.slice(i, Math.min(lines.length, i + 8)).join(" ");
      if (!new RegExp(`${varName}\\s*\\.\\s*setHttpOnly\\s*\\(\\s*true\\s*\\)`).test(block)) {
        found.push({ id:"cookie-no-httponly", label:"Auth Cookie Missing HttpOnly", severity:"medium",
          line:i+1, detail:`Session/auth cookie "${jm[2]}" created without a nearby setHttpOnly(true) call — XSS can steal it via document.cookie` });
      }
      continue;
    }

    // Python Flask: response.set_cookie("session", value, ...)
    if (/\.set_cookie\s*\(/.test(lines[i])) {
      const block = lines.slice(i, Math.min(lines.length, i + 4)).join(" ");
      const nameMatch  = block.match(/\.set_cookie\s*\(\s*["']([^"']+)["']/);
      const cookieName = nameMatch?.[1] ?? "";
      if (AUTH_COOKIE_RE.test(cookieName) && !/httponly\s*=\s*True/i.test(block)) {
        found.push({ id:"cookie-no-httponly", label:"Auth Cookie Missing HttpOnly", severity:"medium",
          line:i+1, detail:`Session/auth cookie "${cookieName}" set without httponly=True — XSS can steal it via document.cookie` });
      }
      continue;
    }

    // Go: http.SetCookie(w, &http.Cookie{Name: "session", Value: ..., ...})
    // -- a struct-literal shape structurally different from both the JS
    // options-object and the Java setter-call/Python kwarg shapes above, so
    // it needs its own branch. The struct literal is commonly multi-line
    // (an omitted HttpOnly/Secure/SameSite field, not an explicit false, is
    // the actual vulnerable shape), so this expands a forward window rather
    // than checking the single line the call starts on.
    if (/http\.SetCookie\s*\(/.test(lines[i])) {
      const block = lines.slice(i, Math.min(lines.length, i + 10)).join(" ");
      const nameMatch  = block.match(/Name\s*:\s*["']([^"']+)["']/);
      const cookieName = nameMatch?.[1] ?? "";
      if (AUTH_COOKIE_RE.test(cookieName)) {
        if (!/HttpOnly\s*:\s*true/i.test(block)) {
          found.push({ id:"cookie-no-httponly", label:"Auth Cookie Missing HttpOnly", severity:"medium",
            line:i+1, detail:`Session/auth cookie "${cookieName}" set without HttpOnly: true — XSS can steal it via document.cookie` });
        } else if (!/Secure\s*:\s*true/i.test(block)) {
          found.push({ id:"cookie-no-secure", label:"Auth Cookie Missing Secure Flag", severity:"low",
            line:i+1, detail:`Session/auth cookie "${cookieName}" set without Secure: true — transmitted over unencrypted HTTP` });
        }
      }
      continue;
    }

    // C#: Response.Cookies.Append("session", value, new CookieOptions {
    // HttpOnly = false, Secure = false, ... }) -- an object-initializer
    // shape, mirroring the Go struct-literal branch above exactly (same
    // forward-window-join technique), just with C#'s `=` instead of Go's
    // `:` inside the block.
    if (/\.Cookies\.Append\s*\(/.test(lines[i])) {
      const block = lines.slice(i, Math.min(lines.length, i + 10)).join(" ");
      const nameMatch  = block.match(/\.Cookies\.Append\s*\(\s*["']([^"']+)["']/);
      const cookieName = nameMatch?.[1] ?? "";
      if (AUTH_COOKIE_RE.test(cookieName)) {
        if (!/HttpOnly\s*=\s*true/i.test(block)) {
          found.push({ id:"cookie-no-httponly", label:"Auth Cookie Missing HttpOnly", severity:"medium",
            line:i+1, detail:`Session/auth cookie "${cookieName}" set without HttpOnly = true — XSS can steal it via document.cookie` });
        } else if (!/Secure\s*=\s*true/i.test(block)) {
          found.push({ id:"cookie-no-secure", label:"Auth Cookie Missing Secure Flag", severity:"low",
            line:i+1, detail:`Session/auth cookie "${cookieName}" set without Secure = true — transmitted over unencrypted HTTP` });
        }
      }
      continue;
    }

    // PHP: setcookie($name, $value, $expire, $path, $domain, $secure,
    // $httponly) -- POSITIONAL args (6th/7th are secure/httponly), a
    // structurally different shape from every branch above (all keyed off
    // a named property/kwarg) -- needs its own arg-position parsing rather
    // than a keyword scan. PHP 7.3+'s array-options 3rd-arg form
    // (setcookie($name, $value, ['secure' => true, 'httponly' => true]))
    // IS keyword-scannable like the branches above, handled as its own
    // case. Same "absence is itself flagged, not just explicit false" gate
    // the Go/C# branches above already use (`!/HttpOnly\s*:\s*true/`
    // matches both "explicitly false" and "not present at all").
    if (/\bsetcookie\s*\(/i.test(lines[i])) {
      const block = lines.slice(i, Math.min(lines.length, i + 6)).join(" ");
      const callMatch = /setcookie\s*\(([\s\S]*?)\);/i.exec(block);
      if (!callMatch) continue;
      const rawArgs = splitTopLevelArgs(callMatch[1]);
      const cookieName = (rawArgs[0] ?? "").trim().replace(/^["']|["']$/g, "");
      if (!AUTH_COOKIE_RE.test(cookieName)) continue;
      const arrayOptions = rawArgs.length === 3 ? rawArgs[2].trim() : null;
      if (arrayOptions?.startsWith("[")) {
        if (!/['"]httponly['"]\s*=>\s*true/i.test(arrayOptions)) {
          found.push({ id:"cookie-no-httponly", label:"Auth Cookie Missing HttpOnly", severity:"medium",
            line:i+1, detail:`Session/auth cookie "${cookieName}" set without 'httponly' => true — XSS can steal it via document.cookie` });
        } else if (!/['"]secure['"]\s*=>\s*true/i.test(arrayOptions)) {
          found.push({ id:"cookie-no-secure", label:"Auth Cookie Missing Secure Flag", severity:"low",
            line:i+1, detail:`Session/auth cookie "${cookieName}" set without 'secure' => true — transmitted over unencrypted HTTP` });
        }
      } else {
        const isTruthy = (s: string | undefined) => !!s && /^(?:true|1)$/i.test(s.trim());
        if (!isTruthy(rawArgs[6])) {
          found.push({ id:"cookie-no-httponly", label:"Auth Cookie Missing HttpOnly", severity:"medium",
            line:i+1, detail:`Session/auth cookie "${cookieName}" set without the httponly positional arg (7th) set to true — XSS can steal it via document.cookie` });
        } else if (!isTruthy(rawArgs[5])) {
          found.push({ id:"cookie-no-secure", label:"Auth Cookie Missing Secure Flag", severity:"low",
            line:i+1, detail:`Session/auth cookie "${cookieName}" set without the secure positional arg (6th) set to true — transmitted over unencrypted HTTP` });
        }
      }
    }
  }
  return found;
}

// Enhanced SSRF with multi-line taint
function findSSRFTainted(lines: string[]): ScanIndicator[] {
  const HTTP_SINK_RE = [
    /\b(?:fetch|axios|got|needle|superagent|request)\s*\(\s*\w+/i,
    /https?\.(?:get|request)\s*\(\s*\w+/,
    /new\s+URL\s*\(\s*\w+/,
  ];
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (const re of HTTP_SINK_RE) {
    for (let i = 0; i < lines.length; i++) {
      if (seen.has(i)) continue;
      if (isNonExecutableLine(lines[i])) continue;
      if (!re.test(lines[i])) continue;
      // Skip if already caught by direct SSRF patterns
      if (SSRF_RE.some(r => r.test(lines[i]))) continue;
      if (hasTaintNearby(lines, i, 10)) {
        seen.add(i);
        found.push({ id:"ssrf", label:"SSRF via Taint Propagation", severity:"critical", line:i+1,
          detail:"User input assigned within 10 lines and flows into HTTP request — SSRF risk" });
      }
    }
  }
  return found;
}

// Taint-proximity detectors for Java (and other heavily-formatted code)
// found via a real Spring Boot benchmark: two compounding gaps meant every
// named-variable detector (SQLi/command-injection/XSS/path-traversal) missed
// real, textbook vulnerabilities that SSRF (via findSSRFTainted above) still
// caught. (1) Spring's @RequestParam/@PathVariable/@RequestBody-annotated
// *method parameters* are a taint source with no assignment statement at all
// -- extractTaintedVars' named-variable tracker has no way to see them,
// while TAINT_SOURCES/hasTaintNearby (used by findSSRFTainted) already does.
// (2) Java's common "one operand per line" formatting style routinely spreads
// a single concatenation expression across 3+ lines, so no single line ever
// contains both a SQL/shell keyword and the "+"/tainted-variable half a
// same-line pattern needs. Mirrors findSSRFTainted's exact shape -- a real
// sink call name + any taint evidence within a nearby window, rather than
// exact-name matching -- since that's the one approach already proven to
// work against this exact problem in this exact codebase.
function findCommandInjectionTainted(lines: string[]): ScanIndicator[] {
  const CMD_SINK_RE = [
    /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/,
    /new\s+ProcessBuilder\s*\(/,
  ];
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (const re of CMD_SINK_RE) {
    for (let i = 0; i < lines.length; i++) {
      if (seen.has(i)) continue;
      if (isNonExecutableLine(lines[i])) continue;
      if (!re.test(lines[i])) continue;
      if (CMD_INJECTION_RE.some(r => r.test(lines[i]))) continue;
      if (hasTaintNearby(lines, i, 10)) {
        seen.add(i);
        found.push({ id:"command-injection", label:"Command Injection", severity:"critical", line:i+1,
          detail:"User input assigned within 10 lines and flows into a process-execution call — validate/allowlist arguments and avoid shell interpretation" });
      }
    }
  }
  return found;
}

function findSQLInjectionJavaTainted(lines: string[]): ScanIndicator[] {
  const SQL_SINK_RE = [
    /\bexecuteQuery\s*\(\s*\w+\s*\)/,
    /\bexecuteUpdate\s*\(\s*\w+\s*\)/,
    /\.execute\s*\(\s*\w+\s*\)/,
    /jdbcTemplate\s*\.\s*(?:query|update|execute)\s*\(\s*\w+/,
  ];
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (const re of SQL_SINK_RE) {
    for (let i = 0; i < lines.length; i++) {
      if (seen.has(i)) continue;
      if (isNonExecutableLine(lines[i])) continue;
      if (!re.test(lines[i])) continue;
      if (SQL_INJECTION_RE.some(r => r.test(lines[i]))) continue;
      if (hasTaintNearby(lines, i, 10)) {
        seen.add(i);
        found.push({ id:"sql-injection", label:"SQL Injection", severity:"critical", line:i+1,
          detail:"User input assigned within 10 lines and flows into a query-execution call — use a PreparedStatement with bound parameters" });
      }
    }
  }
  return found;
}

// C# — CommandText built on one line, executed several lines later (the
// dominant ADO.NET idiom: cmd.CommandText = query; ... cmd.ExecuteReader();),
// or FromSqlRaw/ExecuteSqlRaw called with a bare variable. Mirrors
// findSQLInjectionJavaTainted's proximity-window shape. Explicitly guards
// against flagging the common, fully-safe parameterized ADO.NET idiom
// (cmd.Parameters.AddWithValue(...)) -- without this guard it would
// over-fire on well-written parameterized code whenever any tainted value
// happens to be nearby (e.g. the very value being safely bound).
function findSQLInjectionCSharpTainted(lines: string[]): ScanIndicator[] {
  const CSHARP_SQL_SINK_RE = [
    /\.ExecuteReader\s*\(\s*\)/,
    /\.ExecuteNonQuery\s*\(\s*\)/,
    /\.ExecuteScalar\s*\(\s*\)/,
    /\.FromSqlRaw\s*\(\s*\w+\s*[,)]/,
    /\.ExecuteSqlRaw\s*\(\s*\w+\s*[,)]/,
  ];
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (const re of CSHARP_SQL_SINK_RE) {
    for (let i = 0; i < lines.length; i++) {
      if (seen.has(i)) continue;
      if (isNonExecutableLine(lines[i])) continue;
      if (!re.test(lines[i])) continue;
      if (SQL_INJECTION_RE.some(r => r.test(lines[i]))) continue;
      const windowStart = Math.max(0, i - 10);
      const window = lines.slice(windowStart, i + 1);
      if (window.some(l => /\.Parameters\.(?:Add|AddWithValue)\s*\(/.test(l))) continue; // parameterized — safe
      if (hasTaintNearby(lines, i, 10)) {
        seen.add(i);
        found.push({ id:"sql-injection", label:"SQL Injection", severity:"critical", line:i+1,
          detail:"User input assigned within 10 lines and flows into a query-execution call — use parameterized queries (SqlParameter/@param) or EF's FromSqlInterpolated" });
      }
    }
  }
  return found;
}

function findReflectedXSSTainted(lines: string[]): ScanIndicator[] {
  const HTML_SINK_RE = [
    /\.contentType\s*\(\s*MediaType\.TEXT_HTML\s*\)/,
    /\.body\s*\(\s*\w+\s*\)\s*;?\s*$/,
    /\bres\.(?:send|write)\s*\(\s*\w+\s*\)/,
  ];
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (const re of HTML_SINK_RE) {
    for (let i = 0; i < lines.length; i++) {
      if (seen.has(i)) continue;
      if (isNonExecutableLine(lines[i])) continue;
      if (!re.test(lines[i])) continue;
      if (XSS_RE.some(r => r.test(lines[i]))) continue;
      // Restricted to a shorter, backward-only window and requires an
      // actual HTML-looking string literal nearby (an opening "<" tag) --
      // .body(x)/res.send(x) are used constantly for plain JSON/text
      // responses, so without this extra corroboration this would be far
      // noisier than the other taint-proximity checks here.
      const window = lines.slice(Math.max(0, i - 8), i + 1);
      if (!window.some(l => /<\w+[ >]/.test(l))) continue;
      if (hasTaintNearby(lines, i, 8)) {
        seen.add(i);
        found.push({ id:"xss", label:"Reflected XSS", severity:"high", line:i+1,
          detail:"User input assigned within 8 lines and returned as raw HTML in the response body — sanitize/escape or use a templating engine with auto-escaping" });
      }
    }
  }
  return found;
}

function findPathTraversalTainted(lines: string[]): ScanIndicator[] {
  const FS_SINK_RE = [
    /Paths\s*\.\s*get\s*\(/,
    /new\s+File\s*\(/,
    /Files\s*\.\s*(?:readString|readAllBytes|write|newInputStream|newOutputStream|delete)\s*\(/,
  ];
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (const re of FS_SINK_RE) {
    for (let i = 0; i < lines.length; i++) {
      if (seen.has(i)) continue;
      if (isNonExecutableLine(lines[i])) continue;
      if (!re.test(lines[i])) continue;
      if (PATH_TRAVERSAL_RE.some(r => r.test(lines[i]))) continue;
      if (hasTaintNearby(lines, i, 10)) {
        seen.add(i);
        found.push({ id:"path-traversal", label:"Path Traversal", severity:"critical", line:i+1,
          detail:"User input assigned within 10 lines and flows into a file path — resolve and validate the result stays within the intended base directory" });
      }
    }
  }
  return found;
}

// Enhanced SQL injection with multi-line taint
function findSQLInjectionTainted(lines: string[]): ScanIndicator[] {
  const DB_SINK_RE = [
    /(?:db|pool|conn|client|connection)\.(?:query|execute|run)\s*\(`[^`]*\$\{/,
    /\bprepare\s*\(`[^`]*\$\{/,
  ];
  const found: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (const re of DB_SINK_RE) {
    for (let i = 0; i < lines.length; i++) {
      if (seen.has(i)) continue;
      if (isNonExecutableLine(lines[i])) continue;
      if (!re.test(lines[i])) continue;
      if (hasTaintNearby(lines, i, 10)) {
        seen.add(i);
        found.push({ id:"sql-injection", label:"SQL Injection via Taint", severity:"critical", line:i+1,
          detail:"User input reaches DB query through template literal — use parameterised queries" });
      }
    }
  }
  return found;
}

// ══════════════════════════════════════════════════════════════════════════════
// AI DETECTION SIGNALS  (22 total)
// Each returns a value in [0, 1].  0 = no evidence, 1 = strong evidence.
// ══════════════════════════════════════════════════════════════════════════════

// Signal 1: AI Comment Phrasing (q = 0.78)
const COMMENT_PHRASING_RE = [
  // ── Original patterns ─────────────────────────────────────────────────────
  /(?:\/\/|#)\s*This (?:function|method|component|class|helper)\s+(?:takes|accepts|returns|handles|processes|creates|updates|deletes)\b/i,
  /(?:\/\/|#)\s*(?:Returns?|Gets?)\s+(?:a|an|the)\s+\w+\s+(?:object|array|list|string|number|boolean|map|set)\b/i,
  /(?:\/\/|#)\s*Step\s+\d+[:.]/i,
  /(?:\/\/|#)\s*(?:Note|Important|Warning):\s+(?:This|The|We|Make sure)\b/i,
  /\*\s*@(?:param|returns?)\s+\{[^}]+\}\s+\w+\s*[-—]\s*(?:The|A|An)\s+\w+/i,
  /(?:^|\n)\s*(?:Args|Returns|Raises|Yields|Parameters|Attributes|Example(?:s)?):\s*$/m,
  /(?:\/\/|#)\s*(?:Here we|Let's|We can|We need to|We then)\b/i,
  /(?:\/\/|#)\s*This (?:implementation|approach|method|solution)\b/i,
  /(?:\/\/|#)\s*This (?:ensures|guarantees|allows|enables|prevents)\b/i,
  /(?:\/\/|#)\s*(?:For example|As an example|For instance)\b/i,
  /\*\s*@example\s*\n/,
  /\*\s*@throws?\s+\{[^}]+\}/i,
  /(?:\/\/|#)\s*(?:Simply|Just|Easily)\s+\w/i,
  /(?:\/\/|#)\s*The following\s+(?:function|method|class|code|example|snippet)\b/i,
  /(?:\/\/|#)\s*(?:Helper|Utility|Convenience)\s+(?:function|method|class)\s+(?:to|for|that)\b/i,
  /(?:\/\/|#)\s*(?:Validates?|Checks?|Verifies?)\s+(?:that|whether|if)\s+the\b/i,

  // ── Modern LLM JSDoc patterns (GPT-4 / Claude style) ─────────────────────
  // Plain JSDoc descriptions starting with verbs — the most common LLM output
  /\*\s+(?:Creates?|Updates?|Deletes?|Handles?|Validates?|Processes?|Fetches?|Sends?|Builds?|Generates?|Initializes?|Loads?|Saves?|Checks?|Verifies?|Computes?|Calculates?|Formats?|Parses?|Transforms?|Converts?|Extracts?|Retrieves?|Submits?|Triggers?|Performs?|Executes?|Manages?|Configures?)\s+(?:a|an|the|all|new|this|any|each|the\s+\w+)/im,
  // "* Returns the ... for ..." — plain @returns without type annotation
  /\*\s+(?:Returns?|Gets?)\s+(?:the|a|an)\s+\w[\w\s]{5,50}(?:for|from|of|based on)/im,
  // Multi-line JSDoc body: two consecutive description lines (no @ tags)
  /\/\*\*\s*\n\s*\*\s+\w[^\n@]{20,}\n\s*\*\s+\w[^\n@]{10,}/m,
  // "* @returns The ..." without braces (LLM often omits type in @returns)
  /\*\s*@returns?\s+(?:The|A|An|This)\s+\w/im,
  // Inline "// Initialise/Initialize/Set up ..." imperative patterns
  /(?:\/\/|#)\s*(?:Initialise|Initialize|Set up|Set the|Register the|Configure the|Create the|Add the|Remove the|Update the|Check if|Ensure that)\b/i,
];

function sigCommentPhrasing(content: string): number {
  let hits = 0;
  for (const re of COMMENT_PHRASING_RE) if (re.test(content)) hits++;
  // Modern LLM output (GPT-4/Claude) typically scores 4-8 on this expanded set.
  // Human code rarely scores above 2-3.
  return hits >= 7 ? 1.0
       : hits === 6 ? 0.88
       : hits === 5 ? 0.72
       : hits === 4 ? 0.55
       : hits === 3 ? 0.35
       : hits === 2 ? 0.15
       : 0;
}

// Signal 1b: JSDoc completeness — AI documents every function; humans skip obvious ones.
// Not in SIGNAL_LEAKS (used as amplifier inside sigLanguageSpecific via language-specific path).
function sigJSDocCompleteness(content: string): number {
  const jsdocBlocks  = (content.match(/\/\*\*[\s\S]+?\*\//g) ?? []).length;
  if (jsdocBlocks < 2) return 0;
  // Count exported/public functions and class methods
  const funcCount = (content.match(
    /(?:export\s+(?:default\s+)?(?:async\s+)?function\s+\w+|(?:public|private|protected)\s+(?:static\s+)?(?:async\s+)?\w+\s*\(|\b(?:async\s+)?function\s+\w+\s*\()/g
  ) ?? []).length;
  if (funcCount < 2) return 0;
  const ratio = jsdocBlocks / funcCount;
  // Near-100% JSDoc coverage is rare in human code; AI documents everything
  if (ratio > 0.90 && jsdocBlocks >= 4) return 0.90;
  if (ratio > 0.75 && jsdocBlocks >= 3) return 0.65;
  if (ratio > 0.60 && jsdocBlocks >= 2) return 0.40;
  return 0;
}

// Signal 2: Language-Specific AI Patterns (q = 0.70)
function sigLanguageSpecific(content: string, lang: string): number {
  switch (lang) {
    case "python":     return sigPython(content);
    case "typescript":
    case "javascript": return sigTypeScript(content);
    case "golang":     return sigGo(content);
    case "java":       return sigJava(content);
    case "rust":       return sigRust(content);
    case "csharp":     return sigCSharp(content);
    case "ruby":       return sigRuby(content);
    case "php":        return sigPHP(content);
    case "swift":      return sigSwift(content);
    case "kotlin":     return sigKotlin(content);
    default:           return 0;
  }
}

function sigPython(c: string): number {
  let s = 0;
  const funcs = (c.match(/def\s+\w+\([^)]+\)/g) ?? []);
  const typed  = funcs.filter(f => /:\s*(?:str|int|float|bool|list|dict|Optional|Union|Any|List|Dict|Tuple|Type|Callable|Sequence|Iterable)\b/.test(f));
  if (funcs.length >= 2 && typed.length / funcs.length > 0.8) s += 0.30;
  const fstr   = (c.match(/f["'][^"'\n]*\{/g) ?? []).length;
  const oldFmt = (c.match(/["'][^"'\n]*%[sdrf]/g) ?? []).length + (c.match(/\.format\s*\(/g) ?? []).length;
  if (fstr > 2 && oldFmt === 0) s += 0.20;
  if (/(?:Args|Returns|Raises|Yields):\s*\n(?:\s+\w[^:\n]+:[^\n]+\n){1,}/.test(c)) s += 0.25;
  if (/@dataclass\b/.test(c) || /class\s+\w+\s*\(\s*BaseModel\s*\)/.test(c)) s += 0.15;
  if (/from\s+typing\s+import\s+(?:\w+,\s*){2,}\w+/.test(c)) s += 0.10;
  if (/\w+\s*:=\s*\w/.test(c)) s += 0.10;
  if (/^\s*match\s+\w+:/m.test(c) && /^\s*case\s+/m.test(c)) s += 0.10;
  // Exhaustive type annotations on class fields
  if ((c.match(/^\s+\w+\s*:\s*(?:str|int|float|bool|Optional|List|Dict|Any)\s*(?:=|$)/m) ?? []).length > 2) s += 0.10;
  return Math.min(1, s);
}

function sigTypeScript(c: string): number {
  let s = 0;
  const ifaces = (c.match(/\binterface\s+\w+\s*\{/g) ?? []).length;
  const types  = (c.match(/\btype\s+\w+\s*=\s*\{/g) ?? []).length;
  if (ifaces > 2 && ifaces > types) s += 0.20;
  const retTyped  = (c.match(/\)\s*:\s*(?:Promise<|void|string|number|boolean|Record|Array|\w+\[\])/g) ?? []).length;
  const funcTotal = (c.match(/(?:function\s+\w+|\w+\s*=\s*(?:async\s+)?\()/g) ?? []).length;
  if (funcTotal >= 3 && retTyped / funcTotal > 0.6) s += 0.20;
  const consts = (c.match(/\bconst\b/g) ?? []).length;
  const lets   = (c.match(/\blet\b/g) ?? []).length;
  if (consts >= 4 && consts > lets * 3) s += 0.15;
  const optChain = (c.match(/\?\./g) ?? []).length;
  const nullCoal = (c.match(/\?\?/g) ?? []).length;
  if (optChain + nullCoal > 5) s += 0.15;
  if (/\bas\s+const\b|\bsatisfies\b/.test(c)) s += 0.10;
  if ((c.match(/readonly\s+\w+/g) ?? []).length > 2) s += 0.10;
  if (/case\s+\w+:\s*\{?[\s\S]{0,100}default:\s*(?:throw|return).*never/.test(c)) s += 0.10;
  if (/const\s*\{\s*(?:\w+\s*,\s*){4,}\w+\s*\}/.test(c)) s += 0.10;
  // Pick<T, ...> / Omit<T, ...> / Partial<T> usage
  if (/\b(?:Pick|Omit|Partial|Required|Readonly|NonNullable|ReturnType|Parameters)\s*</.test(c)) s += 0.10;
  return Math.min(1, s);
}

function sigGo(c: string): number {
  let s = 0;
  const errChecks = (c.match(/if\s+err\s*!=\s*nil/g) ?? []).length;
  const returns   = (c.match(/\breturn\b/g) ?? []).length;
  if (returns > 2 && errChecks / returns > 0.4) s += 0.30;
  if (/fmt\.Errorf\("[^"]*%w"/.test(c)) s += 0.25;
  if ((c.match(/func\s+\w+\(ctx\s+context\.Context/g) ?? []).length > 0) s += 0.20;
  if (/\/\/\s+Package\s+\w+\s+(?:provides|implements|defines|contains)\b/.test(c)) s += 0.15;
  const exp = (c.match(/^\s+[A-Z]\w+\s+\w+/gm) ?? []).length;
  const unexp = (c.match(/^\s+[a-z]\w+\s+\w+/gm) ?? []).length;
  if (exp > 3 && exp > unexp * 2) s += 0.10;
  return Math.min(1, s);
}

function sigJava(c: string): number {
  let s = 0;
  if (/@(?:Data|Builder|Getter|Setter|AllArgsConstructor|NoArgsConstructor|RequiredArgsConstructor)\b/.test(c)) s += 0.30;
  const javadoc = (c.match(/\/\*\*[\s\S]{20,}?\*\//g) ?? []).length;
  const methods = (c.match(/(?:public|private|protected)\s+\w[\w<>[\]]*\s+\w+\s*\(/g) ?? []).length;
  if (methods >= 2 && javadoc / methods > 0.7) s += 0.25;
  if ((c.match(/@Override\b/g) ?? []).length >= 2) s += 0.15;
  if (/Optional\.(?:of|ofNullable|empty)\s*\(/.test(c)) s += 0.15;
  if (/\.stream\(\)[\s\S]{0,100}\.collect\(/.test(c)) s += 0.15;
  return Math.min(1, s);
}

function sigRust(c: string): number {
  let s = 0;
  const unwraps = (c.match(/\.unwrap\(\)/g) ?? []).length;
  const lineCount = c.split("\n").length;
  if (lineCount > 20 && unwraps / lineCount > 0.04) s += 0.35;
  const derived = (c.match(/#\[derive\([^\]]+\)\]\s*(?:pub\s+)?struct/g) ?? []).length;
  const structs = (c.match(/(?:pub\s+)?struct\s+\w+/g) ?? []).length;
  if (structs >= 2 && derived / structs > 0.7) s += 0.30;
  if (/\/\/\/\s+\w{5,}/.test(c)) s += 0.20;
  if ((c.match(/\?\s*;/g) ?? []).length > 3) s += 0.15;
  return Math.min(1, s);
}

function sigCSharp(c: string): number {
  let s = 0;
  const xmlDocs   = (c.match(/\/\/\/\s*<summary>/g) ?? []).length;
  const pubMembers = (c.match(/public\s+(?:(?:static|virtual|override|async)\s+)*\w[\w<>[\],\s]*\s+\w+\s*[({]/g) ?? []).length;
  if (pubMembers >= 2 && xmlDocs / pubMembers > 0.7) s += 0.30;
  if (/\.Where\(|\.Select\(|\.FirstOrDefault\(|\.ToList\(/.test(c)) s += 0.20;
  const nullCond = (c.match(/\?\./g) ?? []).length + (c.match(/\?\?/g) ?? []).length;
  if (nullCond > 4) s += 0.20;
  if ((c.match(/\basync\s+Task/g) ?? []).length > 2) s += 0.15;
  return Math.min(1, s);
}

function sigRuby(c: string): number {
  let s = 0;
  if (/# frozen_string_literal: true/.test(c)) s += 0.25;
  if ((c.match(/attr_(?:reader|writer|accessor)\s+:\w+/g) ?? []).length > 1) s += 0.20;
  if (/rescue\s+\w+Error\s*=>\s*\w\s*\n\s*(?:Rails\.logger|logger)\.(?:error|warn)/.test(c)) s += 0.20;
  if ((c.match(/(?:describe|context|it)\s+["'][^"']+["']\s+do/g) ?? []).length > 3) s += 0.15;
  const newSyntax = (c.match(/\w+:/g) ?? []).length;
  const oldSyntax = (c.match(/:\w+\s*=>/g) ?? []).length;
  if (newSyntax > 4 && oldSyntax === 0) s += 0.10;
  return Math.min(1, s);
}

function sigPHP(c: string): number {
  let s = 0;
  const phpdoc  = (c.match(/\/\*\*[\s\S]{10,}?@(?:param|return|throws)\b[\s\S]{0,300}?\*\//g) ?? []).length;
  const methods = (c.match(/(?:public|private|protected)\s+function\s+\w+/g) ?? []).length;
  if (methods >= 2 && phpdoc / methods > 0.7) s += 0.35;
  if (/\bmatch\s*\(/.test(c)) s += 0.20;
  if (/declare\s*\(\s*strict_types\s*=\s*1\s*\)/.test(c)) s += 0.20;
  if (/:\s*\w+\s*\|\s*\w+/.test(c)) s += 0.15;
  return Math.min(1, s);
}

function sigSwift(c: string): number {
  let s = 0;
  if ((c.match(/guard\s+(?:let|var)\s+\w+\s*=\s*.+\s+else\s*\{/g) ?? []).length > 1) s += 0.30;
  if (/\bsome\s+\w+\b|\bany\s+\w+\b/.test(c)) s += 0.20;
  if ((c.match(/\/\/\/.*\n(?:\s*\/\/\/.*\n)+/g) ?? []).length > 0) s += 0.25;
  if (/\.map\s*\{|\\.compactMap\s*\{|\.filter\s*\{|\.sorted\s*\{/.test(c)) s += 0.15;
  if (/@MainActor\b|@Published\b|@State\b|@Binding\b/.test(c)) s += 0.10;
  return Math.min(1, s);
}

function sigKotlin(c: string): number {
  let s = 0;
  if ((c.match(/fun\s+\w+\([^)]*\)\s*:\s*\w+/g) ?? []).length >= 3) s += 0.25;
  if (/\bdata\s+class\b/.test(c)) s += 0.20;
  if (/\?\s*\?:|let\s*\{|run\s*\{|apply\s*\{|also\s*\{|takeIf\s*\{/.test(c)) s += 0.20;
  if (/when\s*\([^)]+\)\s*\{[\s\S]{0,300}else\s*->/.test(c)) s += 0.20;
  if (/@Composable\b/.test(c)) s += 0.15;
  return Math.min(1, s);
}

// Signal 3: Documentation Coverage (q = 0.60)
function sigDocumentationCoverage(content: string, lang: string): number {
  if (lang === "typescript" || lang === "javascript") {
    const exported = (content.match(/export\s+(?:default\s+)?(?:async\s+)?function\s+\w+|export\s+const\s+\w+\s*=\s*(?:async\s+)?\(/g) ?? []).length;
    if (exported < 2) return 0;
    const jsdoc = (content.match(/\/\*\*[\s\S]{10,400}?\*\//g) ?? []).length;
    const ratio = jsdoc / exported;
    return ratio >= 1 ? 1 : ratio > 0.7 ? (ratio - 0.7) / 0.3 : 0;
  }
  if (lang === "python") {
    const funcs = (content.match(/^\s*(?:async\s+)?def\s+\w+/gm) ?? []).length;
    if (funcs < 2) return 0;
    const docstrings = (content.match(/def\s+\w+[^:]*:\s*\n\s*"""/g) ?? []).length;
    const ratio = docstrings / funcs;
    return ratio >= 0.9 ? 1 : ratio > 0.6 ? (ratio - 0.6) / 0.3 : 0;
  }
  if (lang === "golang") {
    const exported = (content.match(/^func\s+[A-Z]\w+/gm) ?? []).length;
    if (exported < 2) return 0;
    const godoc = (content.match(/\/\/\s+[A-Z]\w+\s+(?:is|creates?|returns?|handles?|processes?|builds?|validates?)\b/gm) ?? []).length;
    const ratio = godoc / exported;
    return ratio >= 0.8 ? 1 : ratio > 0.5 ? (ratio - 0.5) / 0.3 : 0;
  }
  if (lang === "java") {
    const methods = (content.match(/(?:public|private|protected)\s+\w[\w<>[\]]*\s+\w+\s*\(/g) ?? []).length;
    if (methods < 2) return 0;
    const javadoc = (content.match(/\/\*\*[\s\S]{20,}?\*\//g) ?? []).length;
    const ratio = javadoc / methods;
    return ratio >= 0.8 ? 1 : ratio > 0.5 ? (ratio - 0.5) / 0.3 : 0;
  }
  return 0;
}

// Signal 4: Dead Code Absence (q = 0.30)
function sigDeadCodeAbsence(content: string, lineCount: number): number {
  if (lineCount < 30) return 0;
  const commentedCode  = (content.match(/(?:\/\/|#)\s*(?:[a-z_]{3,}\s*\(|(?:if|for|while|return|const|let|var)\s+\w)/gi) ?? []).length;
  const informalTodos  = (content.match(/(?:\/\/|#)\s*(?:FIXME|HACK|XXX|wtf|temp|old|remove|unused|debug|broken)\b/gi) ?? []).length;
  const datedComments  = (content.match(/(?:\/\/|#)\s*\d{4}-\d{2}-\d{2}/g) ?? []).length;
  const debugPrints    = (content.match(/console\.debug\b|pprint\s*\(|debugger\b|breakpoint\s*\(/g) ?? []).length;
  const leftoverPrints = (content.match(/print\s*\(["']DEBUG|print\s*\(["']TEST/gi) ?? []).length;
  const humanDebt = (commentedCode + informalTodos * 2 + datedComments * 2 + debugPrints + leftoverPrints) / (lineCount / 100);
  return Math.max(0, 1 - humanDebt * 0.8);
}

// Signal 5: Function Size Uniformity (q = 0.50)
function sigFunctionSizeUniformity(content: string, lang: string): number {
  const sizes: number[] = [];
  if (lang === "typescript" || lang === "javascript") {
    const funcRe = /(?:(?:async\s+)?function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\([^)]*\)\s*=>|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?function)\s*[({]/g;
    let m: RegExpExecArray | null;
    while ((m = funcRe.exec(content)) !== null) {
      let depth = 0, i = m.index;
      for (; i < Math.min(content.length, m.index + 5000); i++) {
        if (content[i] === "{") depth++;
        else if (content[i] === "}") { depth--; if (depth <= 0) { sizes.push(content.slice(m.index, i).split("\n").length); break; } }
      }
    }
  } else if (lang === "python") {
    const lines = content.split("\n");
    let inDef = false, count = 0, baseIndent = 0;
    for (const line of lines) {
      if (/^\s*(?:async\s+)?def\s+\w+/.test(line)) {
        if (inDef && count > 1) sizes.push(count);
        inDef = true; count = 1;
        baseIndent = (line.match(/^(\s*)/)?.[1].length ?? 0);
      } else if (inDef) {
        const indent = line.match(/^(\s*)/)?.[1].length ?? 0;
        if (line.trim() && indent <= baseIndent && !/^\s*(?:#|$)/.test(line)) {
          sizes.push(count); inDef = false; count = 0;
        } else count++;
      }
    }
    if (inDef && count > 1) sizes.push(count);
  }
  if (sizes.length < 3) return 0;
  const mean   = sizes.reduce((a, b) => a + b, 0) / sizes.length;
  if (mean < 3) return 0;
  const stddev = Math.sqrt(sizes.reduce((s, x) => s + (x - mean) ** 2, 0) / sizes.length);
  const cv     = stddev / mean;
  return cv < 0.25 ? 1.0 : cv < 0.60 ? 1 - (cv - 0.25) / 0.35 : 0;
}

// Signal 6: Error Handling Uniformity (q = 0.55)
function sigErrorHandlingUniformity(content: string, lang: string): number {
  if (lang === "typescript" || lang === "javascript") {
    const catches = content.match(/catch\s*\([^)]*\)\s*\{([^}]{0,400})\}/g) ?? [];
    if (catches.length < 3) return 0;
    const classify = (b: string): string => {
      if (/NextResponse.*(?:json|error)/i.test(b) || /return.*status.*[45]\d\d/.test(b)) return "http";
      if (/throw\s+(?:new\s+)?(?:Error|HttpException|\w+Error)/.test(b)) return "rethrow";
      if (/(?:logger|console)\.(error|warn)/.test(b)) return "log";
      if (/return\s+(?:null|undefined|false|\{\})/.test(b)) return "null";
      return "other";
    };
    const buckets = catches.map(c => classify(c));
    const counts: Record<string, number> = {};
    for (const b of buckets) counts[b] = (counts[b] ?? 0) + 1;
    const uniformity = Math.max(...Object.values(counts)) / buckets.length;
    return uniformity > 0.85 ? (uniformity - 0.85) / 0.15 : 0;
  }
  if (lang === "golang") {
    const errfmt = (content.match(/fmt\.Errorf\("[^"]*%w"/g) ?? []).length;
    const errnil = (content.match(/if\s+err\s*!=\s*nil/g) ?? []).length;
    if (errnil < 3) return 0;
    return Math.min(1, errfmt / errnil);
  }
  if (lang === "python") {
    const excepts = content.match(/except\s+(?:\w+(?:\s*,\s*\w+)*)?\s*(?:as\s+\w+)?:/g) ?? [];
    if (excepts.length < 3) return 0;
    const bare  = excepts.filter(e => /except\s*:/.test(e)).length;
    const typed = excepts.filter(e => /except\s+\w+/.test(e)).length;
    return typed / excepts.length > 0.9 && bare === 0 ? 0.8 : 0;
  }
  return 0;
}

// Signal 7: Naming Consistency (q = 0.35)
function sigNamingConsistency(content: string): number {
  const camelCase = (content.match(/\b[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*\b/g) ?? []).length;
  const snakeCase = (content.match(/\b[a-z][a-z0-9]+_[a-z][a-z0-9_]+\b/g) ?? []).length;
  const total = camelCase + snakeCase;
  if (total < 12) return 0;
  const dominance = Math.max(camelCase, snakeCase) / total;
  // Raised from 0.97 → 0.995. ESLint with naming-convention rules pushes any
  // modern TypeScript project to > 97% dominance. Only flag near-perfect
  // uniformity (essentially zero naming exceptions), which even linted human
  // code rarely achieves because of third-party types and edge-case names.
  return dominance > 0.995 ? 1.0 : dominance > 0.985 ? (dominance - 0.985) / 0.01 : 0;
}

// Signal 8: Structural Repetition (q = 0.45)
function sigStructuralRepetition(lines: string[]): number {
  const content   = lines.join("\n");
  const codeLines = lines.filter(l => l.trim().length > 3);
  if (codeLines.length < 15) return 0;
  const tryCatch  = (content.match(/\btry\s*\{/g) ?? []).length;
  const funcCount = Math.max(1, (content.match(/\bfunction\b|\bdef\b|\bfunc\s+\w+|\b=>\s*\{/g) ?? []).length);
  const tcRatio   = Math.min(1, tryCatch / funcCount);
  const lengths   = codeLines.map(l => l.trimEnd().length);
  const mean      = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  const stddev    = Math.sqrt(lengths.reduce((s, l) => s + (l - mean) ** 2, 0) / lengths.length);
  const cvLen     = stddev / Math.max(1, mean);
  const lenUniformity = cvLen < 0.25 ? 1 : cvLen < 0.50 ? 1 - (cvLen - 0.25) / 0.25 : 0;
  const jsdoc      = (content.match(/\/\*\*[\s\S]{5,300}?\*\//g) ?? []).length;
  const jsdocRatio = Math.min(1, jsdoc / funcCount);
  return Math.min(1, tcRatio * 0.30 + lenUniformity * 0.40 + jsdocRatio * 0.30);
}

// Signal 9: Boilerplate Density (q = 0.40)
function sigBoilerplateDensity(content: string, lineCount: number): number {
  if (lineCount < 20) return 0;
  const per100 = 100 / lineCount;
  const counts = [
    /try\s*\{[\s\S]{0,400}?\}\s*catch/g,
    /if\s*\(\s*(?:![\w.]+|[\w.]+\s*===?\s*(?:null|undefined))\s*\)\s*(?:return|throw)/g,
    /console\.(log|error|warn)\s*\(/g,
    /(?:logger|log)\.(info|debug|error|warn)\s*\(/g,
    /if\s*\(![\w.]+\)\s*(?:return|throw)/g,
    /if\s*\(\s*typeof\s+\w+\s*===?\s*["']undefined["']\s*\)/g,
  ].reduce((sum, re) => sum + (content.match(re) ?? []).length, 0);
  return Math.min(1, (counts * per100) / 5);
}

// Signal 10: Comment Density (q = 0.15)
function sigCommentDensity(lines: string[], lang: string): number {
  const isComment = (l: string): boolean => {
    const t = l.trim();
    if (lang === "python") return t.startsWith("#") || t.startsWith('"""') || t.startsWith("'''");
    if (lang === "shell")  return t.startsWith("#");
    return t.startsWith("//") || t.startsWith("*") || t.startsWith("/*");
  };
  const nonEmpty = lines.filter(l => l.trim().length > 0);
  if (nonEmpty.length < 15) return 0;
  const density = nonEmpty.filter(isComment).length / nonEmpty.length;
  return density > 0.50 ? Math.min(1, (density - 0.50) / 0.30) : 0;
}

// Signal 11: Async/Await Consistency (q = 0.50)
function sigAsyncConsistency(content: string, lang: string): number {
  if (lang !== "typescript" && lang !== "javascript") return 0;
  const awaitUsage = (content.match(/\bawait\s+\w/g) ?? []).length;
  const thenUsage  = (content.match(/\.then\s*\(/g) ?? []).length;
  const catchUsage = (content.match(/\.catch\s*\(/g) ?? []).length;
  const thenable   = thenUsage + catchUsage;
  if (awaitUsage + thenable < 4) return 0;
  const promiseAll = (content.match(/Promise\.(?:all|race|allSettled|any)\s*\(/g) ?? []).length;
  const adjusted   = Math.max(0, thenable - promiseAll);
  if (awaitUsage >= 3 && adjusted === 0) return 1.0;
  if (awaitUsage >= 3 && adjusted <= 1 && awaitUsage / (awaitUsage + adjusted) > 0.88) return 0.65;
  return 0;
}

// Signal 12: Variable Vocabulary (q = 0.50)
// Measures the fraction of variable names that are generic AI-favoured tokens.
// "result", "data", "error", "config" are excluded because every developer uses
// them. Only include names that are AI-characteristic at higher frequency.
const AI_VOCAB = new Set([
  "payload","output","response","values",
  "item","items","entry","entries","element","elements","record","records",
  "configuration","options","settings","parameters","args",
  "context","ctx","handler","handlers","manager","service","helper","provider",
  "repository","factory","builder","processor","transformer","mapper","controller",
  "success","status","flag","enabled","disabled","isValid","isLoading","hasError",
  "collection","dict","ref","current","prev","next","node","metadata","resource",
  "instance","entity","model","schema","validator","serializer","formatter",
]);

function sigVariableVocabulary(content: string): number {
  const decls = content.match(/\b(?:const|let|var)\s+(\w+)\b/g) ?? [];
  if (decls.length < 8) return 0;
  const names   = decls.map(d => d.replace(/\b(?:const|let|var)\s+/, "").trim().toLowerCase());
  const aiNames = names.filter(n => AI_VOCAB.has(n));
  const ratio   = aiNames.length / names.length;
  // Raised threshold: requires > 60% AI vocab (was 55%) before any signal.
  // AI code typically scores 65-85%; senior human code typically 25-45%.
  return ratio > 0.75 ? Math.min(1, (ratio - 0.75) / 0.18)
       : ratio > 0.60 ? (ratio - 0.60) / 0.15 * 0.5
       : 0;
}

// Signal 13: Guard Clause Density (q = 0.45)
function sigGuardClauseDensity(content: string, lang: string): number {
  const funcCount = Math.max(1,
    lang === "python"
      ? (content.match(/^\s*(?:async\s+)?def\s+\w+/gm) ?? []).length
      : (content.match(/(?:async\s+)?function\s+\w+|\w+\s*=\s*(?:async\s+)?\([^)]*\)\s*=>/g) ?? []).length
  );
  const guards = [
    /if\s*\(\s*![\w.?[\]]+\s*\)\s*(?:return|throw)/g,
    /if\s*\(\s*[\w.?[\]]+\s*(?:===?|!==?)\s*(?:null|undefined|false|"")\s*\)\s*(?:\{?\s*)?(?:return|throw)/g,
    /if\s*\(\s*![\w.]+\s*\)\s*\{\s*(?:return|throw)/g,
    /if\s+not\s+\w+\s*:/g,
    /if\s+\w+\s+is\s+None\s*:/g,
    /if\s*\(\s*typeof\s+\w+\s*!==?\s*["']\w+["']\s*\)\s*(?:return|throw)/g,
    /guard\s+(?:let|var)\s+\w+/g,
  ].reduce((sum, re) => sum + (content.match(re) ?? []).length, 0);
  const density = guards / funcCount;
  return density > 2.5 ? Math.min(1, (density - 2.5) / 3.0)
       : density > 1.5 ? (density - 1.5) / 1.0 * 0.5
       : 0;
}

// Signal 14: Template Literal Exclusivity (q = 0.40)
function sigTemplateLiteralExclusivity(content: string, lang: string): number {
  if (lang !== "typescript" && lang !== "javascript") return 0;
  const tpl   = (content.match(/`[^`]*\$\{[^}]+\}[^`]*`/g) ?? []).length;
  const concat = (content.match(/["'][^"'\n]{3,}["']\s*\+\s*\w/g) ?? []).length;
  if (tpl + concat < 3) return 0;
  if (tpl >= 2 && concat === 0) return 1.0;
  if (tpl >= 3 && concat <= 1 && tpl / (tpl + concat) > 0.85) return 0.7;
  return 0;
}

// Signal 15: Import Organisation (q = 0.35)
function sigImportOrganization(content: string, lang: string): number {
  const lines = content.split("\n");
  if (lang === "python") {
    const importLines = lines.filter(l => /^(?:import|from)\s+\w/.test(l));
    if (importLines.length < 4) return 0;
    let s = 0;
    if (lines.filter(l => /^#\s*(?:import|from)\s+\w/.test(l)).length === 0) s += 0.30;
    const firstCode  = lines.findIndex(l => l.trim() && !/^(?:import|from|#)/.test(l.trim()));
    const lastImport = lines.reduce((last, l, i) => /^(?:import|from)\s+/.test(l) ? i : last, -1);
    if (firstCode < 0 || firstCode > lastImport) s += 0.20;
    return Math.min(1, s + 0.10);
  }
  if (lang === "typescript" || lang === "javascript") {
    const importLines = lines.filter(l => /^import\s+/.test(l.trim()));
    if (importLines.length < 4) return 0;
    let s = 0;
    if ((content.match(/\bconst\s+\w+\s*=\s*require\s*\(/g) ?? []).length === 0) s += 0.20;
    if (lines.filter(l => /^\/\/\s*import\s+/.test(l.trim())).length === 0) s += 0.20;
    const firstCode  = lines.findIndex(l => {
      const t = l.trim();
      return t.length > 0 && !/^(?:import|\/\/|\/\*|\*|"use |'use )/.test(t);
    });
    const lastImport = lines.reduce((last, l, i) => /^import\s+/.test(l.trim()) ? i : last, -1);
    if (firstCode < 0 || firstCode > lastImport) s += 0.20;
    return Math.min(1, s);
  }
  return 0;
}

// Signal 16: Test Structure Uniformity (q = 0.65)
// Test files show the most extreme AI uniformity of any code type.
function sigTestStructure(content: string): number {
  const isTestLike =
    /(?:describe|it\s*\(|test\s*\(|expect\s*\(|beforeEach|afterEach|beforeAll|afterAll)\s*\(/.test(content) ||
    /(?:def\s+test_\w+|@pytest\.mark|class\s+\w+Test\b|unittest\.TestCase)/.test(content) ||
    /(?:RSpec\.describe|describe\s+\w+\s+do|context\s+["'])/.test(content);
  if (!isTestLike) return 0;

  let s = 0;
  const describes  = (content.match(/\bdescribe\s*\(/g) ?? []).length;
  const its        = (content.match(/\b(?:it|test)\s*\(/g) ?? []).length;
  const expects    = (content.match(/\bexpect\s*\(/g) ?? []).length;
  const beforeEach = (content.match(/\bbeforeEach\s*\(/g) ?? []).length;

  if (its >= 3) {
    const epi = expects / its;
    if (epi >= 0.8 && epi <= 2.2) s += 0.25;  // ~1 assertion per test
    if (beforeEach >= 1 && describes >= 1)   s += 0.20;
    // Consistent "should X" or verb test naming
    const testNames = content.match(/\b(?:it|test)\s*\(\s*["']([^"']+)["']/g) ?? [];
    if (testNames.length >= 3) {
      const verbPat = /["'](?:should|returns?|throws?|calls?|handles?|renders?|creates?|updates?|deletes?|validates?|checks?|fails?)\b/i;
      const ratio = testNames.filter(n => verbPat.test(n)).length / testNames.length;
      if (ratio > 0.75) s += 0.25;
    }
    // Arrow function blocks only
    const arrowBlocks  = (content.match(/\b(?:describe|it|test)\s*\([^,]+,\s*(?:async\s+)?\(\s*\)\s*=>/g) ?? []).length;
    const totalBlocks  = (content.match(/\b(?:describe|it|test)\s*\([^,]+,\s*function/g) ?? []).length + arrowBlocks;
    if (totalBlocks > 0 && arrowBlocks / totalBlocks > 0.90) s += 0.15;
  }

  // Python pytest
  const pytestFuncs = (content.match(/^\s*def\s+test_\w+/gm) ?? []).length;
  if (pytestFuncs >= 3) {
    const allFuncs = (content.match(/^\s*def\s+\w+/gm) ?? []).length;
    if (allFuncs > 0 && pytestFuncs / allFuncs > 0.85) s += 0.25;
    const withDocs = (content.match(/def\s+test_\w+[^:]*:\s*\n\s*"""/g) ?? []).length;
    if (withDocs / pytestFuncs > 0.75) s += 0.25;
  }

  return Math.min(1, s);
}

// Signal 17: Functional Loop Preference (q = 0.48)
function sigFunctionalPreference(content: string, lang: string): number {
  if (lang === "typescript" || lang === "javascript") {
    const functional  = (content.match(/\.\b(?:map|filter|reduce|forEach|find|findIndex|some|every|flatMap|flat|sort|slice|includes)\s*\(/g) ?? []).length;
    const imperative  = (content.match(/\bfor\s*\(/g) ?? []).length + (content.match(/\bwhile\s*\(/g) ?? []).length;
    if (functional + imperative < 4) return 0;
    if (functional >= 3 && imperative === 0) return 1.0;
    if (functional >= 3 && imperative === 1) return 0.75;
    const ratio = functional / (functional + imperative);
    return ratio > 0.80 ? (ratio - 0.80) / 0.20 * 0.6 : 0;
  }
  if (lang === "python") {
    const comps = (content.match(/\[[^\]]{5,}\bfor\b[^\]]+\bin\b[^\]]+\]/g) ?? []).length +
                  (content.match(/\{[^}]{5,}\bfor\b[^}]+\bin\b[^}]+\}/g) ?? []).length;
    const loops = Math.max(0, (content.match(/^\s*for\s+\w+\s+in\b/gm) ?? []).length - comps);
    if (comps + loops < 4) return 0;
    if (comps >= 3 && loops === 0) return 1.0;
    const ratio = comps / (comps + loops);
    return ratio > 0.80 ? (ratio - 0.80) / 0.20 * 0.7 : 0;
  }
  return 0;
}

// Signal 18: Shallow Nesting (q = 0.45)
// AI code almost never exceeds 3 levels of indentation.
function sigShallowNesting(content: string, lineCount: number): number {
  if (lineCount < 25) return 0;
  const lines     = content.split("\n");
  const indents: number[] = [];
  for (const line of lines) {
    const t = line.trim();
    if (!t || /^(?:\/\/|#|\*)/.test(t)) continue;
    const spaces = (line.match(/^(\s+)/)?.[1] ?? "").replace(/\t/g, "    ").length;
    indents.push(spaces);
  }
  if (indents.length < 10) return 0;
  const maxIndent  = Math.max(...indents);
  const deepLines  = indents.filter(n => n > 16).length; // > 4 levels (4-space)
  const deepRatio  = deepLines / indents.length;
  // Callback hell = human code
  const cbHell = (content.match(/function\s*\([^)]*\)\s*\{[\s\S]{0,300}function\s*\([^)]*\)\s*\{[\s\S]{0,300}function\s*\([^)]*\)\s*\{/g) ?? []).length;
  if (cbHell > 0) return 0;
  if (maxIndent <= 8  && deepRatio === 0)   return 0.90;
  if (maxIndent <= 12 && deepRatio < 0.02)  return 0.65;
  if (maxIndent <= 16 && deepRatio < 0.05)  return 0.30;
  if (deepRatio > 0.15) return 0;
  return 0.10;
}

// Signal 19: Low Lexical Diversity (q = 0.55)
// AI reuses the same identifier vocabulary. Low TTR = AI signal.
const IDENT_KEYWORDS = new Set([
  "const","let","var","function","async","await","return","if","else","for",
  "while","class","import","export","from","default","new","this","super",
  "true","false","null","undefined","void","typeof","instanceof","in","of",
  "try","catch","finally","throw","extends","implements","interface","type",
  "static","public","private","protected","readonly","abstract","enum",
  "switch","case","break","continue","do","delete","with","yield","string",
  "number","boolean","object","any","never","unknown","def","pass","raise",
  "with","as","lambda","global","nonlocal","and","or","not","is","elif",
  "except","assert","func","package","chan","go","select","defer","map",
  "struct","range","error","err","Error","console","log","Math","Object",
  "Array","String","Number","Boolean","JSON","Promise","then","catch",
]);

function sigLexicalDiversity(content: string, lineCount: number): number {
  if (lineCount < 35) return 0;
  const ids: string[] = [];
  const re = /\b([a-zA-Z_][a-zA-Z0-9_]{2,})\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    if (!IDENT_KEYWORDS.has(m[1]) && !IDENT_KEYWORDS.has(m[1].toLowerCase()))
      ids.push(m[1].toLowerCase());
  }
  if (ids.length < 60) return 0;
  // Type-token ratio shrinks with corpus size (Heaps' law): a 5,000-line file
  // naturally has a much lower raw TTR than a 200-line file regardless of
  // authorship — e.g. zod's types.ts (human-written, ~5k lines) has a raw TTR
  // of ~0.09, which used to read as maximally AI. Use MATTR (moving-average
  // TTR over fixed-size windows) instead, which is length-independent.
  const WINDOW = 100;
  let ttr: number;
  if (ids.length < WINDOW) {
    ttr = new Set(ids).size / ids.length;
  } else {
    let sum = 0, n = 0;
    for (let i = 0; i + WINDOW <= ids.length; i += WINDOW) {
      sum += new Set(ids.slice(i, i + WINDOW)).size / WINDOW;
      n++;
    }
    ttr = sum / n;
  }
  // Recalibrated thresholds, now applied to MATTR.
  //   AI code MATTR: 0.20–0.32 (heavy identifier reuse within any 100-token window)
  //   Human OOP service files MATTR: 0.38–0.50 (repetitive but not AI-level)
  //   Human utility/algorithm files MATTR: 0.48–0.65 (high diversity)
  if (ttr < 0.22) return Math.min(1, (0.22 - ttr) / 0.08);
  if (ttr < 0.30) return (0.30 - ttr) / 0.08 * 0.65;
  if (ttr < 0.38) return (0.38 - ttr) / 0.08 * 0.30;
  return 0;
}

// Signal 20: Sentence-Style Identifiers (q = 0.48)
// AI uses long, multi-word function names that read like sentences.
function sigSentenceIdentifiers(content: string, lang: string): number {
  const patterns =
    lang === "python"  ? [/(?:def\s+)([a-z][a-z0-9_]{3,})/g] :
    lang === "golang"  ? [/(?:func\s+\w*\s*\()([A-Za-z][A-Za-z0-9]+)/g, /(?:func\s+)([A-Za-z][A-Za-z0-9]+)\s*\(/g] :
                         [/(?:function\s+)([a-z][A-Za-z0-9]{3,})/g,
                          /(?:const\s+)([a-z][A-Za-z0-9]{3,})\s*=\s*(?:async\s+)?\(/g];
  const names: string[] = [];
  for (const pat of patterns) {
    let m: RegExpExecArray | null;
    const r = new RegExp(pat.source, pat.flags);
    while ((m = r.exec(content)) !== null) if (m[1] && m[1].length >= 4) names.push(m[1]);
  }
  if (names.length < 4) return 0;

  const wordCount = (n: string): number =>
    n.includes("_")
      ? n.split("_").filter(Boolean).length
      : (n.match(/[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\b)/g) ?? []).length;

  const wcs   = names.map(wordCount);
  const avg   = wcs.reduce((a, b) => a + b, 0) / wcs.length;
  const long  = wcs.filter(n => n >= 4).length / names.length;

  if (avg >= 3.5 && long >= 0.30) return Math.min(1, (avg - 3.5) / 2.0 * 0.6 + long * 0.4);
  if (avg >= 3.0) return (avg - 3.0) / 0.5 * 0.30;
  return 0;
}

// Signal 21: Method Chain Density (q = 0.40)
// AI prefers fluent interfaces; humans use intermediate variables.
function sigMethodChainDensity(content: string, lang: string): number {
  if (lang !== "typescript" && lang !== "javascript") return 0;
  const lines     = content.split("\n");
  const chains    = lines.filter(l => /^\s+\.\w+\s*\(/.test(l)).length;
  const codeLines = lines.filter(l => l.trim().length > 3).length;
  if (codeLines < 10) return 0;
  const density = chains / codeLines;
  return density > 0.15 ? Math.min(1, (density - 0.15) / 0.20)
       : density > 0.08 ? (density - 0.08) / 0.07 * 0.4
       : 0;
}

// Signal 22: Magic Number Absence (q = 0.42)
// AI always extracts numeric literals into named constants.
function sigMagicNumberAbsence(content: string, lineCount: number): number {
  if (lineCount < 25) return 0;
  const lines     = content.split("\n");
  const codeLines = lines.filter(l => {
    const t = l.trim();
    return t && !t.startsWith("//") && !t.startsWith("#") && !t.startsWith("*");
  });
  if (codeLines.length < 15) return 0;

  // "Safe" numbers that appear even in clean code
  const SAFE = new Set(["0","1","2","3","-1","10","16","32","64","100","200","201","204",
                         "400","401","403","404","429","500","503","1000","1024","2048"]);
  let magic = 0;
  let named = 0;
  for (const line of codeLines) {
    (line.match(/(?<![.\w])\b\d{3,}\b(?!\.\d)/g) ?? []).forEach(n => { if (!SAFE.has(n)) magic++; });
    if (/\b[A-Z][A-Z0-9_]{3,}\b/.test(line)) named++;
  }
  const density = magic / codeLines.length;
  if (density < 0.03 && named > 2) return 0.80;
  if (density < 0.06) return 0.50;
  if (density > 0.20) return 0;
  return 0.20;
}

// Signal 23: Async Try-Catch Coverage (q = 0.50)
// AI wraps every async function in try-catch; humans are more selective.
function sigAsyncTryCatch(content: string, lang: string): number {
  if (lang !== "typescript" && lang !== "javascript") return 0;
  const asyncFuncs = (content.match(/\basync\s+(?:function\s+\w+|\([^)]*\)\s*=>|\w+\s*=>)/g) ?? []).length;
  if (asyncFuncs < 2) return 0;
  const tryCatches = (content.match(/\btry\s*\{/g) ?? []).length;
  const ratio = tryCatches / asyncFuncs;
  if (ratio >= 0.90) return 0.50 + Math.min(0.50, (ratio - 0.90) / 0.10 * 0.50);
  if (ratio >= 0.70) return (ratio - 0.70) / 0.20 * 0.50;
  return 0;
}

// Signal 24: Immutable Operation Preference (q = 0.45)
// AI prefers spread/map/filter over mutation (push/splice/sort-in-place).
function sigImmutablePreference(content: string, lang: string): number {
  if (lang !== "typescript" && lang !== "javascript") return 0;
  const immutable = (content.match(
    /(?:\.\.\.\s*\w+|(?:\.map|\.filter|\.reduce|\.slice|\.concat|\.flat|\.flatMap|Object\.assign|Object\.keys|Object\.values|Object\.entries)\s*\()/g
  ) ?? []).length;
  const mutable = (content.match(/\.push\s*\(|\.pop\s*\(|\.shift\s*\(|\.splice\s*\(|\.sort\s*\((?!\s*\()|\.reverse\s*\(/g) ?? []).length;
  if (immutable + mutable < 5) return 0;
  const ratio = immutable / (immutable + mutable);
  if (ratio >= 0.90) return 0.40 + Math.min(0.60, (ratio - 0.90) / 0.10 * 0.60);
  if (ratio >= 0.75) return (ratio - 0.75) / 0.15 * 0.40;
  return 0;
}

// Signal 25: Exhaustive Switch Coverage (q = 0.48)
// AI always adds a default case; humans often omit it.
function sigExhaustiveSwitches(content: string): number {
  // Extract full switch blocks (non-greedy, up to 3 KB each)
  const switchBlocks = content.match(/\bswitch\s*\([^)]+\)\s*\{[\s\S]{0,3000}?\}/g) ?? [];
  if (switchBlocks.length < 2) return 0;
  const withDefault = switchBlocks.filter(b => /\bdefault\s*:/.test(b)).length;
  const ratio = withDefault / switchBlocks.length;
  if (ratio >= 1.0) return 0.90;
  if (ratio >= 0.80) return (ratio - 0.80) / 0.20 * 0.60;
  return 0;
}

// Signal 26: Type Guards Over Assertions (q = 0.45)
// AI uses typeof/instanceof/in predicates rather than unsafe 'as T' casts.
function sigTypeGuards(content: string, lang: string): number {
  if (lang !== "typescript") return 0;
  const guards = (content.match(
    /\btypeof\s+\w+\s*(?:===?|!==?)\s*["']\w+["']|\b\w+\s+instanceof\s+\w+|\b\w+\s+in\s+\w+|\bfunction\s+is[A-Z]\w+/g
  ) ?? []).length;
  const casts = (content.match(/\bas\s+(?!const\b)[A-Z]\w[\w<>, [\]|&]*/g) ?? []).length;
  if (guards + casts < 4) return 0;
  if (guards >= 3 && casts === 0) return 0.80;
  if (guards > 0 && guards > casts * 1.5) return Math.min(0.60, guards / (guards + casts) * 0.70);
  return 0;
}

// Signal 27: Structured Logging (q = 0.42)
// AI uses logger.info(msg, { context }) rather than bare console.log() calls.
function sigStructuredLogging(content: string, lang: string): number {
  if (lang !== "typescript" && lang !== "javascript") return 0;
  const structured = (content.match(/(?:logger|log|winston|pino)\.\w+\s*\([^)]+,\s*\{[^}]{3,}\}/g) ?? []).length;
  const bare = (content.match(/\bconsole\.(?:log|error|warn|info|debug)\s*\(/g) ?? []).length;
  if (structured + bare < 3) return 0;
  if (structured >= 3 && bare === 0) return 1.0;
  if (structured >= 2 && structured > bare) return Math.min(0.70, structured / (structured + bare) * 0.80);
  return 0;
}

// ── Shared function-body extractor (used by signals 28, 29) ──────────────────
// Returns the raw source text of each top-level function body.
function extractFunctionBodies(content: string, lang: string): string[] {
  const bodies: string[] = [];
  if (lang === "typescript" || lang === "javascript") {
    const funcRe = /(?:(?:async\s+)?function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\([^)]*\)\s*=>|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?function)\s*[({]/g;
    let m: RegExpExecArray | null;
    while ((m = funcRe.exec(content)) !== null) {
      let depth = 0, i = m.index;
      for (; i < Math.min(content.length, m.index + 5000); i++) {
        if (content[i] === "{") depth++;
        else if (content[i] === "}") { depth--; if (depth <= 0) { bodies.push(content.slice(m.index, i + 1)); break; } }
      }
    }
  } else if (lang === "python") {
    const lines = content.split("\n");
    let inDef = false, defStart = 0, baseIndent = 0;
    for (let i = 0; i < lines.length; i++) {
      if (/^\s*(?:async\s+)?def\s+\w+/.test(lines[i])) {
        if (inDef) bodies.push(lines.slice(defStart, i).join("\n"));
        inDef = true; defStart = i;
        baseIndent = (lines[i].match(/^(\s*)/)?.[1].length ?? 0);
      } else if (inDef) {
        const indent = (lines[i].match(/^(\s*)/)?.[1].length ?? 0);
        if (lines[i].trim() && indent <= baseIndent && !/^\s*#/.test(lines[i])) {
          bodies.push(lines.slice(defStart, i).join("\n")); inDef = false;
        }
      }
    }
    if (inDef) bodies.push(lines.slice(defStart).join("\n"));
  }
  return bodies;
}

// Signal 28: Cyclomatic Complexity Uniformity (q = 0.55)
// AI functions have low and highly uniform cyclomatic complexity.
// Human functions vary widely — 1 to 30+ branch points.
function sigCyclomaticUniformity(content: string, lang: string): number {
  if (lang !== "typescript" && lang !== "javascript" && lang !== "python") return 0;
  const bodies = extractFunctionBodies(content, lang);
  if (bodies.length < 3) return 0;
  const BRANCH_RE = /\b(?:if|else\s+if|for|while|do|catch)\s*\(|\bcase\s+[^:]+:|&&|\|\||\?\s*(?![?:])/g;
  const ccs = bodies.map(b => 1 + (b.match(BRANCH_RE) ?? []).length);
  const mean   = ccs.reduce((a, b) => a + b, 0) / ccs.length;
  const stddev = Math.sqrt(ccs.reduce((s, c) => s + (c - mean) ** 2, 0) / ccs.length);
  const cv     = stddev / Math.max(1, mean);
  const maxCC  = Math.max(...ccs);
  if (maxCC > 22 || mean > 14) return 0;
  if (cv < 0.30 && mean <= 7  && maxCC <= 10) return 0.90;
  if (cv < 0.45 && mean <= 9  && maxCC <= 14) return Math.max(0, (0.45 - cv) / 0.15 * 0.60);
  if (cv < 0.55 && mean <= 11 && maxCC <= 16) return Math.max(0, (0.55 - cv) / 0.10 * 0.30);
  return 0;
}

// Signal 29: Return-Type Annotation Coverage (q = 0.45)
// AI always annotates TypeScript return types; humans rely on inference.
function sigReturnTypeAnnotations(content: string, lang: string): number {
  if (lang !== "typescript") return 0;
  const typed   = (content.match(/\)\s*:\s*(?:Promise<|void|never|string|number|boolean|Record|Array|\w+\[\]|[A-Z]\w+)\s*(?:\{|=>)/g) ?? []).length;
  const untyped = (content.match(/\)\s*\{(?!\s*\/)/g) ?? []).length +
                  (content.match(/\)\s*=>\s*(?![:\s]*(?:Promise<|void|never|string|number|boolean|Record|Array|[A-Z]\w+))/g) ?? []).length;
  if (typed + untyped < 5) return 0;
  const ratio = typed / (typed + untyped);
  if (ratio >= 0.80) return 0.40 + Math.min(0.60, (ratio - 0.80) / 0.20 * 0.60);
  if (ratio >= 0.60) return (ratio - 0.60) / 0.20 * 0.40;
  return 0;
}

// Signal 30: Verb-Prefix Consistency (q = 0.45)
// AI function names begin with standard action verbs far more reliably than human code.
const VERB_PREFIX_RE = /^(?:get|set|is|has|can|should|create|make|build|update|delete|remove|handle|process|validate|check|verify|parse|format|render|compute|calculate|fetch|load|save|send|receive|connect|find|filter|map|transform|convert|init|reset|clear|add|push|toggle|enable|disable|run|execute|encode|decode|serialize|deserialize|normalize|sanitize|merge|extract|register|subscribe|publish|emit)\w{1,}/i;

function sigVerbPrefixConsistency(content: string, lang: string): number {
  const pat =
    lang === "python" ? /(?:^|\n)\s*(?:async\s+)?def\s+([a-z]\w+)/g :
    lang === "golang" ? /\bfunc\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s*)?([A-Za-z]\w+)\s*\(/g :
    /\b(?:function\s+([a-z]\w{3,})|(?:const|let)\s+([a-z]\w{3,})\s*=\s*(?:async\s+)?\()/g;
  const names: string[] = [];
  const r = new RegExp(pat.source, pat.flags);
  let m: RegExpExecArray | null;
  while ((m = r.exec(content)) !== null) {
    const name = m[1] ?? m[2];
    if (name && name.length >= 4) names.push(name);
  }
  if (names.length < 5) return 0;
  const verbCount = names.filter(n => VERB_PREFIX_RE.test(n)).length;
  const ratio = verbCount / names.length;
  if (ratio >= 0.90) return 0.80;
  if (ratio >= 0.75) return (ratio - 0.75) / 0.15 * 0.55;
  return 0;
}

// Signal 31: Object Destructuring Density (q = 0.42)
// AI destructures function arguments and intermediate values pervasively.
function sigObjectDestructuringDensity(content: string, lang: string): number {
  if (lang !== "typescript" && lang !== "javascript") return 0;
  const assignDestruct = (content.match(/\b(?:const|let|var)\s+\{[^}]{3,80}\}\s*=/g) ?? []).length;
  const arrayDestruct  = (content.match(/\b(?:const|let|var)\s+\[[^\]]{3,50}\]\s*=/g) ?? []).length;
  const paramDestruct  = (content.match(/(?:function\s+\w+\s*\(\s*\{|=\s*(?:async\s+)?\(\s*\{)[^}]{3,80}\}/g) ?? []).length;
  const funcCount = Math.max(1, (content.match(/(?:async\s+)?function\s+\w+|\w+\s*=\s*(?:async\s+)?\(/g) ?? []).length);
  const density = (assignDestruct + arrayDestruct + paramDestruct) / funcCount;
  if (density >= 2.0) return Math.min(1, 0.50 + (density - 2.0) / 3.0 * 0.50);
  if (density >= 1.0) return (density - 1.0) / 1.0 * 0.50;
  return 0;
}

// Signal 32: Exception Type Specificity (q = 0.45)
// AI throws custom typed exceptions; human code mixes bare Error and string throws.
function sigExceptionSpecificity(content: string, lang: string): number {
  if (lang !== "typescript" && lang !== "javascript") return 0;
  const custom  = (content.match(/throw\s+new\s+(?!(?:Error|TypeError|RangeError|ReferenceError|SyntaxError|URIError)\s*\()[A-Z]\w+(?:Error|Exception|Fault)\s*\(/g) ?? []).length;
  const bare    = (content.match(/throw\s+new\s+(?:Error|TypeError|RangeError|ReferenceError|SyntaxError|URIError)\s*\(/g) ?? []).length;
  const strings = (content.match(/throw\s+["'`]/g) ?? []).length;
  const total   = custom + bare + strings;
  if (total < 3) return 0;
  const ratio = custom / total;
  if (ratio >= 0.80) return 0.40 + Math.min(0.60, (ratio - 0.80) / 0.20 * 0.60);
  if (ratio >= 0.55) return (ratio - 0.55) / 0.25 * 0.40;
  return 0;
}

// Signal 33: Line-Length Distribution Uniformity (q = 0.38)
// AI code lines have a tighter length distribution (lower CV) than human code.
function sigLineLengthUniformity(content: string, lineCount: number): number {
  if (lineCount < 30) return 0;
  const lengths = content.split("\n")
    .filter(l => { const t = l.trim(); return t.length > 5 && !t.startsWith("//") && !t.startsWith("*") && !t.startsWith("#"); })
    .map(l => l.trimEnd().length);
  if (lengths.length < 20) return 0;
  const mean   = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  const stddev = Math.sqrt(lengths.reduce((s, l) => s + (l - mean) ** 2, 0) / lengths.length);
  const cv     = stddev / Math.max(1, mean);
  if (cv < 0.28) return 0.85;
  if (cv < 0.38) return (0.38 - cv) / 0.10 * 0.65;
  if (cv < 0.48) return (0.48 - cv) / 0.10 * 0.30;
  return 0;
}

// Signal 34: Default Parameter Usage (q = 0.40)
// AI uses default parameters in function signatures; humans often add manual if-checks.
function sigDefaultParameters(content: string, lang: string): number {
  const funcCount = Math.max(1,
    lang === "python"
      ? (content.match(/^\s*(?:async\s+)?def\s+\w+/gm) ?? []).length
      : (content.match(/(?:async\s+)?function\s+\w+|\w+\s*=\s*(?:async\s+)?\(/g) ?? []).length
  );
  if (funcCount < 2) return 0;
  const defaults = lang === "python"
    ? (content.match(/def\s+\w+\([^)]*\w+\s*=\s*[^,)]{1,30}/g) ?? []).length
    : (content.match(/(?:function\s+\w+\s*\([^)]*\w+\s*=\s*[^,)>{]{1,30}|(?:const|let)\s+\w+\s*=\s*(?:async\s+)?\([^)]*\w+\s*=\s*[^,)>{]{1,30})/g) ?? []).length;
  const density = defaults / funcCount;
  if (density >= 0.65) return 0.40 + Math.min(0.60, (density - 0.65) / 0.35 * 0.60);
  if (density >= 0.35) return (density - 0.35) / 0.30 * 0.40;
  return 0;
}

// Signal 35: Arrow-Function Callback Consistency (q = 0.38)
// AI uses arrow functions exclusively for callbacks; humans mix with function() syntax.
function sigArrowFunctionConsistency(content: string, lang: string): number {
  if (lang !== "typescript" && lang !== "javascript") return 0;
  const arrowCb = (content.match(/\.(?:then|catch|map|filter|reduce|forEach|find|findIndex|some|every|flatMap|sort|on|once|addEventListener)\s*\(\s*(?:async\s+)?(?:\w+|\([^)]*\))\s*=>/g) ?? []).length;
  const funcCb  = (content.match(/\.(?:then|catch|map|filter|reduce|forEach|find|findIndex|some|every|flatMap|sort|on|once|addEventListener)\s*\(\s*function\s*(?:\w+\s*)?\(/g) ?? []).length;
  if (arrowCb + funcCb < 3) return 0;
  if (arrowCb >= 3 && funcCb === 0) return 0.85;
  const ratio = arrowCb / (arrowCb + funcCb);
  if (ratio >= 0.88) return (ratio - 0.88) / 0.12 * 0.60;
  return 0;
}

// Signal 36: Token N-gram Fingerprint (q = 0.62, CORE)
// AI code produces characteristic keyword bigrams at far higher density than human code.
// These bigrams are each individually unremarkable, but their CO-OCCURRENCE is an AI hallmark.
// Calibrated against a corpus of 2 000 human files: >12 hits = essentially AI.
const AI_NGRAM_PATTERNS: RegExp[] = [
  // Structured return patterns — AI always returns { success, data, error } objects
  /\breturn\s+\{\s*(?:success|data|error|result|message|status|payload|response)\s*:/,
  // Null guard at top of function — AI applies mechanically, humans are more selective
  /if\s*\(\s*!(?:input|data|value|params|options|config|request|body|payload)\s*\)/,
  // AI favourite: early-return guard with typeof / instanceof
  /if\s*\(\s*typeof\s+\w+\s*!==?\s*["']\w+["']\s*\)\s*(?:return|throw)/,
  // AI's favoured async assignment pattern
  /\bconst\s+(?:result|response|data)\s*=\s*await\s+\w/,
  // AI always wraps object spread in new const
  /\bconst\s+\w+\s*=\s*\{\s*\.\.\.\w+,/,
  // Optional chaining followed by nullish coalescing — AI uses together consistently
  /\?\.\w+\s*\?\?\s*(?:null|undefined|["']|0|\[\]|\{)/,
  // Destructure with renaming — AI pattern `const { x: localX } =`
  /\bconst\s+\{\s*\w+\s*:\s*\w+(?:\s*,\s*\w+\s*:\s*\w+)+\s*\}\s*=/,
  // AI always uses `Array.isArray` before array operations
  /Array\.isArray\s*\(\s*\w+\s*\)\s*&&/,
  // Object.keys/values/entries iteration — AI uses these patterns uniformly
  /Object\.(?:keys|values|entries)\s*\(\s*\w+\s*\)\s*\.\s*(?:map|filter|forEach|reduce)\s*\(/,
  // Promise.all with array of awaits — AI-generated concurrency patterns
  /\bawait\s+Promise\.(?:all|allSettled|race)\s*\(\s*\[/,
  // AI always decomposes parameters — `const { id, name, ...rest } = param`
  /\bconst\s+\{\s*(?:\w+,\s*){2,}\.\.\.\w+\s*\}\s*=/,
  // AI-style error wrapping with context
  /throw\s+new\s+\w+(?:Error|Exception)\s*\(\s*`[^`]*\$\{/,
  // AI's characteristic logger pattern with metadata object
  /(?:logger|log)\.\w+\s*\(\s*`[^`]*`\s*,\s*\{/,
  // Guard clause returning early with default value — AI applies this everywhere
  /if\s*\(\s*(?:!|\s*)\w+\s*\)\s*return\s+(?:null|undefined|\[\]|\{\}|false|""|''|0)\s*;/,
  // AI always names the catch variable `error` and logs it structured
  /catch\s*\(\s*(?:error|err)\s*\)\s*\{\s*\n[\s\S]{0,60}(?:logger|console)\.\w+/,
  // Python: AI's f-string in every function
  /f["'](?:[^"'\n]*\{[^}]+\}){2,}[^"'\n]*["']/,
  // Python: type-annotated return with Optional
  /def\s+\w+\([^)]*\)\s*->\s*Optional\[/,
  // Go: AI wraps everything in fmt.Errorf with %w
  /fmt\.Errorf\("[^"]*:\s*%w",\s*(?:err|error)\)/,
  // Go: AI uses context.WithTimeout uniformly
  /ctx,\s*cancel\s*:=\s*context\.WithTimeout\s*\(/,
];

function sigNgramFingerprint(content: string): number {
  let hits = 0;
  for (const re of AI_NGRAM_PATTERNS) if (re.test(content)) hits++;
  if (hits >= 12) return 1.0;
  if (hits >= 9)  return 0.85 + (hits - 9) / 3 * 0.15;
  if (hits >= 6)  return 0.55 + (hits - 6) / 3 * 0.30;
  if (hits >= 3)  return 0.20 + (hits - 3) / 3 * 0.35;
  if (hits >= 1)  return hits * 0.10;
  return 0;
}

// Signal 37: Structural Clone Density (q = 0.58, CORE)
// AI generates near-identical CRUD/handler functions. When 3+ function bodies share
// a structural fingerprint (same token skeleton), it's an extremely strong AI signal.
// Approach: reduce each body to keyword skeleton, compute pairwise Jaccard similarity.
function structuralFingerprint(body: string): Set<string> {
  // Strip strings and numbers; normalise identifiers to their type token
  const stripped = body
    .replace(/`[^`]*`/g, "TMPL")
    .replace(/"[^"]*"/g, "STR")
    .replace(/'[^']*'/g, "STR")
    .replace(/\b\d+\b/g, "NUM")
    .replace(/\b[a-z][a-zA-Z0-9]{6,}\b/g, "ID")      // long identifiers → ID
    .replace(/\b[A-Z][a-zA-Z0-9]{3,}\b/g, "TYPE");     // PascalCase types → TYPE
  // Bigrams of whitespace-separated tokens
  const tokens = stripped.split(/\s+/).filter(t => t.length > 0);
  const bigrams = new Set<string>();
  for (let i = 0; i < tokens.length - 1; i++) bigrams.add(`${tokens[i]}|${tokens[i+1]}`);
  return bigrams;
}

function jaccardSim(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 1;
  let inter = 0;
  a.forEach(t => { if (b.has(t)) inter++; });
  return inter / (a.size + b.size - inter);
}

function sigStructuralClones(content: string, lang: string): number {
  const bodies = extractFunctionBodies(content, lang);
  if (bodies.length < 3) return 0;
  // Only compare substantial bodies (> 6 lines)
  const substantial = bodies.filter(b => b.split("\n").length >= 6);
  if (substantial.length < 3) return 0;
  const fps = substantial.map(structuralFingerprint);
  // Find the largest cluster of mutually similar bodies (Jaccard > 0.72)
  let maxCluster = 0;
  for (let i = 0; i < fps.length; i++) {
    let cluster = 1;
    for (let j = 0; j < fps.length; j++) {
      if (i !== j && jaccardSim(fps[i], fps[j]) >= 0.72) cluster++;
    }
    if (cluster > maxCluster) maxCluster = cluster;
  }
  if (maxCluster >= 5) return 1.0;
  if (maxCluster >= 4) return 0.85;
  if (maxCluster >= 3) return 0.65;
  return 0;
}

// Signal 38: AI Error Message Phrasing (q = 0.45, SECONDARY)
// AI generates error messages with predictable templated phrasing.
// Human error messages show far more vocabulary variety.
const AI_ERROR_PHRASES: RegExp[] = [
  /["'`](?:Invalid|Malformed)\s+\w+(?:\s+\w+)?["'`]/i,
  /["'`]\w+\s+is\s+(?:required|not found|not valid|already exists|not allowed|not authorized)["'`]/i,
  /["'`](?:Failed to|Unable to|Cannot|Could not)\s+\w+(?:\s+\w+)?["'`]/i,
  /["'`]\w+\s+must\s+be\s+(?:a|an|the|between|at least|greater than|less than)\b/i,
  /["'`](?:Error|Exception)(?:\s+occurred)?\s+(?:while|during|when)\s+\w+/i,
  /["'`](?:Unexpected|Unknown)\s+\w+(?:\s+type)?(?:\s*:|\s+"\w+")?["'`]/i,
  /["'`](?:Access denied|Unauthorized|Permission denied|Forbidden)\b/i,
  /["'`](?:Internal server error|Something went wrong|An error occurred)["'`]/i,
  /["'`]\w+\s+(?:does not exist|is not defined|is undefined|is null)\b/i,
  /["'`](?:Please|Ensure|Make sure)\s+\w+/i,
];

function sigErrorMessagePhrasing(content: string): number {
  const errorContextLines = content.split("\n").filter(l =>
    /\b(?:throw|Error|error|Exception|message|detail|msg)\b/.test(l) &&
    /["'`]/.test(l)
  );
  if (errorContextLines.length < 2) return 0;
  const errorBlock = errorContextLines.join("\n");
  let hits = 0;
  for (const re of AI_ERROR_PHRASES) if (re.test(errorBlock)) hits++;
  const density = hits / Math.max(errorContextLines.length, 1);
  if (hits >= 5 && density >= 0.5) return 1.0;
  if (hits >= 4) return 0.80;
  if (hits >= 3) return 0.60;
  if (hits >= 2) return 0.35;
  return 0;
}

// Signal 39: Identifier Length Uniformity (q = 0.38, SECONDARY)
// AI generates identifiers with very uniform lengths (mean 8–14, CV < 0.35).
// Human code mixes short names (`i`, `n`, `ok`, `err`) with long ones — high variance.
function sigIdentifierLengthUniformity(content: string, lineCount: number): number {
  if (lineCount < 25) return 0;
  const re = /\b(?:const|let|var|def|func|function)\s+([a-zA-Z_]\w{2,})\b/g;
  const lengths: number[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const len = m[1].length;
    if (len >= 3 && len <= 40) lengths.push(len);
  }
  if (lengths.length < 8) return 0;
  const mean   = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  const stddev = Math.sqrt(lengths.reduce((s, l) => s + (l - mean) ** 2, 0) / lengths.length);
  const cv     = stddev / Math.max(1, mean);
  // AI: mean 8–15, CV < 0.30 (very uniform, descriptive names throughout)
  // Human: mean 5–10, CV > 0.45 (mixes short loop vars with long descriptive ones)
  const shortFrac = lengths.filter(l => l <= 4).length / lengths.length;
  // High short-name fraction is a human signal — reduce score
  if (shortFrac > 0.25) return 0;
  if (mean >= 8 && mean <= 16 && cv < 0.25) return 0.90;
  if (mean >= 7 && mean <= 18 && cv < 0.35) return 0.60;
  if (mean >= 6 && cv < 0.40) return 0.30;
  return 0;
}

// Signal 40: Blank Line Regularity (q = 0.32, STYLE)
// AI never puts 3+ consecutive blank lines. AI always puts exactly 1 blank line between
// functions. Human code is messier: sometimes 0 (packed) or 3+ (spacious refactoring noise).
function sigBlankLineRegularity(content: string, lineCount: number): number {
  if (lineCount < 30) return 0;
  const lines = content.split("\n");
  let maxConsecutive = 0, cur = 0;
  const gapsBetweenFuncs: number[] = [];
  let inGap = false, gapCount = 0;
  const FUNC_START_RE = /^\s*(?:(?:export\s+)?(?:async\s+)?function\s|\w+\s*=\s*(?:async\s+)?\(|(?:async\s+)?def\s|func\s)/;
  for (const line of lines) {
    if (line.trim() === "") {
      cur++;
      if (inGap) gapCount++;
    } else {
      if (cur > maxConsecutive) maxConsecutive = cur;
      if (FUNC_START_RE.test(line) && inGap) { gapsBetweenFuncs.push(gapCount); inGap = false; gapCount = 0; }
      if (FUNC_START_RE.test(line)) { inGap = true; gapCount = 0; }
      cur = 0;
    }
  }
  // 3+ consecutive blank lines = human code (refactoring remnant or stylistic spacing)
  if (maxConsecutive >= 3) return 0;
  // Check variance of gaps between functions
  if (gapsBetweenFuncs.length >= 3) {
    const mean   = gapsBetweenFuncs.reduce((a, b) => a + b, 0) / gapsBetweenFuncs.length;
    const stddev = Math.sqrt(gapsBetweenFuncs.reduce((s, g) => s + (g - mean) ** 2, 0) / gapsBetweenFuncs.length);
    const cv = stddev / Math.max(0.5, mean);
    // Perfect regularity (AI): every gap is exactly 1 blank line
    if (cv < 0.15 && maxConsecutive <= 1) return 0.80;
    if (cv < 0.30 && maxConsecutive <= 2) return 0.50;
    if (cv < 0.50) return 0.25;
  }
  if (maxConsecutive <= 1) return 0.35;
  return 0;
}

// Signal 41: Token Frequency Profile (q = 0.42, SECONDARY)
// AI code has a characteristic frequency distribution of specific tokens.
// Measured as the ratio of "AI-surplus" keyword occurrences vs total tokens.
// These tokens appear at 2-4× frequency in AI code compared to human baselines.
const TOKEN_FREQ_AI = [
  /\bawait\b/g,        // AI uses async/await everywhere
  /\bconst\b/g,        // AI uses const exclusively
  /\binterface\b/g,    // AI defines interfaces for everything
  /\bReadonly\b/g,     // AI marks everything readonly
  /\bOptional\b/g,     // AI uses Optional<T> in Python/TypeScript
  /\bvoid\b/g,         // AI annotates void returns
  /\bundefined\b/g,    // AI always checks undefined
  /\bnull\b/g,         // AI handles null explicitly
  /\btypeof\b/g,       // AI uses typeof guards
  /\binstanceof\b/g,   // AI uses instanceof checks
];
const TOKEN_FREQ_HUMAN = [
  /\bvar\b/g,          // humans still use var in legacy code
  /\bthis\b/g,         // humans write OOP with this
  /\bprototype\b/g,    // human class patterns
  /\bcallback\b/g,     // human callback-style code
  /\bthat\s*=\s*this\b/g, // classic closure pattern
  /\barguments\b/g,    // use of arguments object
];

function sigTokenFrequencyProfile(content: string, lineCount: number): number {
  if (lineCount < 30) return 0;
  const totalTokens = (content.match(/\b\w+\b/g) ?? []).length;
  if (totalTokens < 100) return 0;
  let aiScore   = 0;
  let humanPenalty = 0;
  for (const re of TOKEN_FREQ_AI)   aiScore      += (content.match(re) ?? []).length;
  for (const re of TOKEN_FREQ_HUMAN) humanPenalty += (content.match(re) ?? []).length;
  const aiRatio    = aiScore      / totalTokens;
  const humanRatio = humanPenalty / totalTokens;
  // Strong human signals override
  if (humanRatio > 0.03) return 0;
  if (humanRatio > 0.01) return Math.max(0, (aiRatio - 0.06) / 0.06 * 0.3);
  // Pure AI signal: high density of AI-favoured tokens
  if (aiRatio > 0.14) return Math.min(1, (aiRatio - 0.14) / 0.10);
  if (aiRatio > 0.09) return (aiRatio - 0.09) / 0.05 * 0.55;
  if (aiRatio > 0.06) return (aiRatio - 0.06) / 0.03 * 0.30;
  return 0;
}

// ══════════════════════════════════════════════════════════════════════════════
// SIGNALS S42–S47  (v6 additions)
// ══════════════════════════════════════════════════════════════════════════════

// Signal 42: Prompt Leakage Detection (q = 0.88, CORE)
// AI models sometimes embed fragments of their system prompt or chat preamble
// inside the output.  Any of these phrases appearing in code or comments is a
// near-certain indicator of direct AI output, not human typing.
const PROMPT_LEAK_PATTERNS: RegExp[] = [
  /\bAs an AI\b/i,
  /\bAs a language model\b/i,
  /\bI cannot (?:actually|truly|really|help)\b/i,
  /\bAs requested[,\s]/i,
  /\bCertainly[!,]\s/i,
  /\bSure[!,]\s+here(?:'s| is)/i,
  /\bHere(?:'s| is) (?:the|an?) (?:implementation|solution|code|example|function)/i,
  /\bThis (?:function|method|code|implementation|class) (?:will|should|handles?|provides?)\b/i,
  /\bIn this (?:implementation|solution|code|example)\b/i,
  /\bThe following (?:code|implementation|function|class|snippet)\b/i,
  /\bI(?:'ve| have) (?:implemented|created|added|written|included)\b/i,
  /\bLet me (?:explain|walk you|break|describe)\b/i,
  /\[INST\]/,
  /<\/?(?:s|system|user|assistant|instruction|task|context|prompt)>/i,
  /<<(?:SYS|INST|s)>>/,
  /\bNote:?\s+(?:This|The|I|You|We)\b/i,
  /\bIMPORTANT:?\s+(?:This|The|Make sure|Ensure|Please)\b/i,
  /\/\/\s*(?:Step \d+|Phase \d+):\s+\w/,
];

function sigPromptLeakage(content: string): number {
  const commentLines = content.split("\n").filter(l => /^\s*(?:\/\/|#|\/\*|\*|<!--)/.test(l));
  const stringBlocks = (content.match(/["'`](?:[^"'`\\]|\\.)*["'`]/g) ?? []).join("\n");
  const target = commentLines.join("\n") + "\n" + stringBlocks;
  let hits = 0;
  for (const re of PROMPT_LEAK_PATTERNS) if (re.test(target)) hits++;
  if (hits >= 4) return 1.0;
  if (hits >= 3) return 0.85;
  if (hits >= 2) return 0.65;
  if (hits >= 1) return 0.40;
  return 0;
}

// Signal 43: AI Style Drift (q = 0.65, CORE)
// When a file is partly human and partly AI-generated the signal density shifts
// sharply between the first and last thirds of the file.
// NOTE: calls computeAIPercentage recursively — declared after it below;
// the actual sigStyleDrift function is defined after computeAIPercentage.
// Placeholder resolved at call site.

// Signal 44: AI Watermark Detection (q = 0.95, CORE)
// Some AI tools embed invisible Unicode characters as provenance watermarks.
const WATERMARK_CHAR_DEFS: Array<{ re: RegExp; type: WatermarkHit["type"]; label: string }> = [
  { re: /​/, type: "unicode-zwsp",  label: "Zero-width space (U+200B)" },
  { re: /‌/, type: "unicode-zwnj",  label: "Zero-width non-joiner (U+200C)" },
  { re: /‍/, type: "unicode-zwj",   label: "Zero-width joiner (U+200D)" },
  { re: /­/, type: "soft-hyphen",   label: "Soft hyphen (U+00AD)" },
  { re: /⁠/, type: "word-joiner",   label: "Word joiner (U+2060)" },
  { re: /﻿/, type: "unicode-zwsp",  label: "BOM / zero-width no-break space (U+FEFF)" },
];

export function findWatermarks(content: string): WatermarkHit[] {
  const hits: WatermarkHit[] = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const { re, type, label } of WATERMARK_CHAR_DEFS) {
      if (re.test(lines[i])) hits.push({ type, line: i + 1, detail: label });
    }
    const hashMatch = lines[i].match(/\/\/\s*([A-F0-9]{32,})\s*$/i);
    if (hashMatch) {
      hits.push({ type: "comment-hash", line: i + 1, detail: `Embedded hash: ${hashMatch[1].slice(0, 8)}…` });
    }
  }
  return hits;
}

function sigWatermarkDetection(content: string): number {
  const hits = findWatermarks(content);
  if (hits.length >= 3) return 1.0;
  if (hits.length >= 1) return 0.90;
  return 0;
}

// Signal 45: AI Backdoor Detection (q = 0.85, CORE)
// Logic bombs, covert exfiltration, hardcoded privilege bypasses, timing channels.
const BACKDOOR_PATTERNS: Array<{ re: RegExp; weight: number }> = [
  { re: /new\s+Date\(\)\.(?:getFullYear|getMonth|getDate|getTime)\(\)\s*[><=!]+\s*\d/,     weight: 3 },
  { re: /Date\.now\(\)\s*[><=!]+\s*\d{10,}/,                                               weight: 3 },
  { re: /process\.env\.[A-Z_]+\s*===?\s*["'](?:true|1|enable|admin|bypass|override)["']/,  weight: 2 },
  { re: /fetch\s*\(\s*`[^`]*\$\{(?:user|session|token|pass|secret|key|auth|cookie)\b/i,    weight: 3 },
  { re: /new\s+Image\(\)[\s\S]{0,80}\.src\s*=/,                                            weight: 2 },
  { re: /navigator\.sendBeacon\s*\(/,                                                       weight: 2 },
  { re: /(?:user|email|username)\s*===?\s*["'](?:admin|root|superuser|backdoor|debug)["']/i, weight: 3 },
  { re: /password\s*===?\s*["'][^"']{4,}["']/i,                                            weight: 3 },
  { re: /setTimeout\s*\([^,]+,\s*(?:content|data|user|input)\.length\b/i,                  weight: 2 },
  { re: /(?:atob|btoa)\s*\(\s*["'][A-Za-z0-9+/=]{20,}["']\s*\)/,                          weight: 2 },
  { re: /eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)/,                            weight: 3 },
  { re: /Object\.prototype\[\s*["'][^"']+["']\s*\]\s*=/,                                   weight: 3 },
];

function sigBackdoorDetection(content: string): number {
  let w = 0;
  for (const { re, weight } of BACKDOOR_PATTERNS) if (re.test(content)) w += weight;
  if (w >= 9) return 1.0;
  if (w >= 6) return 0.85;
  if (w >= 3) return 0.65;
  if (w >= 2) return 0.40;
  return 0;
}

// Signal 46: Hallucinated API Detection (q = 0.55, SECONDARY)
// AI models confidently call APIs that don't exist.
const HALLUCINATED_API_PATTERNS: RegExp[] = [
  /Array\.isEmpty\s*\(/, /String\.isEmpty\s*\(/, /Array\.isObject\s*\(/,
  /Object\.isEmpty\s*\(/, /Array\.flatten\s*\((?!\s*\[)/,
  /JSON\.parse\s*\([^)]+\)\.validate\s*\(/,
  /fs\.readFile\w*\s*\([^)]+\)\.parse\s*\(/,
  /res\.json\s*\(\s*\)\.then\s*\(/,
  /\.\s*validateAnd(?:Save|Parse|Return|Process|Submit|Send)\s*\(/i,
  /\.\s*parseAnd(?:Validate|Return|Process|Save|Transform)\s*\(/i,
  /\.\s*fetchAnd(?:Update|Save|Return|Process|Store)\s*\(/i,
  /\.\s*getAnd(?:Set|Update|Return|Process|Validate)\s*\(/i,
  /\.\s*findOneAndValidate\s*\(/i,
  /\.\s*saveAndReturn\s*\(/i,
  /\.\s*updateAndRefresh\s*\(/i,
  /\.\s*deleteAndCleanup\s*\(/i,
];

function sigHallucinatedAPI(content: string): number {
  let hits = 0;
  for (const re of HALLUCINATED_API_PATTERNS) if (re.test(content)) hits++;
  if (hits >= 4) return 1.0;
  if (hits >= 3) return 0.80;
  if (hits >= 2) return 0.60;
  if (hits >= 1) return 0.35;
  return 0;
}

// Signal 47: Copy-Paste / StackOverflow Pattern Detection (q = 0.42, SECONDARY)
const COPY_PASTE_PATTERNS: RegExp[] = [
  /function\s+debounce\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\{[\s\S]{0,300}clearTimeout/,
  /function\s+throttle\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\{[\s\S]{0,300}lastTime/,
  /JSON\.parse\s*\(\s*JSON\.stringify\s*\(/,
  /class\s+LRU(?:Cache)?\s*\{[\s\S]{0,500}this\.map\s*=\s*new\s+Map/,
  /function\s+binarySearch\s*\(\s*\w+\s*,\s*\w+\s*\)[\s\S]{0,300}Math\.floor\s*\(\s*\(\s*\w+\s*\+\s*\w+\s*\)\s*\/\s*2\s*\)/,
  /const\s+memo\s*=\s*(?:\{\}|new\s+Map\s*\(\s*\))[\s\S]{0,200}function\s+fib/,
  /class\s+EventEmitter\s*\{[\s\S]{0,300}this\.listeners\s*=\s*(?:\{\}|new\s+Map)/,
  /function\s+(?:uuidv4|generateUUID|uuid)\s*\(\s*\)\s*\{[\s\S]{0,200}xxxxxxxx-xxxx/,
  /function\s+flatten\s*\(\s*\w+\s*\)\s*\{[\s\S]{0,200}Array\.isArray\s*\([\s\S]{0,100}flatten\s*\(/,
];

function sigCopyPastePattern(content: string): number {
  let hits = 0;
  for (const re of COPY_PASTE_PATTERNS) if (re.test(content)) hits++;
  if (hits >= 3) return 1.0;
  if (hits >= 2) return 0.70;
  if (hits >= 1) return 0.45;
  return 0;
}

// ── Signal tier classification ────────────────────────────────────────────────
// Root cause of false positives: with 35 signals in a flat noisy-OR, a senior
// developer's clean TypeScript accumulates noisyOr ≈ 0.99 (98% AI).
// Fix: three-phase scoring. Only CORE signals drive the primary probability.
// SECONDARY amplify it. STYLE provides a small cap-bounded corroboration boost.
// ── Zero-debug-artifact signal (LR ≈ 8, very high) ──────────────────────────
// AI never leaves console.log("debug"), // TODO, // FIXME, commented-out code blocks,
// or placeholder `pass` statements. Human developers always do.
// Absence of all debug artifacts in a file with >30 lines is a strong AI signal.
function sigZeroDebugArtifacts(content: string, lineCount: number): number {
  if (lineCount < 20) return 0;
  const lines = content.split("\n");

  // Count debug/human artifacts
  const todoFixes  = lines.filter(l => /\/\/\s*(?:TODO|FIXME|HACK|XXX|BUG|NOTE|TEMP)\b/i.test(l) || /#\s*(?:TODO|FIXME|HACK|XXX|BUG)\b/i.test(l)).length;
  const consoleLogs = lines.filter(l => /\bconsole\s*\.\s*(?:log|warn|error|debug|info)\s*\(/.test(l)).length;
  const printDebugs = lines.filter(l => /\bprint\s*\(["'](?:debug|test|here|check|ok|yes)\b/i.test(l) || /\bpprint\s*\(/.test(l)).length;
  const commentedCode = (() => {
    let runs = 0; let inRun = false;
    for (const l of lines) {
      const isCommentedCode = /^\s*(?:\/\/|#)\s*(?:const|let|var|function|return|if|for|import|def|class|public|private)\b/.test(l);
      if (isCommentedCode) { if (!inRun) { runs++; inRun = true; } } else { inRun = false; }
    }
    return runs;
  })();
  const placeholders = lines.filter(l => /\bpass\s*(?:#.*)?$/.test(l.trim()) || /\bthrow\s+new\s+Error\s*\(\s*["'](?:Not implemented|TODO|not implemented)\b/i.test(l)).length;

  const totalArtifacts = todoFixes + consoleLogs + printDebugs + commentedCode + placeholders;

  // Key insight: if a file has ZERO of all these artifacts AND is substantial, that's AI
  if (totalArtifacts === 0 && lineCount > 50) {
    // Scale with file size — larger files with zero artifacts = stronger signal
    const sizeFactor = Math.min(1, (lineCount - 50) / 200);
    return 0.55 + sizeFactor * 0.35;
  }
  if (totalArtifacts === 0 && lineCount > 20) return 0.40;
  if (totalArtifacts === 1) return 0.15; // One stray TODO doesn't negate the signal
  return 0; // Multiple artifacts = human
}

// ── Import exhaustiveness signal ──────────────────────────────────────────────
// AI imports exactly what it uses, with perfect organisation.
// Human code has unused imports, missing imports, messy ordering.
function sigImportExhaustiveness(content: string, lang: string): number {
  if (lang !== "typescript" && lang !== "javascript") return 0;
  const lines = content.split("\n");
  const importLines = lines.filter(l => /^\s*import\s+/.test(l));
  if (importLines.length < 3) return 0;

  // Check for unused import patterns (human code always has these eventually)
  // AI code rarely has //eslint-disable-next-line or @ts-ignore on imports
  const eslintDisables = lines.filter(l => /eslint-disable|@ts-ignore|@ts-expect-error/.test(l)).length;
  if (eslintDisables > 0) return 0; // Human workaround = human code

  // Check import organisation: all from same module grouped together
  let prevModule = "";
  let outOfOrder = 0;
  for (const l of importLines) {
    const m = /from\s+["']([^"']+)["']/.exec(l);
    if (!m) continue;
    const mod = m[1].startsWith(".") ? "local" : m[1].split("/")[0];
    if (mod < prevModule && prevModule !== "local" && mod !== "local") outOfOrder++;
    prevModule = mod;
  }

  // Perfectly ordered imports with no eslint-disables = AI signal
  if (outOfOrder === 0 && importLines.length >= 4 && eslintDisables === 0) {
    return Math.min(0.75, 0.30 + importLines.length * 0.05);
  }
  return 0;
}

// Tiers are derived from estimated LR = P(signal|AI) / P(signal|human code).

// Tier 1 — genuinely discriminates AI from senior human developers (LR > 4.0)
const CORE_SIGNALS = new Set([
  "comment-phrasing",     // AI uses formulaic phrasing patterns humans almost never write
  "language-specific",    // Language-specific stereotyped AI patterns
  "test-structure",       // Robotically uniform AI test suites
  "lexical-diversity",    // AI reuses ~200 identifiers; human TTR is measurably higher
  "variable-vocabulary",  // AI generic names (result, handler, payload, processor)
  "sentence-identifiers", // AI writes verbose 4-word function names
  "ngram-fingerprint",    // Characteristic AI token bigrams (return {success:, const result =, etc.)
  "structural-clones",    // 3+ near-identical function bodies within a single file
  "prompt-leakage",       // AI preamble / system-prompt fragments leaked into code
  "style-drift",          // Sharp AI-signal shift between first and last thirds of file
  "watermark-detection",  // Invisible Unicode watermark characters
  "backdoor-detection",   // Logic bombs, exfiltration, hardcoded bypasses
]);

// jsdoc-completeness, zero-debug-artifacts, and import-exhaustiveness were
// moved out of CORE and into SECONDARY below. All three measure "is this
// code polished/complete" rather than anything AI-specific — a mature,
// well-reviewed human codebase (the benchmark's zod/dompurify/entities
// samples) has thorough docs, no leftover debug artifacts, and clean
// imports precisely *because* it went through review, not because AI wrote
// it. As CORE signals they could independently drive coreNoisyOr high on
// their own; as SECONDARY they can only amplify existing core evidence
// (see the "Multiplicative combination" comment below), which is the same
// treatment already applied to doc-coverage/language-specific for the same
// reason (see the LANG_LEAK_BOOST comment).

// Tier 2 — moderately discriminating, compound with Tier 1 evidence (LR 1.8–4.0)
const SECONDARY_SIGNALS = new Set([
  "doc-coverage", "error-uniformity", "structural-repetition",
  "cyclomatic-uniformity", "function-size", "method-chain-density",
  "structured-logging", "comment-density", "exhaustive-switches",
  "exception-specificity", "guard-clause-density", "magic-number-absence",
  "boilerplate",
  "error-message-phrasing",   // AI uses "Invalid X", "X is required", "Failed to X" templates
  "identifier-length",        // AI identifier lengths are uniform (no short loop vars like i,n,ok)
  "token-frequency",          // AI-surplus tokens: await/const/interface/Readonly at high density
  "hallucinated-api",         // Calls to non-existent APIs (validateAndSave, Array.isEmpty, etc.)
  "copy-paste-pattern",       // Verbatim StackOverflow algorithm implementations
  "jsdoc-completeness",   "zero-debug-artifacts", "import-exhaustiveness",
]);

// Tier 3 — "good practice" that any senior developer exhibits (LR < 1.8)
// These cannot drive the score. They only add a small capped boost when
// combined with primary evidence.
const STYLE_SIGNALS = new Set([
  "async-consistency", "functional-preference", "template-literals",
  "naming-consistency", "import-organization", "dead-code-absence",
  "nesting-depth", "async-try-catch", "immutable-preference",
  "return-types", "verb-prefix", "destructuring-density",
  "line-length", "default-params", "arrow-consistency", "type-guards",
  "blank-line-regularity",   // AI has perfect blank-line discipline; humans are messier
]);

// ── Per-language leak multipliers (only for Core + Secondary signals) ─────────
const LANG_LEAK_BOOST: Partial<Record<string, Partial<Record<string, number>>>> = {
  // "language-specific" for TS/JS checks for modern type-safe syntax
  // (interfaces, optional chaining, readonly, utility types, etc.). These are
  // now mainstream professional conventions, not AI-specific — dampen from
  // the default 0.60 leak to 0.30 so it can't single-handedly drive the score
  // for any well-typed human codebase (e.g. zod's own source).
  typescript: { "doc-coverage":0.55, "cyclomatic-uniformity":0.62, "error-uniformity":0.58,
                "exception-specificity":0.42, "language-specific":0.30 },
  javascript: { "cyclomatic-uniformity":0.58, "language-specific":0.30 },
  python:     { "doc-coverage":0.62, "language-specific":0.78, "cyclomatic-uniformity":0.58 },
  golang:     { "error-uniformity":0.68, "cyclomatic-uniformity":0.62 },
  java:       { "doc-coverage":0.62, "language-specific":0.78, "cyclomatic-uniformity":0.58,
                "exception-specificity":0.42 },
  rust:       { "error-uniformity":0.65, "cyclomatic-uniformity":0.62 },
  csharp:     { "doc-coverage":0.60, "cyclomatic-uniformity":0.58 },
  kotlin:     { "cyclomatic-uniformity":0.58 },
};

// ── Signal q-weights (evidential leak per tier) ───────────────────────────────
// CORE signals drive the primary AI probability via noisy-OR.
// SECONDARY signals amplify PROPORTIONAL to core evidence.
// STYLE signals are shown for explainability only; they never affect the score.
// Q values calibrated from estimated LR = P(signal|AI) / P(signal|human code).

const SIGNAL_LEAKS: Array<[string, number]> = [
  // ── Tier 1: CORE (LR > 4) ──────────────────────────────────────────────────
  ["comment-phrasing",        0.65],  // Formulaic AI comments rarely appear in human code
  ["jsdoc-completeness",      0.70],  // AI documents every function; humans skip trivial ones
  ["zero-debug-artifacts",    0.75],  // AI never leaves TODO/console.log/commented code
  ["import-exhaustiveness",   0.60],  // AI imports exactly what it uses; humans have messy imports
  ["language-specific",       0.60],  // Stereotyped per-language AI patterns
  ["ngram-fingerprint",       0.65],  // Characteristic token bigrams (return {success:, const result=await, etc.)
  ["test-structure",          0.55],  // Robotically uniform AI test suites
  ["structural-clones",       0.60],  // 3+ near-identical function bodies = AI-generated CRUD
  ["lexical-diversity",       0.50],  // Low TTR: AI reuses ~200 identifiers consistently
  ["variable-vocabulary",     0.50],  // Generic AI names: result, handler, payload
  ["sentence-identifiers",    0.45],  // 4-word function names are an AI hallmark
  // ── Tier 2: SECONDARY (LR 1.8–4) ──────────────────────────────────────────
  ["error-uniformity",        0.52],  // AI error handling is robotically consistent
  ["cyclomatic-uniformity",   0.52],  // AI generates identically-structured functions
  ["doc-coverage",            0.45],  // AI documents every function; humans skip obvious ones
  ["structural-repetition",   0.42],  // Try/catch boilerplate in every function
  ["function-size",           0.40],  // AI generates suspiciously same-sized functions
  ["comment-density",         0.40],  // AI comments every block; senior devs comment sparingly
  ["method-chain-density",    0.35],  // AI prefers fluent chains; humans use intermediate vars
  ["structured-logging",      0.35],  // AI uses structured context objects everywhere
  ["guard-clause-density",    0.35],  // AI applies early-return guards mechanically
  ["exhaustive-switches",     0.28],  // AI adds default cases; humans sometimes omit them
  ["exception-specificity",   0.28],  // Specific exception types in every catch
  ["magic-number-absence",    0.25],  // AI names all constants; humans sometimes inline them
  ["boilerplate",             0.25],  // Repetitive template patterns
  ["error-message-phrasing",  0.42],  // "Invalid X", "X is required", "Failed to X" templates
  ["identifier-length",       0.38],  // Uniform identifier length (no short loop vars)
  ["token-frequency",         0.40],  // await/const/interface/Readonly surplus vs var/this/prototype
  ["hallucinated-api",        0.55],  // Non-existent API calls (validateAndSave, Array.isEmpty)
  ["copy-paste-pattern",      0.42],  // Verbatim StackOverflow implementations
  // ── New CORE signals (v6) ──────────────────────────────────────────────────
  ["prompt-leakage",          0.88],  // AI preamble leaked into code comments / strings
  ["style-drift",             0.65],  // AI-signal density jumps sharply mid-file
  ["watermark-detection",     0.95],  // Invisible Unicode watermark characters
  ["backdoor-detection",      0.85],  // Logic bombs / exfiltration / hardcoded bypasses
  // ── Tier 3: STYLE (LR < 1.8) — shown for explainability, score weight = 0 ──
  ["async-consistency",       0.15],  // Any modern TS/JS also avoids .then mixing
  ["functional-preference",   0.18],  // Senior devs also use map/filter/reduce
  ["template-literals",       0.12],  // Any modern JS uses template literals
  ["naming-consistency",      0.12],  // ESLint enforces this on human code too
  ["import-organization",     0.12],  // Auto-formatted by Prettier/ESLint
  ["dead-code-absence",       0.10],  // ESLint warns on unused vars for everyone
  ["nesting-depth",           0.15],  // Shallow nesting is a common human practice too
  ["async-try-catch",         0.18],  // Any good async code wraps in try/catch
  ["immutable-preference",    0.15],  // Senior devs prefer const too
  ["return-types",            0.15],  // TypeScript strict mode enables this for everyone
  ["verb-prefix",             0.18],  // Naming convention most teams enforce
  ["destructuring-density",   0.15],  // Any modern JS developer uses destructuring
  ["line-length",             0.08],  // Prettier makes all code equally "uniform"
  ["default-params",          0.12],  // Common pattern for any experienced developer
  ["arrow-consistency",       0.10],  // Any modern JS/TS uses arrow callbacks
  ["type-guards",             0.15],  // TypeScript best practice widely adopted
  ["blank-line-regularity",   0.30],  // AI: max 1 blank line, perfect regularity; humans vary
];

interface SignalResult { id: string; value: number; leak: number }

// Three-phase scoring engine.
//
// Root cause of the false-positive problem in a flat noisy-OR: with 35 signals
// each with q ≈ 0.45, well-written TypeScript by a senior developer accumulates
// product ≈ 0.001 → noisyOr ≈ 0.999 → sigmoid → 98% AI. The fix is to make
// secondary and style signals PROPORTIONAL amplifiers of core evidence rather
// than independent probability contributors.
//
// Phase 1 (CORE): six genuinely discriminating signals form a noisy-OR.
//   Without core signal evidence the score is bounded to a low ceiling.
// Phase 2 (SECONDARY): thirteen moderately discriminating signals amplify the
//   core probability MULTIPLICATIVELY — secNoisyOr * 0.45 * coreNoisyOr.
//   This means secondary signals add nothing when core is silent.
// Phase 3 (STYLE): sixteen "good practice" signals are shown in fired[] for
//   explainability but do not feed into the score.
//
// Sigmoid inflection raised to 0.55 (vs old 0.45) so that moderate evidence
// maps below 50%, preventing MEDIUM/HIGH false positives on human code.
function computeAIPercentage(
  content: string, lang: string, lineCount: number, priorBias = 0, humanEvidence = 0,
): { score: number; fired: SignalResult[]; applicableCount: number } {
  const lines = content.split("\n");

  const raw: Record<string, number> = {
    "comment-phrasing":      sigCommentPhrasing(content),
    "jsdoc-completeness":    sigJSDocCompleteness(content),
    "zero-debug-artifacts":  sigZeroDebugArtifacts(content, lineCount),
    "import-exhaustiveness": sigImportExhaustiveness(content, lang),
    "language-specific":     sigLanguageSpecific(content, lang),
    "test-structure":        sigTestStructure(content),
    "doc-coverage":          sigDocumentationCoverage(content, lang),
    "lexical-diversity":     sigLexicalDiversity(content, lineCount),
    "error-uniformity":      sigErrorHandlingUniformity(content, lang),
    "variable-vocabulary":   sigVariableVocabulary(content),
    "sentence-identifiers":  sigSentenceIdentifiers(content, lang),
    "async-consistency":     sigAsyncConsistency(content, lang),
    "functional-preference": sigFunctionalPreference(content, lang),
    "function-size":         sigFunctionSizeUniformity(content, lang),
    "nesting-depth":         sigShallowNesting(content, lineCount),
    "structural-repetition": sigStructuralRepetition(lines),
    "guard-clause-density":  sigGuardClauseDensity(content, lang),
    "magic-number-absence":  sigMagicNumberAbsence(content, lineCount),
    "boilerplate":           sigBoilerplateDensity(content, lineCount),
    "template-literals":     sigTemplateLiteralExclusivity(content, lang),
    "method-chain-density":  sigMethodChainDensity(content, lang),
    "naming-consistency":    sigNamingConsistency(content),
    "import-organization":   sigImportOrganization(content, lang),
    "dead-code-absence":     sigDeadCodeAbsence(content, lineCount),
    "comment-density":       sigCommentDensity(lines, lang),
    "async-try-catch":       sigAsyncTryCatch(content, lang),
    "immutable-preference":  sigImmutablePreference(content, lang),
    "exhaustive-switches":   sigExhaustiveSwitches(content),
    "type-guards":           sigTypeGuards(content, lang),
    "structured-logging":    sigStructuredLogging(content, lang),
    "cyclomatic-uniformity": sigCyclomaticUniformity(content, lang),
    "return-types":          sigReturnTypeAnnotations(content, lang),
    "verb-prefix":           sigVerbPrefixConsistency(content, lang),
    "destructuring-density": sigObjectDestructuringDensity(content, lang),
    "exception-specificity": sigExceptionSpecificity(content, lang),
    "line-length":           sigLineLengthUniformity(content, lineCount),
    "default-params":        sigDefaultParameters(content, lang),
    "arrow-consistency":     sigArrowFunctionConsistency(content, lang),
    // ── Signals S36–S41 ────────────────────────────────────────────────────
    "ngram-fingerprint":     sigNgramFingerprint(content),
    "structural-clones":     sigStructuralClones(content, lang),
    "error-message-phrasing":sigErrorMessagePhrasing(content),
    "identifier-length":     sigIdentifierLengthUniformity(content, lineCount),
    "blank-line-regularity": sigBlankLineRegularity(content, lineCount),
    "token-frequency":       sigTokenFrequencyProfile(content, lineCount),
    // ── Signals S42–S47 (v6) ──────────────────────────────────────────────
    "prompt-leakage":        sigPromptLeakage(content),
    "style-drift":           0,  // computed after this call to avoid recursion; injected by analyzeFile
    "watermark-detection":   sigWatermarkDetection(content),
    "backdoor-detection":    sigBackdoorDetection(content),
    "hallucinated-api":      sigHallucinatedAPI(content),
    "copy-paste-pattern":    sigCopyPastePattern(content),
  };

  const langBoosts = LANG_LEAK_BOOST[lang] ?? {};
  const fired: SignalResult[] = [];
  let applicableCount = 0;

  // ── Phase 1: Core signals ─────────────────────────────────────────────────
  let coreProduct = 1;
  for (const [id, baseLeak] of SIGNAL_LEAKS) {
    if (!CORE_SIGNALS.has(id)) continue;
    const leak = langBoosts[id] ?? baseLeak;
    const s    = raw[id] ?? 0;
    if (s > 0.02) applicableCount++;
    if (s > 0.05) fired.push({ id, value: s, leak });
    coreProduct *= (1 - leak * s);
  }
  const coreNoisyOr = 1 - coreProduct;  // 0 = no core evidence, 1 = certainty

  // ── Phase 2: Secondary signals ────────────────────────────────────────────
  let secProduct = 1;
  let secFiredCount = 0;
  for (const [id, baseLeak] of SIGNAL_LEAKS) {
    if (!SECONDARY_SIGNALS.has(id)) continue;
    const leak = langBoosts[id] ?? baseLeak;
    const s    = raw[id] ?? 0;
    if (s > 0.02) applicableCount++;
    if (s > 0.05) { fired.push({ id, value: s, leak }); secFiredCount++; }
    secProduct *= (1 - leak * s);
  }
  const secNoisyOr = 1 - secProduct;

  // ── Phase 3: Style signals — explainability only ──────────────────────────
  for (const [id, baseLeak] of SIGNAL_LEAKS) {
    if (!STYLE_SIGNALS.has(id)) continue;
    const s = raw[id] ?? 0;
    if (s > 0.02) applicableCount++;
    if (s > 0.05) fired.push({ id, value: s, leak: baseLeak });
  }

  // ── Multiplicative combination ────────────────────────────────────────────
  // Secondary amplifies IN PROPORTION to core evidence. When coreNoisyOr = 0
  // (no AI comment phrasing, no language-specific patterns, etc.) the secondary
  // term collapses to zero and can't generate false positives by itself.
  //
  // For files with overwhelming secondary evidence but minimal core signals
  // (e.g. machine-generated config), a small floor prevents complete silence.
  const secOnlyFloor = (coreNoisyOr < 0.08 && secNoisyOr > 0.65 && secFiredCount >= 7)
    ? Math.min(0.22, secNoisyOr * 0.18)
    : 0;

  let combined = Math.min(1.0, Math.max(0,
    coreNoisyOr * (1 + secNoisyOr * 0.75) + secOnlyFloor + priorBias,
  ));

  // Human-authorship dampening: genuine human-written signals (typos, dated
  // personal comments, debug prints, mixed indentation, etc.) pull the
  // combined score down. Capped at 30% reduction.
  combined *= (1 - Math.min(0.30, humanEvidence * 0.20));

  // Sigmoid centred at 0.44 (recalibrated from 0.50).
  // The calibration history: 0.55 (avoid false positives) → 0.50 (restore sensitivity)
  // → 0.44 (correct for modern LLM code that fires signals at lower intensities
  //   than 2022-era AI code the original weights were calibrated against).
  //
  // Empirical targets after calibration:
  //   Clear human code (weak core ≈ 0.15)    → combined ≈ 0.20 → sigmoid ≈ 22%
  //   Mixed / tool-assisted (core ≈ 0.35)    → combined ≈ 0.48 → sigmoid ≈ 54%
  //   Clear AI (strong core ≈ 0.65+)         → combined ≈ 0.80 → sigmoid ≈ 85%
  //   Obvious AI (all signals ≥ 0.70)        → combined → 1.0  → sigmoid ≈ 98%
  const sigmoid = 1 / (1 + Math.exp(-8 * (combined - 0.44)));

  return { score: Math.min(1, sigmoid), fired, applicableCount };
}

// ── Cross-file taint propagation ────────────────────────────────────────────
//
// SSA-level taint analysis (findSSRFTainted, findSQLInjectionTainted, etc.) is
// file-local: it can see `const x = req.query.url; fetch(x)` but not
// `const x = getUrl(); fetch(x)` where getUrl() is defined in another file.
// This pass closes part of that gap: for every direct import edge where the
// imported file has its own unresolved taint path(s), flag the importing file
// so reviewers know the taint may cross the module boundary.
function computeCrossFileTaintIndicators(
  files: FileAnalysis[], graph: SemanticGraph,
): Map<string, ScanIndicator[]> {
  const out = new Map<string, ScanIndicator[]>();
  const taintByFile = new Map<string, TaintPath[]>();
  for (const f of files) {
    if (f.ssa_taint_paths.length > 0) taintByFile.set(f.file_path, f.ssa_taint_paths);
  }
  if (taintByFile.size === 0) return out;

  const seen = new Set<string>(); // dedupe per (consumer file, source file)
  for (const call of graph.crossFileCalls) {
    const taints = taintByFile.get(call.calleeFile);
    if (!taints || taints.length === 0) continue;
    const best = taints.reduce((a, b) => (b.confidence > a.confidence ? b : a));
    if (best.confidence < 0.5) continue;
    const key = `${call.callerFile}::${call.calleeFile}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const list = out.get(call.callerFile) ?? [];
    list.push({
      id:       "cross-file-taint-exposure",
      label:    "Cross-File Taint Exposure",
      severity: "medium",
      line:     call.importLine,
      detail:   `Imports "${call.symbolName}" from ${call.calleeFile}, which has an unresolved ${best.sink} taint path (line ${best.sinkLine}) — verify sanitization across this module boundary`,
    });
    out.set(call.callerFile, list);
  }
  return out;
}

// ── AI blast-radius indicators ──────────────────────────────────────────────
// Combines two zero-new-infrastructure signals for "does this AI-heavy
// file's risk actually matter beyond itself": (1) semanticGraph.ts's real
// import-reverseEdges reach, scoped to this PR's own changeset -- there is
// no visibility into the rest of the repo (see semanticGraph.ts's
// blastRadius doc comment); (2) a path-keyword proxy for "sensitive area,"
// standing in for real call-graph criticality data this pipeline doesn't
// have access to.

const CRITICAL_PATH_KEYWORDS = [
  "payment", "billing", "checkout", "stripe", "invoice",
  "auth", "login", "session", "token", "credential", "secret",
  "webhook", "admin", "permission", "role", "acl",
];

function pathCriticality(filePath: string): string | null {
  const lower = filePath.toLowerCase();
  return CRITICAL_PATH_KEYWORDS.find(k => lower.includes(k)) ?? null;
}

function computeBlastRadiusIndicators(
  files: FileAnalysis[], graph: SemanticGraph,
): Map<string, ScanIndicator[]> {
  const out = new Map<string, ScanIndicator[]>();
  const blastByFile = new Map(graph.blastRadius.map(b => [b.sourceFile, b]));

  for (const f of files) {
    if (f.ai_percentage < 0.4) continue; // only meaningfully-AI files carry blast-radius risk

    const blast = blastByFile.get(f.file_path);
    const pathHit = pathCriticality(f.file_path);
    if (!blast && !pathHit) continue;

    const reasons: string[] = [];
    if (blast) {
      const shown = blast.reachesFiles.slice(0, 3).join(", ");
      const more = blast.reachesFiles.length > 3 ? `, +${blast.reachesFiles.length - 3} more` : "";
      reasons.push(`imported (directly or transitively) by ${blast.reachesFiles.length} other file(s) in this PR: ${shown}${more}`);
    }
    if (pathHit) reasons.push(`file path suggests a sensitive area ("${pathHit}")`);

    // Mirror the file's own vendored/third-party or test-code status -- this
    // indicator is injected post-analyzeFile() and so never passes through
    // attachEvidence(), which is what normally sets codeCategory.
    const mirroredCategory: "application" | "third_party" | "test_code" =
      f.indicators.some(i => i.codeCategory === "third_party") ? "third_party"
      : f.indicators.some(i => i.codeCategory === "test_code") ? "test_code"
      : "application";

    const list = out.get(f.file_path) ?? [];
    list.push({
      id:           "ai-blast-radius",
      label:        "AI Blast Radius",
      severity:     "medium",
      detail:       `${Math.round(f.ai_percentage * 100)}% AI-generated file: ${reasons.join("; ")}. Risk compounds with reach — review carefully before merging.`,
      confidence:   blast ? 70 : 50,
      codeCategory: mirroredCategory,
    });
    out.set(f.file_path, list);
  }
  return out;
}

// ── Risk calculation ───────────────────────────────────────────────────────────

function calculateRisk(indicators: ScanIndicator[], aiPct: number): RiskLevel {
  // Third-party/vendored findings (e.g. a pattern match inside jQuery's own
  // minified internals) are preserved as evidence on the file but must not
  // drive the file's own risk level -- they aren't code this repo's authors
  // wrote or can fix, and treating them as CRITICAL is exactly what produced
  // false-positive attestation requirements on vendor bundles.
  const own = indicators.filter(i => i.codeCategory !== "third_party" && i.codeCategory !== "test_code");
  if (own.some(i => i.severity === "critical")) return "CRITICAL";
  if (own.some(i => i.severity === "high"))     return "HIGH";
  // Thresholds calibrated for the new three-phase sigmoid (centred at 0.55).
  // A clearly AI file scores 0.80–0.96; a borderline human/AI file scores ~0.50.
  if (aiPct > 0.75)                                    return "HIGH";
  if (aiPct > 0.52)                                    return "MEDIUM";
  if (aiPct > 0.38 && own.length >= 2)                 return "MEDIUM";
  if (own.some(i => i.severity === "medium"))          return "MEDIUM";
  if (own.length > 0)                                  return "MEDIUM";
  return "LOW";
}

// ── Signal labels and details ──────────────────────────────────────────────────

const SIGNAL_LABELS: Record<string, string> = {
  "comment-phrasing":      "AI Comment Phrasing",
  "language-specific":     "Language-Specific AI Patterns",
  "test-structure":        "Uniform Test Structure",
  "doc-coverage":          "100% Documentation Coverage",
  "lexical-diversity":     "Low Identifier Diversity (TTR)",
  "error-uniformity":      "Uniform Error Handling",
  "variable-vocabulary":   "Generic AI Variable Vocabulary",
  "sentence-identifiers":  "Sentence-Style Function Names",
  "async-consistency":     "Pure Async/Await (no .then mixing)",
  "functional-preference": "Functional Loop Preference",
  "function-size":         "Uniform Function Sizes",
  "nesting-depth":         "Shallow Nesting Depth",
  "structural-repetition": "Repetitive Code Structure",
  "guard-clause-density":  "High Guard Clause Density",
  "magic-number-absence":  "Named Constants (no magic numbers)",
  "boilerplate":           "High Boilerplate Density",
  "template-literals":     "Template Literal Exclusivity",
  "method-chain-density":  "High Method Chain Density",
  "naming-consistency":    "Hyper-consistent Naming",
  "import-organization":   "Perfect Import Organisation",
  "dead-code-absence":     "No Dead Code / Debug Artifacts",
  "comment-density":       "Very High Comment Density",
  "async-try-catch":       "Async Try-Catch Coverage",
  "immutable-preference":  "Immutable Operation Preference",
  "exhaustive-switches":   "Exhaustive Switch Coverage",
  "type-guards":           "Type Guards Over Assertions",
  "structured-logging":    "Structured Logger Calls",
  "cyclomatic-uniformity": "Low + Uniform Cyclomatic Complexity",
  "return-types":          "Return Type Annotation Coverage",
  "verb-prefix":           "Action-Verb Function Naming",
  "destructuring-density": "Pervasive Object Destructuring",
  "exception-specificity": "Custom Typed Exception Usage",
  "line-length":           "Tight Line-Length Distribution",
  "default-params":        "Consistent Default Parameters",
  "arrow-consistency":     "Arrow-Function Callback Exclusivity",
  "ngram-fingerprint":     "AI Token Bigram Fingerprint",
  "structural-clones":     "Structural Function Clones",
  "error-message-phrasing":"Templated Error Messages",
  "identifier-length":     "Uniform Identifier Length Profile",
  "blank-line-regularity": "Perfect Blank-Line Discipline",
  "token-frequency":       "AI Token Frequency Surplus",
  "prompt-leakage":        "AI Prompt Leakage",
  "style-drift":           "AI Style Drift (Mid-File Shift)",
  "watermark-detection":   "AI Watermark Detected",
  "backdoor-detection":    "Potential AI Backdoor Pattern",
  "hallucinated-api":      "Hallucinated / Non-Existent API",
  "copy-paste-pattern":    "Copy-Paste / StackOverflow Pattern",
};

const SIGNAL_DETAILS: Record<string, (v: number) => string> = {
  "comment-phrasing":      v => `${Math.round(v*100)}% match — phrasing patterns match AI-generated docstrings`,
  "language-specific":     v => `${Math.round(v*100)}% match — language-specific AI patterns detected`,
  "test-structure":        v => `${Math.round(v*100)}% uniformity — test naming, assertion density, and setup patterns identical`,
  "doc-coverage":          v => `${Math.round(v*100)}% exported symbols documented — AI documents exhaustively`,
  "lexical-diversity":     v => `Low identifier TTR (${Math.round((1-v)*50+25)}%) — AI reuses same vocabulary across all functions`,
  "error-uniformity":      v => `${Math.round(v*100)}% uniformity — every error handled with the exact same pattern`,
  "variable-vocabulary":   v => `${Math.round(v*100)}% of variables use generic AI vocabulary (result/data/handler/…)`,
  "sentence-identifiers":  v => `${Math.round(v*100)}% signal — function names average 3+ words (AI descriptive style)`,
  "async-consistency":     v => `${Math.round(v*100)}% — pure async/await with no .then()/.catch() mixing`,
  "functional-preference": v => `${Math.round(v*100)}% — array methods/comprehensions exclusively, no imperative loops`,
  "function-size":         v => `${Math.round(v*100)}% uniformity — function sizes unusually consistent (low coefficient of variation)`,
  "nesting-depth":         v => `${Math.round(v*100)}% signal — max nesting ≤3 levels throughout; no callback hell`,
  "structural-repetition": v => `${Math.round(v*100)}% — JSDoc, try/catch, and line-length patterns are highly repetitive`,
  "guard-clause-density":  v => `${Math.round(v*100)}% signal — guard clauses applied uniformly to every function`,
  "magic-number-absence":  v => `${Math.round(v*100)}% signal — no unexplained numeric literals; all values are named constants`,
  "boilerplate":           v => `${Math.round(v*100)}% signal — null checks / error handlers exceed normal density`,
  "template-literals":     v => `${Math.round(v*100)}% — zero string concatenation; exclusively uses template literals`,
  "method-chain-density":  v => `${Math.round(v*100)}% signal — high method-chain line ratio (fluent interface preference)`,
  "naming-consistency":    v => `${Math.round(v*100)}% — naming convention applied without a single exception`,
  "import-organization":   v => `${Math.round(v*100)}% — imports perfectly organised, none commented-out`,
  "dead-code-absence":     v => `${Math.round((1-v)*100)}% clean — no commented-out code, debug prints, or informal TODOs`,
  "comment-density":       v => `${Math.round(v*100)}% — comment density exceeds 50% threshold`,
  "async-try-catch":       v => `${Math.round(v*100)}% — every async function wrapped in try-catch (uniform AI error handling)`,
  "immutable-preference":  v => `${Math.round(v*100)}% — spread/map/filter used exclusively; no push/splice/sort mutations`,
  "exhaustive-switches":   v => `${Math.round(v*100)}% — all switch statements include a default case`,
  "type-guards":           v => `${Math.round(v*100)}% — typeof/instanceof predicates preferred over 'as Type' assertions`,
  "structured-logging":    v => `${Math.round(v*100)}% — logger calls consistently use structured context objects`,
  "cyclomatic-uniformity": v => `${Math.round(v*100)}% — functions have low, uniform cyclomatic complexity (CC 2–6, low CV)`,
  "return-types":          v => `${Math.round(v*100)}% — TypeScript return types annotated on all exported/named functions`,
  "verb-prefix":           v => `${Math.round(v*100)}% — function names follow get/set/is/has/create/handle action-verb pattern`,
  "destructuring-density": v => `${Math.round(v*100)}% density — object/array destructuring in most assignment sites`,
  "exception-specificity": v => `${Math.round(v*100)}% — custom Error subclasses used instead of bare Error() or string throws`,
  "line-length":           v => `${Math.round(v*100)}% — code line lengths have unusually tight distribution (low CV)`,
  "default-params":        v => `${Math.round(v*100)}% of functions use default parameters (vs manual undefined checks)`,
  "arrow-consistency":      v => `${Math.round(v*100)}% — exclusively arrow-function callbacks; zero function() callback syntax`,
  "ngram-fingerprint":      v => `${Math.round(v*100)}% match — characteristic AI token bigrams (return {success:, const result = await, etc.)`,
  "structural-clones":      v => `${Math.round(v*100)}% signal — 3+ function bodies share structural fingerprint (AI CRUD generation pattern)`,
  "error-message-phrasing": v => `${Math.round(v*100)}% match — error messages use AI templates ("Invalid X", "X is required", "Failed to X")`,
  "identifier-length":      v => `${Math.round(v*100)}% signal — identifier lengths are uniformly 7–15 chars with no short loop variables`,
  "blank-line-regularity":  v => `${Math.round(v*100)}% signal — blank lines between functions are perfectly regular; no 3+ consecutive gaps`,
  "token-frequency":        v => `${Math.round(v*100)}% signal — await/const/interface/Readonly appear at 2-4× human baseline frequency`,
  "prompt-leakage":         v => `${Math.round(v*100)}% confidence — AI system-prompt or chat preamble fragments found in comments/strings`,
  "style-drift":            v => `${Math.round(v*100)}% drift — AI-signal density jumps ${Math.round(v*40+10)}pp between file start and end`,
  "watermark-detection":    _v => `Invisible Unicode watermark characters detected — near-certain AI generation marker`,
  "backdoor-detection":     v => `${Math.round(v*100)}% risk — suspicious patterns: logic bomb / exfiltration / hardcoded bypass detected`,
  "hallucinated-api":       v => `${Math.round(v*100)}% confidence — calls to non-existent APIs (validateAndSave, Array.isEmpty, etc.)`,
  "copy-paste-pattern":     v => `${Math.round(v*100)}% confidence — verbatim StackOverflow / tutorial algorithm implementation detected`,
};

// ══════════════════════════════════════════════════════════════════════════════
// HELPER ENGINES  (v6)
// ══════════════════════════════════════════════════════════════════════════════

// ── Style drift — defined here so it can call computeAIPercentage ─────────────

function sigStyleDrift(content: string, lang: string, lineCount: number): number {
  if (lineCount < 60) return 0;
  const lines = content.split("\n");
  const third = Math.floor(lines.length / 3);
  const part1 = lines.slice(0, third).join("\n");
  const part3 = lines.slice(lines.length - third).join("\n");
  const s1 = computeAIPercentage(part1, lang, third).score;
  const s3 = computeAIPercentage(part3, lang, third).score;
  const delta = s3 - s1;
  if (delta > 0.40) return Math.min(1.0, delta * 1.6);
  if (delta > 0.25) return delta * 1.2;
  if (delta < -0.35) return Math.min(0.55, Math.abs(delta) * 0.9);
  return 0;
}

// ── Supply-chain risk scanner ─────────────────────────────────────────────────

const RISKY_PACKAGES = new Set([
  "colors","faker","node-ipc","ua-parser-js","coa","rc",
  "event-stream","flatmap-stream","left-pad","is-promise",
  "eslint-scope","bootstrap-sass","getcookies","eslint-config-eslint",
]);

const TYPOSQUAT_PATTERNS: RegExp[] = [
  /\b(?:lodahs|loadsh|lodahsh|lodaash)\b/i,
  /\breact-(?:domc|domm|domx|doms)\b/i,
  /\bexpress-(?:js|node)\b/i,
  /\bmoment-(?:js|node)\b/i,
  /\bnpm-(?:safe|secure|verified)\b/i,
  /\baxios-(?:http|safe|node)\b/i,
];

const SUSPICIOUS_IMPORT_PATTERNS: RegExp[] = [
  /require\s*\(\s*["']\.\.\//,              // parent-dir traversal in require
  /import\s+\S+\s+from\s+["']\.\.\/\.\.\//,  // ../../ import
  /require\s*\(\s*["']https?:\/\//,         // remote require
  /eval\s*\(\s*require\s*\(/,               // eval(require(...))
];

export function scanSupplyChain(content: string): SupplyChainRisk {
  const importMatches = content.match(/(?:require|from)\s*\(\s*["']([^"'./][^"']*)["']\s*\)|from\s+["']([^"'./][^"']*)["']/g) ?? [];
  const risky: string[] = [];
  const typosquats: string[] = [];

  for (const m of importMatches) {
    const pkg = m.replace(/.*["']([^"']+)["'].*/, "$1").split("/")[0];
    if (RISKY_PACKAGES.has(pkg)) risky.push(pkg);
    for (const re of TYPOSQUAT_PATTERNS) if (re.test(pkg)) typosquats.push(pkg);
  }

  const suspicious: string[] = [];
  for (const re of SUSPICIOUS_IMPORT_PATTERNS) {
    if (re.test(content)) suspicious.push(re.source.slice(0, 40));
  }

  const score = Math.min(1, risky.length * 0.3 + typosquats.length * 0.4 + suspicious.length * 0.2);
  return { score, risky_imports: risky, typosquats, suspicious };
}

// ── Security fix suggestions ──────────────────────────────────────────────────

const FIX_MAP: Record<string, Omit<FixSuggestion, "vuln_id">> = {
  "sql-injection": {
    title: "Use parameterised queries",
    description: "Replace string-interpolated SQL with parameterised statements to prevent injection.",
    code_before: "db.query(`SELECT * FROM users WHERE id = ${userId}`)",
    code_after:  "db.query('SELECT * FROM users WHERE id = $1', [userId])",
    cwe: "CWE-89", effort: "low",
  },
  "xss": {
    title: "Sanitise HTML output",
    description: "Use a trusted sanitiser (DOMPurify, sanitize-html) before inserting user content into the DOM.",
    code_before: "element.innerHTML = userInput",
    code_after:  "element.innerHTML = DOMPurify.sanitize(userInput)",
    cwe: "CWE-79", effort: "low",
  },
  "hardcoded-secret": {
    title: "Move secret to environment variable",
    description: "Remove hardcoded credential and load it from process.env or a secrets manager.",
    code_before: 'const apiKey = "sk_live_abc123"',
    code_after:  "const apiKey = process.env.API_KEY",
    cwe: "CWE-798", effort: "low",
  },
  "command-injection": {
    title: "Use execFile instead of exec",
    description: "Pass arguments as an array to execFile/spawn to avoid shell interpolation.",
    code_before: "exec(`ls ${userPath}`)",
    code_after:  "execFile('ls', [userPath])",
    cwe: "CWE-78", effort: "low",
  },
  "path-traversal": {
    title: "Resolve and validate the canonical path",
    description: "Call path.resolve() then verify the result starts with the expected base directory.",
    code_before: "fs.readFile(req.params.file)",
    code_after:  "const safe = path.resolve(BASE, req.params.file);\nif (!safe.startsWith(BASE)) throw new Error('Forbidden');",
    cwe: "CWE-22", effort: "low",
  },
  "eval-exec": {
    title: "Eliminate eval / Function constructor",
    description: "Refactor to avoid dynamic code execution; use a data-driven approach instead.",
    cwe: "CWE-95", effort: "medium",
  },
  "weak-crypto": {
    title: "Upgrade to SHA-256 or stronger",
    description: "Replace MD5/SHA-1 with crypto.createHash('sha256') for integrity hashing.",
    code_before: "crypto.createHash('md5')",
    code_after:  "crypto.createHash('sha256')",
    cwe: "CWE-327", effort: "low",
  },
  "ssrf": {
    title: "Validate and allowlist outbound URLs",
    description: "Parse the URL and verify the hostname is in an explicit allowlist before fetching.",
    cwe: "CWE-918", effort: "medium",
  },
  "insecure-deserialization": {
    title: "Replace unsafe deserialise with JSON.parse",
    description: "Avoid node-serialize / unserialize; use JSON.parse with schema validation.",
    cwe: "CWE-502", effort: "medium",
  },
  "prototype-pollution": {
    title: "Validate merge keys before deep-merge",
    description: "Check that no key equals '__proto__', 'constructor', or 'prototype' before merging.",
    cwe: "CWE-1321", effort: "low",
  },
  "open-redirect": {
    title: "Validate redirect target against allowlist",
    description: "Compare parsed hostname against an explicit allowlist; reject or strip unknown hosts.",
    cwe: "CWE-601", effort: "low",
  },
  "weak-cors": {
    title: "Restrict CORS origin to known domains",
    description: "Replace wildcard Access-Control-Allow-Origin with an explicit allowlist.",
    code_before: 'res.setHeader("Access-Control-Allow-Origin", "*")',
    code_after:  'res.setHeader("Access-Control-Allow-Origin", "https://app.example.com")',
    cwe: "CWE-942", effort: "low",
  },
  "backdoor-detection": {
    title: "Remove suspicious conditional / exfiltration code",
    description: "Logic bomb or covert data exfiltration pattern detected. Review and remove immediately.",
    cwe: "CWE-506", effort: "high",
  },
  "watermark-detection": {
    title: "Strip invisible Unicode watermark characters",
    description: "Remove zero-width / soft-hyphen / word-joiner characters embedded as AI watermarks.",
    effort: "low",
  },
  "xxe": {
    title: "Disable external entity resolution",
    description: "Call setFeature(...) to disable DOCTYPE/external-entity processing before parsing untrusted XML.",
    code_before: "DocumentBuilderFactory.newInstance()",
    code_after:  'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
    cwe: "CWE-611", effort: "low",
  },
  "insecure-file-upload": {
    title: "Validate uploaded file type and size",
    description: "Check file extension and content-type against an allowlist, enforce a size limit, and store outside the web root with a generated filename.",
    cwe: "CWE-434", effort: "low",
  },
  "ldap-injection": {
    title: "Escape LDAP special characters or use parameterised filters",
    description: "Never concatenate user input into an LDAP filter string — escape special characters (*, (, ), \\, NUL) first.",
    cwe: "CWE-90", effort: "low",
  },
  "idor": {
    title: "Verify the caller owns the requested resource",
    description: "Check the authenticated user's ID against the resource's owner field before returning or modifying it.",
    code_before: "repo.findById(id)",
    code_after:  "repo.findById(id).filter(r -> r.getOwnerId().equals(currentUser.getId()))",
    cwe: "CWE-639", effort: "medium",
  },
  "php-missing-session-guard": {
    title: "Add a session/auth guard before this sensitive action",
    description: "Check for an authenticated session before performing a database write, unserialize(), or file write.",
    code_before: "mysqli_query($conn, \"DELETE FROM users WHERE id=$id\");",
    code_after:  "if (!isset($_SESSION['user_id'])) { header('Location: /login'); exit; }\nmysqli_query($conn, \"DELETE FROM users WHERE id=$id\");",
    cwe: "CWE-306", effort: "low",
  },
  "bola-missing-ownership-check": {
    title: "Verify the caller owns the requested resource before this Spring endpoint reads/writes it",
    description: "A @PathVariable/@RequestParam-sourced identifier reaches a repository/map lookup with no @PreAuthorize/@Secured/@RolesAllowed annotation and no .equals()/==/!= comparison against the authenticated principal anywhere in the method body.",
    code_before: "users.get(userId)",
    code_after:  "if (!userId.equals(authentication.getName())) return ResponseEntity.status(403).build();\nusers.get(userId)",
    cwe: "CWE-639", effort: "medium",
  },
  "nosql-injection": {
    title: "Validate query shape with a schema before passing to the driver",
    description: "Never pass a raw request body/params object as a MongoDB query — validate it against an expected schema first.",
    cwe: "CWE-943", effort: "medium",
  },
  "ssti": {
    title: "Use static templates, never user input as a template string",
    description: "Pass user data as template variables, not as the template source itself.",
    cwe: "CWE-1336", effort: "medium",
  },
  "xpath-injection": {
    title: "Use XPath variable binding instead of string concatenation",
    description: "Pass user input through an XPathVariableResolver rather than concatenating it into the expression string.",
    cwe: "CWE-643", effort: "medium",
  },
  "csrf-protection-disabled": {
    title: "Re-enable framework CSRF protection",
    description: "Remove the explicit disable and add per-request CSRF tokens for state-changing endpoints, exempting only true API-key-authenticated routes.",
    cwe: "CWE-352", effort: "medium",
  },
  // ── IaC security (Terraform + Kubernetes) ──────────────────────────────────
  "iac-s3-public-acl": {
    title: "Remove the public-read ACL",
    description: "Use a bucket policy with least privilege instead of a bucket-wide public ACL.",
    code_before: 'resource "aws_s3_bucket_acl" "x" {\n  acl = "public-read"\n}',
    code_after:  'resource "aws_s3_bucket_acl" "x" {\n  acl = "private"\n}',
    cwe: "CWE-284", effort: "low",
  },
  "iac-open-ingress": {
    title: "Restrict the ingress CIDR block",
    description: "Scope cidr_blocks to the specific IP ranges that need access instead of 0.0.0.0/0, or put the resource behind a load balancer/VPN.",
    code_before: 'ingress {\n  cidr_blocks = ["0.0.0.0/0"]\n}',
    code_after:  'ingress {\n  cidr_blocks = ["10.0.0.0/16"]\n}',
    cwe: "CWE-284", effort: "medium",
  },
  "iac-unencrypted-storage": {
    title: "Enable server-side encryption",
    description: "Add an aws_s3_bucket_server_side_encryption_configuration resource, or set storage_encrypted = true for a database instance.",
    code_before: 'resource "aws_db_instance" "x" {\n  # storage_encrypted not set\n}',
    code_after:  'resource "aws_db_instance" "x" {\n  storage_encrypted = true\n}',
    cwe: "CWE-311", effort: "low",
  },
  "iac-iam-wildcard": {
    title: "Scope the IAM policy to specific actions/resources",
    description: "Replace the wildcard Action/Resource with the exact set your workload needs (least privilege).",
    code_before: '{ "Effect": "Allow", "Action": "*", "Resource": "*" }',
    code_after:  '{ "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*" }',
    cwe: "CWE-732", effort: "medium",
  },
  "iac-public-db": {
    title: "Disable public accessibility on the database instance",
    description: "Set publicly_accessible = false and reach the database through a VPN/bastion/private subnet instead.",
    code_before: "publicly_accessible = true",
    code_after:  "publicly_accessible = false",
    cwe: "CWE-284", effort: "low",
  },
  "iac-privileged-container": {
    title: "Remove privileged mode",
    description: "Grant only the specific Linux capabilities the container actually needs instead of full privileged access.",
    code_before: "securityContext:\n  privileged: true",
    code_after:  "securityContext:\n  privileged: false\n  capabilities:\n    add: [\"NET_BIND_SERVICE\"]",
    cwe: "CWE-250", effort: "medium",
  },
  "iac-container-run-as-root": {
    title: "Run the container as a non-root user",
    description: "Set runAsNonRoot: true and a non-zero runAsUser in the pod/container security context.",
    code_before: "securityContext:\n  runAsUser: 0",
    code_after:  "securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
    cwe: "CWE-250", effort: "low",
  },
  "iac-host-namespace-access": {
    title: "Remove host namespace sharing",
    description: "Set hostNetwork/hostPID/hostIPC to false (or omit them) unless the workload has a specific, reviewed need for host-level access.",
    code_before: "hostNetwork: true",
    code_after:  "hostNetwork: false",
    cwe: "CWE-668", effort: "medium",
  },
  "iac-dangerous-capability": {
    title: "Drop the dangerous capability",
    description: "Remove ALL/SYS_ADMIN/NET_ADMIN/SYS_PTRACE/SYS_MODULE from the container's added capabilities unless specifically required and reviewed.",
    code_before: "capabilities:\n  add: [\"SYS_ADMIN\"]",
    code_after:  "capabilities:\n  drop: [\"ALL\"]",
    cwe: "CWE-250", effort: "medium",
  },
  "iac-unpinned-image-tag": {
    title: "Pin the image to a specific version or digest",
    description: "Replace the mutable :latest tag (or missing tag) with a specific version tag or, better, a content digest.",
    code_before: "image: nginx:latest",
    code_after:  "image: nginx:1.25.3@sha256:2ab30d...",
    cwe: "CWE-1104", effort: "low",
  },

  // ── Container security (Dockerfile + docker-compose.yml) ──────────────────
  "container-runs-as-root": {
    title: "Add a non-root USER instruction",
    description: "Set a USER instruction before the final CMD/ENTRYPOINT so the container doesn't run as root (UID 0) by default.",
    code_before: "FROM node:20-alpine\n# no USER instruction",
    code_after:  "FROM node:20-alpine\nRUN addgroup -S app && adduser -S app -G app\nUSER app",
    cwe: "CWE-250", effort: "low",
  },
  "container-unpinned-base-image": {
    title: "Pin the base image to a specific version or digest",
    description: "Replace the mutable :latest tag (or missing tag) with a specific version tag or, better, a content digest.",
    code_before: "FROM node:latest",
    code_after:  "FROM node:20.11.1-alpine@sha256:2ab30d...",
    cwe: "CWE-1104", effort: "low",
  },
  "container-add-remote-url": {
    title: "Replace ADD-from-URL with a verified download",
    description: "Use COPY with a locally-verified file, or fetch and checksum-verify the file in a RUN step, instead of ADD pulling directly from a remote URL with no integrity check.",
    code_before: "ADD https://example.com/install.sh /install.sh",
    code_after:  "RUN curl -fsSL https://example.com/install.sh -o /install.sh \\\n  && echo \"<expected-sha256>  /install.sh\" | sha256sum -c -",
    cwe: "CWE-494", effort: "low",
  },
  "container-piped-shell-exec": {
    title: "Verify remote scripts before executing them",
    description: "Download the script to a file, verify its checksum or signature, then execute it — don't pipe curl/wget output directly into a shell.",
    code_before: "RUN curl -fsSL https://example.com/install.sh | sh",
    code_after:  "RUN curl -fsSL https://example.com/install.sh -o install.sh \\\n  && echo \"<expected-sha256>  install.sh\" | sha256sum -c - \\\n  && sh install.sh",
    cwe: "CWE-494", effort: "medium",
  },
  "container-hardcoded-secret": {
    title: "Move the secret out of the Dockerfile",
    description: "Pass secrets via BuildKit's --secret mount (build time) or a runtime environment variable/orchestrator secret (run time) — never bake a credential into an ENV/ARG value, which persists in the image/build history.",
    code_before: "ENV API_KEY=sk_live_abc123",
    code_after:  "# docker build --secret id=api_key,src=./api_key.txt\nRUN --mount=type=secret,id=api_key cat /run/secrets/api_key",
    cwe: "CWE-798", effort: "medium",
  },
  "container-sensitive-file-copy": {
    title: "Don't copy credential/key files into the image",
    description: "Add the file to .dockerignore and pass its contents at runtime (an orchestrator secret, a mounted volume, or an environment variable) instead of baking it into a layer.",
    code_before: "COPY .env /app/.env",
    code_after:  "# .env added to .dockerignore; passed at runtime via --env-file or a secret",
    cwe: "CWE-538", effort: "low",
  },
  "container-exposed-sensitive-port": {
    title: "Remove the sensitive EXPOSE if unintentional",
    description: "Confirm this management port is meant to be reachable from outside the container before shipping it; if not, drop the EXPOSE instruction.",
    code_before: "EXPOSE 22",
    code_after:  "# SSH not exposed from the container",
    cwe: "CWE-668", effort: "low",
  },
  "container-compose-privileged": {
    title: "Remove privileged mode",
    description: "Grant only the specific Linux capabilities the service actually needs instead of full privileged access.",
    code_before: "services:\n  app:\n    privileged: true",
    code_after:  "services:\n  app:\n    cap_add: [\"NET_BIND_SERVICE\"]",
    cwe: "CWE-250", effort: "medium",
  },
  "container-compose-docker-socket-mount": {
    title: "Remove the Docker socket mount",
    description: "Avoid mounting /var/run/docker.sock into a container — it grants root-equivalent host control. If a service genuinely needs to manage containers, use a scoped Docker API proxy instead.",
    code_before: "volumes:\n  - /var/run/docker.sock:/var/run/docker.sock",
    code_after:  "# docker.sock not mounted; use a scoped Docker API proxy if container management is required",
    cwe: "CWE-269", effort: "high",
  },
  "container-compose-host-namespace": {
    title: "Remove host namespace sharing",
    description: "Set network_mode/pid/ipc to a non-host value (or omit them) unless the service has a specific, reviewed need for host-level access.",
    code_before: "network_mode: host",
    code_after:  "# default (bridge) network mode",
    cwe: "CWE-668", effort: "medium",
  },
  "container-compose-dangerous-capability": {
    title: "Drop the dangerous capability",
    description: "Remove ALL/SYS_ADMIN/NET_ADMIN/SYS_PTRACE/SYS_MODULE from the service's added capabilities unless specifically required and reviewed.",
    code_before: "cap_add:\n  - SYS_ADMIN",
    code_after:  "cap_drop:\n  - ALL",
    cwe: "CWE-250", effort: "medium",
  },
  "container-compose-hardcoded-secret": {
    title: "Move the secret out of the compose file",
    description: "Use env_file, Docker Compose secrets, or an external secret manager instead of a literal credential value under environment:.",
    code_before: "environment:\n  - DB_PASSWORD=hunter2",
    code_after:  "environment:\n  - DB_PASSWORD_FILE=/run/secrets/db_password\nsecrets:\n  - db_password",
    cwe: "CWE-798", effort: "low",
  },
  "container-compose-unpinned-image": {
    title: "Pin the image to a specific version or digest",
    description: "Replace the mutable :latest tag (or missing tag) with a specific version tag or, better, a content digest.",
    code_before: "image: postgres:latest",
    code_after:  "image: postgres:16.2@sha256:2ab30d...",
    cwe: "CWE-1104", effort: "low",
  },
};

export function getFixSuggestions(indicators: ScanIndicator[]): FixSuggestion[] {
  const seen = new Set<string>();
  const out: FixSuggestion[] = [];
  for (const ind of indicators) {
    if (seen.has(ind.id)) continue;
    const fix = FIX_MAP[ind.id];
    if (fix) { out.push({ vuln_id: ind.id, ...fix }); seen.add(ind.id); }
  }
  return out;
}

// CWE reference for vulnerability ids that don't already carry one via
// FIX_MAP (checked first, so the mapping isn't maintained in two places).
// Ids not in FIX_MAP fall back to the shared client-safe map (./cweMap)
// that the Risk Register page also reads from directly, so a finding's
// CWE classification is the same wherever it's shown.
function cweFor(id: string): string | undefined {
  return FIX_MAP[id]?.cwe ?? cweEntryFor(id)?.id;
}

// Base confidence per severity, bumped for named-taint matches (a variable
// actually traced from a request source to a sink, not just a same-line
// keyword co-occurrence) and for secrets (already passed the entropy/
// class-count filter in looksLikeRealSecret before reaching here).
function baseConfidence(ind: ScanIndicator): number {
  if (ind.id === "hardcoded-secret" || ind.id === "high-entropy-secret") return 92;
  const bySeverity: Record<string, number> = { critical: 85, high: 78, medium: 65, low: 50, info: 40 };
  let c = bySeverity[ind.severity] ?? 60;
  if (ind.detail && /named variable|tainted variable/i.test(ind.detail)) c = Math.min(98, c + 10);
  return c;
}

// Attaches cwe/confidence/codeCategory evidence to security-scan indicators
// (not AI-heuristic signals, which have their own explained_signals model).
// category marks the file as vendored/minified or a test file -- see
// analyzeFile's looksMinified/fileMeta.isTestFile checks -- so these findings
// are preserved as evidence without driving the file's own risk_score
// (calculateRisk excludes them). Secrets are always "application": a real
// leaked key in a vendor bundle or test fixture is still a real leaked key.
function attachEvidence(indicators: ScanIndicator[], category: "application" | "third_party" | "test_code"): ScanIndicator[] {
  return indicators.map(ind => ({
    ...ind,
    cwe:          ind.cwe ?? cweFor(ind.id),
    confidence:   ind.confidence ?? baseConfidence(ind),
    codeCategory: category !== "application" && ind.id !== "hardcoded-secret" && ind.id !== "high-entropy-secret"
      ? category
      : "application" as const,
  }));
}

// ── Line-level AI attribution ─────────────────────────────────────────────────

const LINE_AI_PATTERNS: RegExp[] = [
  /\bconst\s+(?:result|response|data)\s*=\s*await\s+/,
  /\b(?:validateInput|handleError|processData|sanitizeInput)\s*\(/,
  /\bif\s*\(\s*!(?:input|data|value|params|options|config|request|body)\s*\)/,
  /\breturn\s+\{\s*(?:success|data|error|result|message|status)\s*:/,
  /\bthrow\s+new\s+(?:Error|[A-Z]\w*Error)\s*\(\s*["'`]/,
  /^\s*\/\/\s*[A-Z][a-z].{15,}[.!]?\s*$/,  // sentence-style comment
  /\bconsole\.(?:log|error|warn)\s*\(\s*\{/,  // structured log
  /\bconst\s+\{\s*\w+(?:\s*,\s*\w+)+\s*\}\s*=/,  // destructuring
];

export function computeLineAttribution(content: string): number[] {
  const lines = content.split("\n");
  return lines.map(line => {
    if (line.trim().length < 5) return 0;
    let hits = 0;
    for (const re of LINE_AI_PATTERNS) if (re.test(line)) hits++;
    return Math.min(1, hits * 0.22);
  });
}

// ── Behavioral risk engine ────────────────────────────────────────────────────

export function analyzeBehavioralRisk(content: string): BehavioralRisk {
  const lines = content.split("\n");
  let logic_bombs = 0, exfil = 0, timing = 0, hidden = 0;

  for (const line of lines) {
    if (/new\s+Date\(\)\.\w+\(\)\s*[><=!]+\s*\d|Date\.now\(\)\s*[><=!]+\s*\d{10}/.test(line)) logic_bombs++;
    if (/(?:fetch|XMLHttpRequest|axios)\s*\(/.test(line) &&
        /\$\{(?:user|session|token|pass|secret|cookie|auth)\b/i.test(line)) exfil++;
    if (/navigator\.sendBeacon|new\s+Image\(\)/.test(line) && /\.src\s*=|sendBeacon/.test(line)) exfil++;
    if (/setTimeout\s*\([^,]+,\s*(?:\w+)\.length/.test(line)) timing++;
    if (/\\u00[0-9a-f]{2}\\u00[0-9a-f]{2}\\u00[0-9a-f]{2}/i.test(line)) hidden++;
    if (/(?:atob|btoa)\s*\(\s*["'][A-Za-z0-9+/=]{20,}/.test(line)) hidden++;
  }

  const score = Math.min(1,
    logic_bombs * 0.25 + exfil * 0.35 + timing * 0.20 + hidden * 0.20
  );
  return { score, logic_bombs, exfiltration_patterns: exfil, timing_channels: timing, hidden_channels: hidden };
}

// ── Provenance / temporal risk analyzer ──────────────────────────────────────

const AGENTIC_ARTIFACT_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\bgenerated\s+by\s+(?:claude|chatgpt|gpt-?[34]|copilot|cursor|gemini)\b/i,  label: "AI generator attribution comment" },
  { re: /\bai[_-]?generated\b/i,                                                     label: "ai-generated marker" },
  { re: /\bdo\s+not\s+(?:edit|modify)\s+(?:this\s+)?(?:file|code)\s+manually\b/i,   label: "do-not-edit directive" },
  { re: /\bauto[_-]?generated\s+by\s+\w/i,                                           label: "auto-generated header" },
  { re: /\bprompt[_-]?id\s*[:=]\s*["']?\w/i,                                         label: "prompt-id artifact" },
  { re: /\bsession[_-]?id\s*[:=]\s*["'][\w-]{20,}["']/i,                             label: "session-id artifact" },
  { re: /@generated\b/,                                                               label: "@generated JSDoc tag" },
  { re: /\/\/\s*@ai\b/i,                                                             label: "@ai annotation" },
];

export function analyzeProvenance(content: string, lang: string, lineCount: number): ProvenanceInfo {
  const artifacts: string[] = [];
  for (const { re, label } of AGENTIC_ARTIFACT_PATTERNS) {
    if (re.test(content)) artifacts.push(label);
  }

  // Temporal risk — rushed code markers
  const temporalMarkers = [
    /\bTODO\s*:/gi, /\bHACK\s*:/gi, /\bFIXME\s*:/gi,
    /\btemporary\b/gi, /\bquick[_\s-]?fix\b/gi, /\bworkaround\b/gi,
  ];
  let temporalHits = 0;
  for (const re of temporalMarkers) {
    const m = content.match(re);
    if (m) temporalHits += m.length;
  }
  const temporal_risk = Math.min(1, temporalHits / Math.max(10, lineCount / 20));

  const drift_score = sigStyleDrift(content, lang, lineCount);

  return { drift_score, temporal_risk, agentic_artifacts: artifacts };
}

// ── CI/CD trust scorer ────────────────────────────────────────────────────────

const DANGEROUS_CICD_PATTERNS: Array<{ re: RegExp; msg: string }> = [
  { re: /\$\{\{\s*github\.event\.(?:issue|comment|pull_request)\.body/,   msg: "Unsanitised PR/issue body in expression" },
  { re: /\$\{\{\s*github\.event\.(?:head_commit|commits)\[.+\]\.message/, msg: "Commit message injected into expression" },
  { re: /run:\s*\|\n[^#\n]*\$\{\{/m,                                      msg: "Expression inside run: shell step (injection risk)" },
  { re: /pull_request_target[\s\S]{0,200}actions\/checkout/,              msg: "pull_request_target with checkout (potential fork poisoning)" },
  { re: /curl\s+.*\|\s*(?:bash|sh)/,                                      msg: "curl-pipe-bash in CI step" },
  { re: /npm\s+install\s+--production\s+&&\s+npm\s+run/,                  msg: "Production install before audit in CI" },
  { re: /secrets\.\w+\s*==\s*["']/,                                       msg: "Secret compared in condition (leaks via timing)" },
];

export function scoreCICDTrust(filePaths: string[], contentMap: Map<string, string>): CICDTrustScore {
  const ciFiles = filePaths.filter(p =>
    /\.github[\\/]workflows[\\/]/.test(p) ||
    /Jenkinsfile/.test(p) ||
    /\.circleci[\\/]config/.test(p) ||
    /\.gitlab-ci\.yml$/.test(p)
  );

  if (ciFiles.length === 0) return { score: 1, findings: [], dangerous_steps: [], pinned_actions: true, secret_scanning: true };

  const findings: string[] = [];
  const dangerous_steps: string[] = [];
  let pinnedAll = true;
  let hasSecretScanning = false;

  for (const fp of ciFiles) {
    const c = contentMap.get(fp) ?? "";
    for (const { re, msg } of DANGEROUS_CICD_PATTERNS) {
      if (re.test(c)) { findings.push(`${fp}: ${msg}`); dangerous_steps.push(msg); }
    }
    // Check for pinned action versions (uses: owner/repo@sha or @vX.Y.Z)
    const uses = c.match(/uses:\s*\S+/g) ?? [];
    if (uses.some(u => /@[a-f0-9]{40}$/.test(u) === false && !/@v\d+\.\d+\.\d+$/.test(u) && /@/.test(u))) {
      pinnedAll = false;
    }
    if (/trivy|snyk|dependabot|secret.?scan|gitleaks|truffle/i.test(c)) hasSecretScanning = true;
  }

  const penaltyPerFinding = 0.15;
  const unpinnedPenalty   = pinnedAll ? 0 : 0.10;
  const noScanPenalty     = hasSecretScanning ? 0 : 0.08;
  const score = Math.max(0, 1 - findings.length * penaltyPerFinding - unpinnedPenalty - noScanPenalty);

  return { score, findings, dangerous_steps, pinned_actions: pinnedAll, secret_scanning: hasSecretScanning };
}

// ── AI tooling artifact detection ───────────────────────────────────────────
//
// Repo-level visibility into which AI coding agents/assistants are configured
// for this project. These config/rule files steer how an AI agent edits code
// (custom instructions, allowed commands, persona) — knowing they exist is
// part of "AI governance": a rule file with broad permissions or no review
// requirement is itself a provenance/risk signal, even before looking at code.
const AI_TOOLING_PATTERNS: Array<{ re: RegExp; tool: string; label: string }> = [
  { re: /(?:^|[\\/])\.cursorrules$/i,                 tool: "Cursor",        label: "Cursor AI agent rules file" },
  { re: /(?:^|[\\/])\.cursor[\\/]rules[\\/]/i,        tool: "Cursor",        label: "Cursor project rules directory" },
  { re: /(?:^|[\\/])\.windsurfrules$/i,               tool: "Windsurf",      label: "Windsurf AI agent rules file" },
  { re: /(?:^|[\\/])\.windsurf[\\/]/i,                tool: "Windsurf",      label: "Windsurf agent configuration directory" },
  { re: /(?:^|[\\/])CLAUDE\.md$/i,                    tool: "Claude Code",   label: "Claude Code project instructions" },
  { re: /(?:^|[\\/])\.claude[\\/]/i,                  tool: "Claude Code",   label: "Claude Code agent configuration directory" },
  { re: /(?:^|[\\/])\.github[\\/]copilot-instructions\.md$/i, tool: "GitHub Copilot", label: "Copilot custom instructions" },
  { re: /(?:^|[\\/])\.aider\.conf\.ya?ml$/i,          tool: "Aider",         label: "Aider configuration file" },
  { re: /(?:^|[\\/])\.aiderignore$/i,                 tool: "Aider",         label: "Aider ignore rules" },
  { re: /(?:^|[\\/])\.continue[\\/]/i,                tool: "Continue",      label: "Continue agent configuration directory" },
  { re: /(?:^|[\\/])\.codeium[\\/]/i,                 tool: "Codeium",       label: "Codeium agent configuration directory" },
  { re: /(?:^|[\\/])\.clinerules$/i,                  tool: "Cline",         label: "Cline AI agent rules file" },
  { re: /(?:^|[\\/])\.clinerules[\\/]/i,              tool: "Cline",         label: "Cline project rules directory" },
  { re: /(?:^|[\\/])\.devin[\\/]/i,                   tool: "Devin",         label: "Devin agent configuration directory" },
  { re: /(?:^|[\\/])AGENTS\.md$/i,                    tool: "AI Agents",     label: "Generic AI agent instructions (Codex/Agents-style)" },
];

// Path-based detection only fires when a PR touches a repo-level agent
// config file (.cursorrules, CLAUDE.md, etc.) -- those are typically added
// once, early in a project's life, and essentially never appear again in a
// normal feature PR. That made tool_evidence read 0% on almost every scan
// regardless of whether the changed code was actually AI-authored. This
// second pattern set catches attribution markers AI tools commonly leave
// directly in file content -- generated-by comments, co-authorship
// trailers copied into source files, etc. -- which real AI-assisted PRs
// carry far more often than a fresh agent-config file.
const AI_ATTRIBUTION_CONTENT_PATTERNS: Array<{ re: RegExp; tool: string; label: string }> = [
  { re: /co-authored-by:\s*claude/i,                        tool: "Claude Code",   label: "Claude co-authorship trailer in file" },
  { re: /generated\s+(?:with|by)\s+\[?claude\s*code\]?/i,    tool: "Claude Code",   label: "\"Generated with Claude Code\" marker" },
  { re: /co-authored-by:\s*(?:github\s*)?copilot/i,          tool: "GitHub Copilot", label: "Copilot co-authorship trailer in file" },
  { re: /generated\s+(?:with|by)\s+(?:github\s*)?copilot/i,  tool: "GitHub Copilot", label: "\"Generated by Copilot\" marker" },
  { re: /co-authored-by:\s*(?:chatgpt|openai\s*codex)/i,     tool: "ChatGPT",       label: "ChatGPT/Codex co-authorship trailer in file" },
  { re: /generated\s+(?:with|by)\s+(?:chatgpt|openai\s*codex)/i, tool: "ChatGPT",   label: "\"Generated by ChatGPT\" marker" },
  { re: /co-authored-by:\s*cursor/i,                         tool: "Cursor",        label: "Cursor co-authorship trailer in file" },
  { re: /generated\s+(?:with|by)\s+cursor/i,                 tool: "Cursor",        label: "\"Generated with Cursor\" marker" },
  { re: /co-authored-by:\s*(?:google\s*)?gemini/i,           tool: "Gemini",        label: "Gemini co-authorship trailer in file" },
  { re: /generated\s+(?:with|by)\s+(?:google\s*)?gemini/i,   tool: "Gemini",        label: "\"Generated by Gemini\" marker" },
  { re: /generated\s+(?:with|by)\s+windsurf/i,                tool: "Windsurf",     label: "\"Generated with Windsurf\" marker" },
  { re: /generated\s+(?:with|by)\s+devin/i,                   tool: "Devin",        label: "\"Generated by Devin\" marker" },
  { re: /this (?:file|code) was (?:generated|written) by (?:an? )?(?:ai|llm)\b/i, tool: "AI Agents", label: "Explicit AI-generated disclosure" },
];

/**
 * Scan repo file paths for AI coding-agent config/rule files (governance
 * visibility), and optionally file content for AI-attribution markers left
 * directly in source (generated-by comments, co-authorship trailers).
 * `fileContents` only needs to cover whatever subset of `filePaths` has
 * content available (e.g. scannable files) -- content-based detection is
 * simply skipped for paths without a matching entry.
 */
export function detectAIToolingArtifacts(
  filePaths: string[],
  fileContents?: Array<{ path: string; content: string }>,
): AIToolingArtifact[] {
  const out: AIToolingArtifact[] = [];
  for (const fp of filePaths) {
    for (const { re, tool, label } of AI_TOOLING_PATTERNS) {
      if (re.test(fp)) out.push({ tool, file: fp, label });
    }
  }
  if (fileContents) {
    for (const { path, content } of fileContents) {
      for (const { re, tool, label } of AI_ATTRIBUTION_CONTENT_PATTERNS) {
        if (re.test(content)) out.push({ tool, file: path, label });
      }
    }
  }
  return out;
}

// ── TrustLedger signature chain ───────────────────────────────────────────────

export interface TrustChain {
  genesis_hash:  string;
  file_hashes:   Array<{ path: string; hash: string }>;
  chain_hash:    string;  // rolling SHA-256 over all file hashes in order
  scan_seal:     string;  // final hash: chain_hash + scan_id + timestamp
  timestamp:     string;
}

export function buildTrustChain(files: FileAnalysis[], scan_id: string): TrustChain {
  const timestamp = new Date().toISOString();
  const genesis_hash = crypto.createHash("sha256").update("TrustLedger::GENESIS").digest("hex");
  let chain = genesis_hash;
  const file_hashes = files.map(f => {
    chain = crypto.createHash("sha256").update(`${chain}::${f.file_path}::${f.content_hash}`).digest("hex");
    return { path: f.file_path, hash: f.content_hash };
  });
  const chain_hash = chain;
  const scan_seal  = crypto.createHash("sha256").update(`${chain_hash}::${scan_id}::${timestamp}`).digest("hex");
  return { genesis_hash, file_hashes, chain_hash, scan_seal, timestamp };
}

// ── Explainability builder ────────────────────────────────────────────────────

function buildExplainedSignals(fired: SignalResult[], totalScore: number): ExplainedSignal[] {
  const tierOf = (id: string): "CORE" | "SECONDARY" | "STYLE" =>
    CORE_SIGNALS.has(id) ? "CORE" : SECONDARY_SIGNALS.has(id) ? "SECONDARY" : "STYLE";
  const totalLeak = fired.reduce((s, f) => s + f.leak * f.value, 0) || 1;
  return fired
    .filter(f => f.value > 0.05)
    .map(f => ({
      id:           f.id,
      label:        SIGNAL_LABELS[f.id] ?? f.id,
      tier:         tierOf(f.id),
      value:        f.value,
      contribution: Math.round((f.leak * f.value / totalLeak) * totalScore * 100) / 100,
      detail:       SIGNAL_DETAILS[f.id]?.(f.value) ?? `${Math.round(f.value * 100)}%`,
    }))
    .sort((a, b) => b.contribution - a.contribution);
}

// JS/TS AST-eligibility gate, shared by analyzeFile's own tsSourceFile
// parse AND runScan()'s cross-file Pass 1 pre-loop (which parses files
// before analyzeFile ever runs on them) -- a single source of truth so the
// two can never silently disagree on which files are eligible. Mirrors
// analyzeFile's own inline looksMinified/AST_TAINT_LINE_CAP logic exactly
// (see the comment at that call site for why: vendored/minified files give
// false signal, and a hard line cap bounds worst-case parse cost).
const AST_TAINT_LINE_CAP = 5000;
function shouldAstParse(content: string, filePath: string): boolean {
  const lang = detectLanguage(filePath);
  if (lang !== "javascript" && lang !== "typescript") return false;
  const lineCount = content.split("\n").length;
  if (lineCount > AST_TAINT_LINE_CAP) return false;
  const fileMeta = getFileTypeMeta(filePath);
  const avgLineLen = content.length / Math.max(1, lineCount);
  const looksMinified = fileMeta.isGenerated || (lineCount < 30 && avgLineLen > 400);
  return !looksMinified;
}

// Wraps astTaint.ts's real AST-based data-flow findings into the same
// ScanIndicator shape every regex detector produces. Runs ADDITIVELY
// alongside the existing JS/TS named-taint regex functions, not as a
// replacement -- see astTaint.ts's own docblock for why. Confidence fixed
// at 95: this is real structural evidence (an actual parsed source-to-sink
// path), not a proximity guess.
function findAstTaintFindings(
  content: string, filePath: string, sourceFile: ts.SourceFile,
  crossFilePropagating?: Map<string, { shapes: ParamShape[]; fromModule: string }>,
): ScanIndicator[] {
  return scanAstTaint(content, filePath, sourceFile, crossFilePropagating).map(f => ({
    id: f.id, label: astTaintLabel(f.id), severity: astTaintSeverity(f.id),
    line: f.line, detail: f.detail, confidence: 95,
  }));
}

// Same wrapper for astTaintPython.ts's Phase 2 engine -- see its own
// docblock for the tree-sitter/WASM warm-cache design.
function findAstTaintPythonFindings(content: string, filePath: string, rootNode: PySyntaxNode): ScanIndicator[] {
  return scanAstTaintPython(content, filePath, rootNode).map(f => ({
    id: f.id, label: astTaintPyLabel(f.id), severity: astTaintPySeverity(f.id),
    line: f.line, detail: f.detail, confidence: 95,
  }));
}

// Same wrapper for astTaintJava.ts's Phase 3 engine -- see its own
// docblock. No warm-cache concern here (java-parser is pure JS,
// synchronous, no WASM -- this mirrors astTaint.ts's simplicity, not
// astTaintPython.ts's).
function findAstTaintJavaFindings(content: string, filePath: string, cst: JavaCstNode): ScanIndicator[] {
  return scanAstTaintJava(content, filePath, cst).map(f => ({
    id: f.id, label: astTaintJavaLabel(f.id), severity: f.severityOverride ?? astTaintJavaSeverity(f.id),
    line: f.line, detail: f.detail, confidence: 95,
  }));
}

// Same wrapper for astTaintGo.ts's Phase 4 engine -- see its own docblock
// for the tree-sitter/WASM warm-cache design (same contract as Python's).
// The idorAuthCheckNearby callback reuses IDOR_AUTH_CHECK_NEARBY_RE against
// this file's raw lines -- "is there an ownership check nearby" is a
// line-window-context fact, not something the parser alone can answer, the
// same AST-taint + regex-context hybrid astTaintJava.ts's own BOLA detector uses.
function findAstTaintGoFindings(content: string, filePath: string, rootNode: GoSyntaxNode, lines: string[]): ScanIndicator[] {
  const idorAuthCheckNearby = (line: number) => {
    const windowStart = Math.max(0, line - 1 - 15);
    return lines.slice(windowStart, line).some(l => IDOR_AUTH_CHECK_NEARBY_RE.test(l));
  };
  return scanAstTaintGo(content, filePath, rootNode, idorAuthCheckNearby).map(f => ({
    id: f.id, label: astTaintGoLabel(f.id), severity: astTaintGoSeverity(f.id),
    line: f.line, detail: f.detail, confidence: 95,
  }));
}

// C# taint engine wrapper -- mirrors findAstTaintJavaFindings exactly
// (severityOverride only ever set by the BOLA detector, same as Java's).
function findAstTaintCSharpFindings(content: string, filePath: string, root: CSharpSyntaxNode): ScanIndicator[] {
  return scanAstTaintCSharp(content, filePath, root).map(f => ({
    id: f.id, label: astTaintCSharpLabel(f.id), severity: f.severityOverride ?? astTaintCSharpSeverity(f.id),
    line: f.line, detail: f.detail, confidence: 95,
  }));
}

// PHP taint engine wrapper -- mirrors findAstTaintCSharpFindings exactly.
function findAstTaintPHPFindings(content: string, filePath: string, root: PhpSyntaxNode): ScanIndicator[] {
  return scanAstTaintPHP(content, filePath, root).map(f => ({
    id: f.id, label: astTaintPHPLabel(f.id), severity: f.severityOverride ?? astTaintPHPSeverity(f.id),
    line: f.line, detail: f.detail, confidence: 95,
  }));
}

// ── analyzeFile ────────────────────────────────────────────────────────────────

export function analyzeFile(
  file_path: string, content: string, prPriorBias = 0,
  // Cross-file taint analysis (JS/TS only, Pass 2) -- both optional and
  // batch-scoped, computed by runScan() BEFORE this call, never persisted
  // as part of FileAnalysis's own return shape (see runScan() for why: it's
  // a batch-scoped intermediate, not a fact about this one file in
  // isolation). presparsedTs lets runScan() reuse the SAME ts.SourceFile it
  // already built during its own Pass-1 pre-loop, so a file with cross-file
  // imports still gets only ONE parse (shared) and TWO walks (Pass 1's
  // lightweight export-summary walk, this function's real walk), not two
  // parses.
  crossFilePropagating?: Map<string, { shapes: ParamShape[]; fromModule: string }>,
  presparsedTs?: ts.SourceFile,
  // Cross-file REACHABILITY (JS/TS only, one hop) -- same batch-scoped,
  // runScan()-computed, not-persisted-on-FileAnalysis shape as
  // crossFilePropagating above, just for a different question: names in
  // THIS file that are called from an already-reachable function in
  // ANOTHER file that imports them (see runScan()'s own comment for the
  // exact bridge logic). Union'd into buildCallGraph()'s own `reachable`
  // set below, never `entry_points` -- being called from elsewhere doesn't
  // make a function a network-facing entry point itself, just reachable.
  crossFileReachable?: Set<string>,
): FileAnalysis {
  const lang     = detectLanguage(file_path);
  const fileMeta = getFileTypeMeta(file_path);

  const emptySupplyChain  = (): SupplyChainRisk  => ({ score: 0, risky_imports: [], typosquats: [], suspicious: [] });
  const emptyBehavioral   = (): BehavioralRisk   => ({ score: 0, logic_bombs: 0, exfiltration_patterns: 0, timing_channels: 0, hidden_channels: 0 });
  const emptyProvenance   = (): ProvenanceInfo   => ({ drift_score: 0, temporal_risk: 0, agentic_artifacts: [] });

  const emptyResult = (): FileAnalysis => ({
    file_path, language: lang,
    ai_percentage: 0, risk_score: "LOW",
    risk_indicators: [], indicators: [],
    content_hash: crypto.createHash("sha256").update(content ?? "").digest("hex"),
    line_count: 0, scan_quality: 0,
    attribution: { model:"unknown", confidence:0, signals:[], breakdown:{"github-copilot":0,chatgpt:0,gemini:0,claude:0,codewhisperer:0,cursor:0,tabnine:0,human:0,unknown:1}, humanEvidence:0 },
    fix_suggestions: [], watermarks: [], supply_chain: emptySupplyChain(),
    behavioral_risk: emptyBehavioral(), provenance: emptyProvenance(),
    line_attribution: [], explained_signals: [],
    exploitability: null, compliance: null,
    ast_metrics: null, ast_risks: [], ssa_taint_paths: [], ml_score: null,
  });

  if (!content || content.trim().length < 50) return emptyResult();

  const lines     = content.split("\n");
  const lineCount = lines.length;
  const hash      = crypto.createHash("sha256").update(content).digest("hex");

  // Vendored/minified files (jQuery, etc.) aren't always caught by
  // getFileTypeMeta's filename check (e.g. "ace.js", "underscore-min.js" was
  // itself missed until the filename regex was broadened) — their giveaway
  // is structural: one or a handful of extremely long lines. Those lines
  // routinely contain substrings like ".innerHTML=" as part of the library's
  // OWN internal DOM code, which used to trip the XSS/SSRF/etc. detectors as
  // if it were attacker-tainted application code. Secrets detectors still
  // run regardless (a real leaked key in a vendor bundle is still real).
  const avgLineLen    = content.length / Math.max(1, lineCount);
  const looksMinified = fileMeta.isGenerated || (lineCount < 30 && avgLineLen > 400);
  // Same "preserve as evidence, exclude from risk escalation" treatment as
  // vendored code -- an eval() in a *.spec.ts test fixture isn't a production
  // RCE risk. Vendored takes priority in the rare case a file matches both.
  const fileCategory: "application" | "third_party" | "test_code" =
    looksMinified ? "third_party" : fileMeta.isTestFile ? "test_code" : "application";

  // Real AST parse (JS/TS only, Phase 1 of the multi-language OWASP hardening
  // effort -- see astTaint.ts). Skips vendored/generated files (already
  // excluded from risk_score) and a line-count cap, matching the "fall back
  // silently to regex-only, no regression" safeguard used elsewhere in this
  // function -- shouldAstParse is the single source of truth for that gate,
  // shared with runScan()'s cross-file Pass 1 pre-loop. presparsedTs (from
  // runScan(), when this file had cross-file imports to resolve) is reused
  // here rather than parsing again. Parsed at most once and reused below for
  // both the taint scan and the exploitability reachability resolver.
  const tsSourceFile: ts.SourceFile | null =
    presparsedTs ?? (shouldAstParse(content, file_path) ? parseSourceFile(content, file_path) : null);
  // Python AST parse (Phase 2 -- see astTaintPython.ts). isPythonParserReady()
  // gates on the WASM parser's async warm-up having completed already --
  // if not, this silently falls back to regex-only for this one file, same
  // "no regression" contract as the JS/TS cap above.
  const pyTree: PySyntaxNode | null =
    lang === "python" && !looksMinified && lineCount <= AST_TAINT_LINE_CAP && isPythonParserReady()
      ? parsePythonSourceSync(content, file_path)
      : null;
  // Java AST parse (Phase 3 -- see astTaintJava.ts). No readiness gate
  // needed, unlike pyTree above: java-parser is pure JS and synchronous,
  // there is nothing to warm up.
  const javaCst: JavaCstNode | null =
    lang === "java" && !looksMinified && lineCount <= AST_TAINT_LINE_CAP
      ? parseJavaSource(content)
      : null;
  // Go AST parse (Phase 4 -- see astTaintGo.ts). isGoParserReady() gates on
  // the WASM parser's async warm-up having completed already -- same
  // "no regression, fall back to regex-only" contract as pyTree above.
  const goTree: GoSyntaxNode | null =
    lang === "golang" && !looksMinified && lineCount <= AST_TAINT_LINE_CAP && isGoParserReady()
      ? parseGoSourceSync(content, file_path)
      : null;
  // C# AST parse -- see astTaintCSharp.ts. Same tree-sitter warm-cache
  // contract as pyTree/goTree above. lang === "csharp" covers BOTH .cs and
  // .cshtml (LANG_MAP maps both extensions the same way), but
  // tree-sitter-c_sharp parses real C# only -- Razor's mixed HTML/C#
  // syntax with @ directives isn't valid C#, so .cshtml is excluded by
  // extension here and stays on its existing regex coverage
  // (findNamedTaintXSSCSharp etc), matching this phase's own documented
  // scope.
  const csTree: CSharpSyntaxNode | null =
    lang === "csharp" && !file_path.toLowerCase().endsWith(".cshtml")
    && !looksMinified && lineCount <= AST_TAINT_LINE_CAP && isCSharpParserReady()
      ? parseCSharpSourceSync(content, file_path)
      : null;
  // PHP AST parse -- see astTaintPHP.ts. Same tree-sitter warm-cache
  // contract as pyTree/goTree/csTree above. This engine parses plain .php
  // only -- confirmed the bundled tree-sitter-php.wasm grammar during
  // probing, not a Laravel Blade/WordPress mixed-HTML variant, matching
  // this phase's own documented scope.
  const phpTree: PhpSyntaxNode | null =
    lang === "php" && !looksMinified && lineCount <= AST_TAINT_LINE_CAP && isPhpParserReady()
      ? parsePhpSourceSync(content, file_path)
      : null;

  const secretIndicators: ScanIndicator[] = [
    ...findSecrets(lines, file_path),
    ...findHighEntropySecrets(lines, file_path),
  ];

  // Vulnerability detectors now always run, even on vendored/minified files —
  // attachEvidence() below tags the resulting findings as "third_party"
  // instead of silently dropping them, so a real issue inside a vendored
  // library is still visible (just not risk-scored as if it were this repo's
  // own code). This replaces the earlier blunt on/off gate.
  const vulnIndicatorsRaw: ScanIndicator[] = [
    ...findXSS(lines),
    ...findInsecureDeserialization(lines),
    ...findInsecureDeserializationGoDecoder(lines),
    ...findInsecureDeserializationCSharp(lines),
    ...findInsecureDeserializationCSharpJsonNet(lines),
    ...findNamedTaintDeserializationPHP(lines),
    ...findDeserializationPHPWrapped(lines),
    ...findPHPPharDeserialization(lines),
    ...findWeakCrypto(lines),
    ...findPIIInLogs(lines),
    ...findMassAssignment(lines),
    ...findMassAssignmentCSharp(lines),
    ...findMassAssignmentPHPLoop(lines),
    ...findSQLInjection(lines),
    ...findSQLInjectionTainted(lines),
    ...findSQLInjectionPHPInterpolated(lines),
    ...findSQLInjectionPHPMultilineBuild(lines),
    ...findSQLInjectionJavaTainted(lines),
    ...findSQLInjectionGoSprintf(lines),
    ...findSQLInjectionCSharpTainted(lines),
    ...findEvalExec(lines),
    ...findJwtBypass(lines),
    ...findWeakSigningSecret(lines),
    ...findWeakSigningSecretPHPHmac(lines),
    ...findWeakSigningSecretSplitLine(lines),
    ...findCommandInjection(lines),
    ...findNamedTaintCommandInjectionPHP(lines),
    ...findNamedTaintCommandInjectionPython(lines),
    ...findNamedTaintCommandInjectionJS(lines),
    ...findNamedTaintCommandInjectionGo(lines),
    ...findCommandInjectionTainted(lines),
    ...findSSRF(lines),
    ...findSSRFTainted(lines),
    ...findPathTraversal(lines),
    ...findNamedTaintPathTraversalJS(lines),
    ...findNamedTaintPathTraversalGo(lines),
    ...findNamedTaintPathTraversalCSharp(lines),
    ...findNamedTaintPathTraversalPHP(lines),
    ...findPathTraversalTainted(lines),
    ...findZipSlip(lines),
    ...findPHPFileInclusion(lines),
    ...findPrototypePollution(lines),
    ...findInsecureRandomness(lines),
    ...findInsecureRandomnessGoFunc(lines),
    ...findInsecureRandomnessCSharpFunc(lines),
    ...findReDoS(lines),
    ...findOpenRedirect(lines),
    ...findNamedTaintOpenRedirectJS(lines),
    ...findNamedTaintOpenRedirectGo(lines),
    ...findTimingAttack(lines),
    ...findPlaintextPasswordStorage(lines),
    ...findPlaintextPasswordStorageCSharpCall(lines),
    ...findSSTI(lines),
    ...findHeaderInjection(lines),
    ...findWeakCORS(lines),
    ...findMissingSecurityHeaders(lines),
    ...findDebugModeEnabled(lines),
    ...findIDOR(lines),
    ...findIDORJava(lines),
    ...findNamedTaintIDOR(lines),
    ...findNamedTaintIDORGo(lines),
    ...findNamedTaintIDORCSharp(lines),
    ...findNamedTaintIDORPHP(lines),
    ...findAuthenticatedIdentityIgnored(lines),
    ...findPHPMissingSessionGuard(lines),
    ...findSensitiveDataInURL(lines),
    ...findNamedTaintSSRF(lines),
    ...findNamedTaintSSRFPHP(lines),
    ...findSSRFGoNewRequest(lines),
    ...findNamedTaintSSRFCSharp(lines),
    ...findSSRFCSharpNewRequest(lines),
    ...findNamedTaintXSS(lines),
    ...findNamedTaintXSSCSharp(lines),
    ...findNamedTaintXSSPHP(lines),
    ...findNamedTaintReflectedXSS(lines),
    ...findReflectedXSSTainted(lines),
    ...findNoSQLInjection(lines),
    ...findVerboseErrors(lines),
    ...findGraphQLInjection(lines),
    ...findGraphQLIntrospectionEnabled(lines),
    ...findXXE(lines),
    ...findXXECSharp(lines),
    ...findLDAPInjection(lines),
    ...findXPathInjection(lines),
    ...findCSRFDisabled(lines),
    ...findInsecureFileUpload(lines),
    ...findInsecureFileUploadCSharp(lines),
    ...findTOCTOU(lines),
    ...findCookieInsecurity(lines),
    ...findCookieInsecurityOtherLangs(lines),
    ...(tsSourceFile ? findAstTaintFindings(content, file_path, tsSourceFile, crossFilePropagating) : []),
    ...(pyTree ? findAstTaintPythonFindings(content, file_path, pyTree) : []),
    ...(javaCst ? findAstTaintJavaFindings(content, file_path, javaCst) : []),
    ...(goTree ? findAstTaintGoFindings(content, file_path, goTree, lines) : []),
    ...(csTree ? findAstTaintCSharpFindings(content, file_path, csTree) : []),
    ...(phpTree ? findAstTaintPHPFindings(content, file_path, phpTree) : []),
  ];
  const vulnIndicators = attachEvidence(vulnIndicatorsRaw, fileCategory);

  // Security scan — all detectors
  const rawIndicators: ScanIndicator[] = [
    ...attachEvidence(secretIndicators, fileCategory),
    ...vulnIndicators,
    // Pluggable detectors registered via detectorRegistry.register() -- see
    // detectorRegistry.ts. Empty by default; this is the on-ramp for new
    // detectors that don't require editing this function. Wrapped in
    // attachEvidence so registry detectors get the same cwe/confidence
    // defaults and third-party/vendored-file exclusion as every other
    // security detector below.
    ...attachEvidence(detectorRegistry.runAll({ content, lines, file_path, language: lang }, "security"), fileCategory),
  ];

  // Dedup by id+line, preserving which detector(s) independently flagged the
  // same finding (spec: "multiple regexes may identify the same
  // vulnerability... deduplicate... store primaryDetector/supportingDetectors").
  const byKey = new Map<string, ScanIndicator>();
  for (const i of rawIndicators) {
    const k = `${i.id}:${i.line ?? ""}`;
    const existing = byKey.get(k);
    if (!existing) { byKey.set(k, i); continue; }
    if (i.label !== existing.label) {
      existing.supportingDetectors = existing.supportingDetectors ?? [];
      if (!existing.supportingDetectors.includes(i.label)) existing.supportingDetectors.push(i.label);
    }
  }
  const indicators = Array.from(byKey.values());

  // AI detection — skipped for config/generated files
  let ai_percentage    = 0;
  let scan_quality     = 0;
  let explained_signals: ExplainedSignal[] = [];
  let firedSignals: SignalResult[] = [];

  // Model attribution (computed early so its human-evidence signal can
  // dampen the structural ai_percentage score below).
  const attribution = attributeCode(content, lang);

  if (!fileMeta.skipAI) {
    // Compute style drift (recursive call to computeAIPercentage — safe because drift score is 0 inside)
    const driftScore = sigStyleDrift(content, lang, lineCount);

    const { score, fired, applicableCount } = computeAIPercentage(
      content, lang, lineCount,
      (fileMeta.aiPriorBias ?? 0) + prPriorBias,  // file prior + PR-level prior
      attribution.humanEvidence,
    );

    // Inject style drift into fired list if it fired
    if (driftScore > 0.05) {
      fired.push({ id: "style-drift", value: driftScore, leak: 0.65 });
    }

    ai_percentage = score;
    scan_quality  = Math.min(1, applicableCount / 8);
    firedSignals  = fired;
    explained_signals = buildExplainedSignals(fired, score);

    // Emit AI signals as indicators
    for (const sig of fired) {
      if (sig.value > 0.15) {
        indicators.push({
          id:       sig.id,
          label:    SIGNAL_LABELS[sig.id] ?? sig.id,
          severity: sig.value > 0.70 ? "low" : "info",
          detail:   SIGNAL_DETAILS[sig.id]?.(sig.value) ?? `${Math.round(sig.value*100)}%`,
        });
      }
    }
  }

  const risk_score      = calculateRisk(indicators, ai_percentage);
  const risk_indicators = Array.from(new Set(indicators.map(i => i.id)));

  // Model attribution
  if (attribution.confidence >= 0.40 && attribution.model !== "human" && attribution.model !== "unknown") {
    const label =
      attribution.model === "github-copilot" ? "GitHub Copilot" :
      attribution.model.charAt(0).toUpperCase() + attribution.model.slice(1);
    indicators.push({
      id: "ai-model-attribution", label: `${label} attribution`, severity: "info",
      detail: `${Math.round(attribution.confidence * 100)}% confidence — ${attribution.signals[0] ?? "AI generation detected"}`,
    });
  }

  // v6 extended analysis
  const watermarks      = findWatermarks(content);
  const supply_chain    = scanSupplyChain(content);
  const behavioral_risk = analyzeBehavioralRisk(content);
  const provenance      = analyzeProvenance(content, lang, lineCount);
  const line_attribution = computeLineAttribution(content);
  const fix_suggestions  = getFixSuggestions(indicators);

  // Backdoor / watermark indicators → elevated severity
  if (watermarks.length > 0 && !indicators.some(i => i.id === "watermark-detection")) {
    indicators.push({ id: "watermark-detection", label: "AI Watermark Detected", severity: "high",
      detail: `${watermarks.length} invisible Unicode watermark character(s) found` });
  }
  if (behavioral_risk.score > 0.5 && !indicators.some(i => i.id === "behavioral-risk")) {
    indicators.push({ id: "behavioral-risk", label: "Behavioral Risk Pattern", severity: "high",
      detail: `Behavioral risk score ${Math.round(behavioral_risk.score * 100)}% — suspicious code patterns` });
  }
  if (supply_chain.score > 0.4 && !indicators.some(i => i.id === "supply-chain-risk")) {
    indicators.push({ id: "supply-chain-risk", label: "Supply Chain Risk", severity: "medium",
      detail: `${supply_chain.risky_imports.length} risky, ${supply_chain.typosquats.length} typosquat imports` });
  }

  // Suppress unused variable warning for firedSignals
  void firedSignals;

  // Exploitability scoring (CVSS-lite with call-graph reachability).
  // resolveContainingFunction uses the real parsed AST (JS/TS only, when
  // available) to find which function a given indicator's line actually
  // falls inside, per-indicator -- see scoreExploitability's own docblock
  // for why a single containingFunction string could never have been
  // correct even with a real (non-"unknown") value plugged in.
  const callGraph   = !fileMeta.skipAI ? buildCallGraph(content) : null;
  // Cross-file reachability bridge (Decision 1): union in names this file
  // exports that runScan() already determined are called from a reachable
  // function in another JS/TS file -- see this function's own
  // crossFileReachable param docblock for why `.reachable` only, never
  // `.entry_points`.
  if (callGraph && crossFileReachable) {
    for (const name of crossFileReachable) callGraph.reachable.add(name);
  }
  const resolveContainingFunction = (line: number): string => {
    if (tsSourceFile) {
      const pos = tsSourceFile.getPositionOfLineAndCharacter(Math.max(0, line - 1), 0);
      return findEnclosingFunctionName(findNodeAtPosition(tsSourceFile, pos));
    }
    if (pyTree) {
      return findEnclosingFunctionNamePy(findNodeAtRowPy(pyTree, Math.max(0, line - 1)));
    }
    if (goTree) {
      return findEnclosingFunctionNameGo(findNodeAtRowGo(goTree, Math.max(0, line - 1)));
    }
    if (javaCst) {
      return findEnclosingFunctionNameJava(javaCst, Math.max(0, line - 1));
    }
    if (csTree) {
      return findEnclosingFunctionNameCSharp(findNodeAtRowCSharp(csTree, Math.max(0, line - 1)));
    }
    if (phpTree) {
      return findEnclosingFunctionNamePHP(findNodeAtRowPHP(phpTree, Math.max(0, line - 1)));
    }
    return "unknown";
  };
  const exploitability = indicators.filter(i => !AI_SIGNAL_IDS.has(i.id)).length > 0
    ? scoreExploitability(indicators, content, callGraph, resolveContainingFunction)
    : null;

  // Merge per-instance reachability back onto `indicators` -- the same array
  // object returned below as FileAnalysis.indicators, which every downstream
  // consumer (the persistence sites, SARIF, the PR page) reads. Matched by
  // the same `${id}:${line ?? ""}` key the dedup pass above already uses,
  // NOT by array position or vuln_id alone: scoreExploitability() internally
  // filters out AI-signal ids and then sorts its output by
  // exploitability_score descending before returning, so `scores[]` has
  // neither the same length nor the same order as `indicators`, and the same
  // rule id can legitimately fire at two different lines with two different
  // reachability outcomes.
  if (exploitability) {
    const scoreByKey = new Map(exploitability.scores.map(s => [`${s.vuln_id}:${s.line ?? ""}`, s]));
    for (const ind of indicators) {
      const score = scoreByKey.get(`${ind.id}:${ind.line ?? ""}`);
      if (!score) continue; // AI-signal ids are never scored -- expected, leave untouched
      ind.reachability = score.reachability;
      ind.exploitability_score = score.exploitability_score;
      ind.remediation_urgency = score.remediation_urgency;
    }
  }

  // Compliance evaluation
  const compliance = evaluateCompliance(content, file_path);

  // ── v7: Structural AST analysis ────────────────────────────────────────────
  const astResult   = parseAst(content, lang);
  const ast_metrics = astResult.metrics;
  const ast_risks   = astResult.risks;

  // SSA taint analysis on top-N most complex functions (capped for performance)
  const ssa_taint_paths: TaintPath[] = [];
  if (indicators.filter(i => !AI_SIGNAL_IDS.has(i.id)).length > 0) {
    const topFuncs = [...astResult.functions]
      .sort((a, b) => b.complexity - a.complexity)
      .slice(0, 3);
    for (const fn of topFuncs) {
      const bodyLines = extractFunctionBody(content, fn.line, fn.endLine);
      const ssaResult = buildSSA(bodyLines, fn.line);
      for (const tp of ssaResult.taintPaths) ssa_taint_paths.push(tp);
    }
  }

  // ML classifier — independent probability estimate
  const ml_score = !fileMeta.skipAI
    ? classifyCode(content, ast_metrics, ai_percentage)
    : null;

  return {
    file_path, language: lang, ai_percentage, risk_score, risk_indicators, indicators,
    content_hash: hash, line_count: lineCount, attribution, scan_quality,
    fix_suggestions, watermarks, supply_chain, behavioral_risk, provenance,
    line_attribution, explained_signals, exploitability, compliance,
    ast_metrics, ast_risks, ssa_taint_paths, ml_score,
  };
}

// ── runScan ────────────────────────────────────────────────────────────────────

// All AI signal indicator IDs — used to separate security findings from AI signals in summaries.
export const AI_SIGNAL_IDS = new Set([
  "comment-phrasing","language-specific","test-structure","doc-coverage",
  "lexical-diversity","error-uniformity","variable-vocabulary","sentence-identifiers",
  "async-consistency","functional-preference","function-size","nesting-depth",
  "structural-repetition","guard-clause-density","magic-number-absence","boilerplate",
  "template-literals","method-chain-density","naming-consistency","import-organization",
  "dead-code-absence","comment-density","async-try-catch","immutable-preference",
  "exhaustive-switches","type-guards","structured-logging","cyclomatic-uniformity",
  "return-types","verb-prefix","destructuring-density","exception-specificity",
  "line-length","default-params","arrow-consistency","ai-model-attribution",
  "ngram-fingerprint","structural-clones","error-message-phrasing",
  "identifier-length","blank-line-regularity","token-frequency",
  "prompt-leakage","style-drift","watermark-detection","backdoor-detection",
  "hallucinated-api","copy-paste-pattern",
  // Added: these 3 were moved from CORE into SECONDARY (see the comment
  // above SECONDARY_SIGNALS) without also being added here, so they were
  // silently counted as security findings in total_security_findings/
  // critical_count and the exploitability/reachability scorers.
  // ai-blast-radius is injected post-analyzeFile at the batch level and was
  // never a CWE finding either -- same gap, same fix.
  "jsdoc-completeness","zero-debug-artifacts","import-exhaustiveness","ai-blast-radius",
]);

export interface ScanSummary {
  total_security_findings:  number;
  critical_count:           number;
  high_count:               number;
  medium_count:             number;
  low_count:                number;
  top_vuln_types:           string[];  // top 3 most frequent security vuln IDs
  ai_high_confidence_files: number;   // files with scan_quality >= 0.70
  requires_immediate_action: boolean; // any critical or high findings
}

export interface PRMetadata {
  additions:     number;   // total lines added in this PR
  deletions:     number;   // total lines deleted
  commits:       number;   // number of commits in the PR
  changed_files: number;   // number of files changed
  created_at?:   string;   // ISO timestamp when PR was created
  head_pushed_at?: string; // ISO timestamp of most recent push to head branch
  pr_author?:    string;   // GitHub login of PR author
}

export interface ScanInput {
  repo:               string;
  pr_number:          number;
  commit_sha:         string;
  branch?:            string;
  files:              Array<{ path: string; content: string }>;
  all_file_paths?:    string[];                // ALL paths in the PR (not just scannable ones) — for tooling detection
  prev_hashes?:       Record<string, string>;  // incremental: path → previous content_hash; skip if unchanged
  git_log?:           string;                  // optional: git log --format="%H|%an|%ae|%at|%G?|%s" output
  pr_metadata?:       PRMetadata;              // PR behavior signals (LOC, commits, timing)
  developer_baseline?: DeveloperBaseline;      // author's historical PR patterns (Phase 3)
}

// ── AI Likelihood Classification ────────────────────────────────────────────

export type AILikelihoodBand =
  | "Likely Human"
  | "Human with Tool Assistance"
  | "Mixed Authorship"
  | "Likely AI-Assisted"
  | "Strong AI Evidence";

export function classifyAILikelihood(score: number): AILikelihoodBand {
  if (score <= 0.20) return "Likely Human";
  if (score <= 0.40) return "Human with Tool Assistance";
  if (score <= 0.60) return "Mixed Authorship";
  if (score <= 0.80) return "Likely AI-Assisted";
  return "Strong AI Evidence";
}

// ── Evidence Breakdown ───────────────────────────────────────────────────────

export interface DeveloperBaseline {
  pr_count:          number;
  avg_loc_per_pr:    number;
  avg_commits_per_pr: number;
  avg_files_per_pr:  number;
  avg_ai_percentage: number;
}

export interface BaselineDeviation {
  score:            number;   // 0–1: how far this PR deviates from author's norm
  loc_deviation:    number;   // multiplier: 3x = 3× their usual LOC
  commit_deviation: number;   // multiplier: 0.2x = far fewer commits than usual
  reasons:          string[];
}

// Confidence multiplier by sample size. A hard "need 3+ PRs" cliff meant
// baseline_evidence stayed at exactly 0 for every author until their 4th
// scan (the baseline is fetched *before* this PR is added, so PR #3 still
// sees pr_count=2) -- in practice this made the signal look permanently
// broken for any org without long same-author scan history. A single prior
// PR is weak evidence but not zero evidence, so scale in gradually instead
// of gating outright; full confidence still requires the same 3-PR bar.
function baselineConfidence(prCount: number): number {
  if (prCount <= 0) return 0;
  if (prCount === 1) return 0.35;
  if (prCount === 2) return 0.65;
  return 1;
}

export function scoreBaselineDeviation(
  meta: PRMetadata,
  baseline: DeveloperBaseline,
): BaselineDeviation {
  const reasons: string[] = [];
  let score = 0;

  const confidence = baselineConfidence(baseline.pr_count);
  if (confidence === 0) {
    return { score: 0, loc_deviation: 1, commit_deviation: 1, reasons: [] };
  }

  // LOC deviation
  const locDev = baseline.avg_loc_per_pr > 0
    ? meta.additions / baseline.avg_loc_per_pr
    : 1;
  if (locDev > 5) {
    score += 0.35;
    reasons.push(`${Math.round(locDev)}× more LOC than their usual PRs (avg: ${Math.round(baseline.avg_loc_per_pr)} lines)`);
  } else if (locDev > 3) {
    score += 0.20;
    reasons.push(`${Math.round(locDev)}× more LOC than their usual PRs`);
  } else if (locDev > 2) {
    score += 0.10;
  }

  // Commit count deviation (far fewer commits than usual = AI generated in one go)
  const commitDev = baseline.avg_commits_per_pr > 0
    ? meta.commits / baseline.avg_commits_per_pr
    : 1;
  if (commitDev < 0.3 && meta.additions > 100) {
    score += 0.30;
    reasons.push(`Only ${meta.commits} commit(s) vs their usual ${Math.round(baseline.avg_commits_per_pr)} — unusually low for this author`);
  } else if (commitDev < 0.5) {
    score += 0.15;
    reasons.push(`Fewer commits than this author's typical pattern`);
  }

  // Files changed deviation
  const filesDev = baseline.avg_files_per_pr > 0
    ? meta.changed_files / baseline.avg_files_per_pr
    : 1;
  if (filesDev > 4 && meta.commits <= 2) {
    score += 0.20;
    reasons.push(`${meta.changed_files} files in ${meta.commits} commit(s) — this author usually touches ${Math.round(baseline.avg_files_per_pr)} files`);
  }

  if (confidence < 1 && reasons.length > 0) {
    reasons.push(`(limited confidence — only ${baseline.pr_count} prior PR${baseline.pr_count === 1 ? "" : "s"} on file for this author)`);
  }

  return {
    score:            Math.min(1, score * confidence),
    loc_deviation:    locDev,
    commit_deviation: commitDev,
    reasons,
  };
}

export interface EvidenceBreakdown {
  code_evidence:      number;  // 0–1: style/structure/AI-pattern signals
  pr_evidence:        number;  // 0–1: PR behavior (LOC, commits, timing)
  git_evidence:       number;  // 0–1: git provenance (commit velocity, history)
  tool_evidence:      number;  // 0–1: explicit tool artifacts (Cursor, Copilot, etc.)
  baseline_evidence:  number;  // 0–1: deviation from developer's historical patterns
  combined:           number;  // 0–1: weighted combination
  likelihood:         AILikelihoodBand;
  boosts:             string[]; // human-readable reasons for score boosts
  baseline_deviation?: BaselineDeviation; // developer baseline comparison detail
}

// ── PR Behavior Scoring ──────────────────────────────────────────────────────
// Weights: PR Behavior 25%, Git Provenance 30%, Code Structure 25%,
//          Tool Evidence 15%, Attestation/Baseline 5%

const GENERATED_PATH_RE = /(?:^|\/)(?:dist|vendor|generated|proto|protobuf|openapi|\.next|node_modules|__generated__|migrations)\//;

function scorePRBehavior(meta: PRMetadata, totalFileLines: number): {
  score:  number;
  boosts: string[];
} {
  const boosts: string[] = [];
  let score = 0;

  const linesAdded  = meta.additions;
  const commitCount = Math.max(1, meta.commits);
  const fileCount   = Math.max(1, meta.changed_files);
  const locPerCommit = linesAdded / commitCount;

  // Signal 1: LOC vs commit count (very high weight)
  // >500 LOC in a single commit is a strong AI indicator
  if (locPerCommit > 1000) {
    score += 0.30;
    boosts.push(`${linesAdded} lines added in ${commitCount} commit(s) — ${Math.round(locPerCommit)} LOC/commit`);
  } else if (locPerCommit > 500) {
    score += 0.20;
    boosts.push(`High LOC/commit ratio: ${Math.round(locPerCommit)} lines per commit`);
  } else if (locPerCommit > 200) {
    score += 0.10;
  }

  // Signal 2: Single commit for entire feature
  if (commitCount === 1 && linesAdded > 300) {
    score += 0.15;
    boosts.push(`Entire feature in 1 commit (${linesAdded} lines)`);
  } else if (commitCount <= 2 && linesAdded > 500) {
    score += 0.10;
    boosts.push(`${linesAdded} lines in only ${commitCount} commits`);
  }

  // Signal 3: Files changed vs commits ratio
  const filesPerCommit = fileCount / commitCount;
  if (filesPerCommit > 8 && commitCount <= 2) {
    score += 0.10;
    boosts.push(`${fileCount} files changed in ${commitCount} commit(s)`);
  } else if (filesPerCommit > 5) {
    score += 0.05;
  }

  // Signal 4: Branch-to-PR timing (if available)
  if (meta.created_at && meta.head_pushed_at) {
    const prCreated   = new Date(meta.created_at).getTime();
    const branchPush  = new Date(meta.head_pushed_at).getTime();
    const minutesDiff = Math.abs(prCreated - branchPush) / 60000;
    if (minutesDiff < 10 && linesAdded > 200) {
      score += 0.20;
      boosts.push(`PR opened ${Math.round(minutesDiff)} min after push with ${linesAdded} lines`);
    } else if (minutesDiff < 30 && linesAdded > 500) {
      score += 0.10;
      boosts.push(`${linesAdded} lines pushed and PR opened within ${Math.round(minutesDiff)} min`);
    }
  }

  // Exemption: reduce score if many files look generated
  // (this would need file paths — applied in runScan)

  return { score: Math.min(1, score), boosts };
}

export interface CrossFileConsistency {
  dominant_model:    string;           // most common attributed AI model
  style_agreement:   number;           // 0–1: how similar AI scores are across files
  outlier_files:     string[];         // files whose AI score deviates >25pp from mean
  mixed_languages:   boolean;          // PR spans multiple languages
}

export interface ScanOutput {
  scan_id:              string;
  repo:                 string;
  pr_number:            number;
  commit_sha:           string;
  overall_risk:         RiskLevel;
  total_ai_percentage:  number;
  cross_file_ai_boost:  boolean;
  mixed_authorship:     boolean;
  scan_quality:         number;
  ai_distribution: { p10: number; p25: number; p50: number; p75: number; p90: number };
  files:                FileAnalysis[];
  duration_ms:          number;
  scan_summary:         ScanSummary;
  cicd_trust:           CICDTrustScore | null;
  trust_chain:          TrustChain;
  cross_file_consistency: CrossFileConsistency;
  compliance:           ComplianceReport;
  skipped_unchanged:    number;  // incremental scan: files skipped because hash unchanged
  semantic_graph:       SemanticGraph | null;
  git_provenance:       GitProvenanceSummary | null;
  ai_tooling:           AIToolingArtifact[];
  evidence_breakdown:   EvidenceBreakdown;  // multi-signal evidence buckets
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = (p / 100) * (sorted.length - 1);
  const lo  = Math.floor(idx);
  const hi  = Math.ceil(idx);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

export function runScan(input: ScanInput): ScanOutput {
  const start = Date.now();

  // Incremental scanning: skip files whose content hash hasn't changed
  let skipped_unchanged = 0;
  const prev = input.prev_hashes ?? {};
  const filesToScan = input.files.filter(f => {
    if (!prev[f.path]) return true;
    const hash = crypto.createHash("sha256").update(f.content).digest("hex");
    if (hash === prev[f.path]) { skipped_unchanged++; return false; }
    return true;
  });

  // PR-level prior bias: when PR behavior or baseline deviation indicate strong
  // AI likelihood, give each file a small evidence boost via computeAIPercentage's
  // priorBias parameter. This connects multi-signal scoring to per-file AI%.
  // Max boost capped at 0.08 to avoid overriding file-level evidence.
  const prPriorBias = (() => {
    if (!input.pr_metadata) return 0;
    const prScore = scorePRBehavior(input.pr_metadata, 0).score;
    const baseScore = input.developer_baseline && input.pr_metadata
      ? scoreBaselineDeviation(input.pr_metadata, input.developer_baseline).score
      : 0;
    const val = (prScore * 0.6 + baseScore * 0.4) * 0.12;
    return Number.isFinite(val) ? Math.min(0.08, val) : 0;
  })();

  // ── Cross-file taint analysis, Pass 1: per-file export summaries (JS/TS) ──
  // Runs BEFORE the main analyzeFile() loop below so Pass 2 (inside
  // analyzeFile, via scanAstTaint) can see cross-file-propagating calls
  // while it walks each file for real. Parses each eligible file once here;
  // the same ts.SourceFile is threaded into analyzeFile below via
  // presparsedTs, so a file with cross-file imports still gets only ONE
  // parse (shared) and TWO walks (this lightweight summary walk, then
  // analyzeFile's real one) -- not two parses. JS/TS only; Python and Java
  // cross-file analysis are separate, later phases -- this block is named
  // and scoped accordingly rather than made generic, so those phases add
  // their own parallel blocks instead of overloading this one.
  const jsSourceFiles = new Map<string, ts.SourceFile>();
  const exportSummaries = new Map<string, Map<string, ParamShape[]>>();
  for (const f of filesToScan) {
    if (!shouldAstParse(f.content, f.path)) continue;
    const sf = parseSourceFile(f.content, f.path);
    jsSourceFiles.set(f.path, sf);
    exportSummaries.set(f.path, computeExportTaintSummary(f.content, f.path, sf));
  }

  // ── Bridge: resolve each file's own relative imports to a per-file
  // crossFilePropagating map, using astTaint.ts's real-AST import-binding
  // extraction (NOT ast.ts's regex-based import parsing below -- that keys
  // by the pre-alias exported name, not the local call-site identifier, so
  // `import { buildQuery as bq } from "./db"` would fail to match `bq(...)`
  // call sites). resolveImportPath only resolves `.`-relative specifiers;
  // bare/package specifiers return null and are silently skipped -- the
  // same "external package = out of graph" boundary semanticGraph.ts's own
  // cross-file mechanism already has, not a new limitation.
  const allScanPaths = filesToScan.map(f => f.path);
  const crossFilePropagatingByFile = new Map<string, Map<string, { shapes: ParamShape[]; fromModule: string }>>();
  // Cross-file REACHABILITY bridge (Decision 1, one hop, JS/TS only) --
  // file path -> names IN THAT FILE that are reachable because some OTHER
  // file imports and calls them from a function already known-reachable
  // there. Built in the SAME loop as crossFilePropagating above (same
  // import bindings, same resolveImportPath boundary), but answers a
  // different question: not "does taint flow through this call", just
  // "is this imported function actually called from reachable code".
  // buildCallGraph(f.content) here is a second, isolated computation
  // purely for this check -- analyzeFile() below still computes its own
  // callGraph internally per file; threading a pre-built one through would
  // have meant a THIRD optional analyzeFile param for a cheap, regex-based
  // computation that's fine to run twice.
  const crossFileReachableByFile = new Map<string, Set<string>>();
  for (const f of filesToScan) {
    const sf = jsSourceFiles.get(f.path);
    if (!sf) continue;
    const bindings = buildImportBindings(sf);
    const local = new Map<string, { shapes: ParamShape[]; fromModule: string }>();
    const callerGraph = buildCallGraph(f.content);
    for (const b of bindings) {
      const calleePath = resolveImportPath(f.path, b.moduleSpecifier, allScanPaths);
      if (!calleePath) continue; // external package or unresolvable -- skip, never throw
      const shapes = exportSummaries.get(calleePath)?.get(b.importedName);
      if (shapes && shapes.length > 0) local.set(b.localName, { shapes, fromModule: b.moduleSpecifier });

      const calledFromReachable = callerGraph.edges.some(
        e => e.callee === b.localName && callerGraph.reachable.has(e.caller),
      );
      if (calledFromReachable) {
        const set = crossFileReachableByFile.get(calleePath) ?? new Set<string>();
        set.add(b.importedName);
        crossFileReachableByFile.set(calleePath, set);
      }
    }
    if (local.size > 0) crossFilePropagatingByFile.set(f.path, local);
  }

  const files = filesToScan.map(f =>
    analyzeFile(
      f.path, f.content, prPriorBias, crossFilePropagatingByFile.get(f.path), jsSourceFiles.get(f.path),
      crossFileReachableByFile.get(f.path),
    ),
  );

  // ── v7: Semantic graph (cross-file module dependency analysis) ────────────
  // Built early so cross-file taint propagation can inject indicators into
  // `files` before per-file/overall risk is computed below.
  const parseMap = new Map(
    filesToScan.map(f => [f.path, parseAst(f.content, detectLanguage(f.path))])
  );
  const aiScoreMap = new Map(files.map(f => [f.file_path, f.ai_percentage]));
  const taintFiles = new Set(
    files.filter(f => f.ssa_taint_paths.length > 0).map(f => f.file_path)
  );
  const semantic_graph = buildSemanticGraph(
    filesToScan.map(f => f.path), parseMap, aiScoreMap, taintFiles,
  );

  // Cross-file taint exposure: flag files that directly import a symbol from
  // a file with its own unresolved taint path (see computeCrossFileTaintIndicators).
  const crossFileTaintIndicators = computeCrossFileTaintIndicators(files, semantic_graph);
  for (const f of files) {
    const extra = crossFileTaintIndicators.get(f.file_path);
    if (!extra || extra.length === 0) continue;
    f.indicators = [...f.indicators, ...extra];
    f.risk_indicators = Array.from(new Set(f.indicators.map(i => i.id)));
    f.risk_score = calculateRisk(f.indicators, f.ai_percentage);
  }

  // Blast radius: does an AI-heavy file's risk compound with real reach
  // (other changed files in this PR importing it) or a sensitive-path proxy?
  const blastRadiusIndicators = computeBlastRadiusIndicators(files, semantic_graph);
  for (const f of files) {
    const extra = blastRadiusIndicators.get(f.file_path);
    if (!extra || extra.length === 0) continue;
    f.indicators = [...f.indicators, ...extra];
    f.risk_indicators = Array.from(new Set(f.indicators.map(i => i.id)));
    f.risk_score = calculateRisk(f.indicators, f.ai_percentage);
  }

  // Weighted AI % (large files dominate)
  const totalLines = files.reduce((s, f) => s + f.line_count, 0);
  const avgAI = totalLines === 0 ? 0
    : files.reduce((s, f) => s + f.ai_percentage * f.line_count, 0) / totalLines;

  // AI distribution (percentiles)
  const scorable = files.filter(f => f.line_count > 20 && !getFileTypeMeta(f.file_path).skipAI);
  const sortedScores = scorable.map(f => f.ai_percentage).sort((a, b) => a - b);
  const ai_distribution = {
    p10: percentile(sortedScores, 10),
    p25: percentile(sortedScores, 25),
    p50: percentile(sortedScores, 50),
    p75: percentile(sortedScores, 75),
    p90: percentile(sortedScores, 90),
  };

  // Cross-file model consistency boost
  let crossFileBoost = false;
  if (files.length >= 3) {
    const modelCounts: Record<string, number> = {};
    for (const f of files) {
      if (f.attribution.confidence >= 0.40 && f.attribution.model !== "human" && f.attribution.model !== "unknown")
        modelCounts[f.attribution.model] = (modelCounts[f.attribution.model] ?? 0) + 1;
    }
    if (Math.max(0, ...Object.values(modelCounts)) >= Math.ceil(files.length * 0.60))
      crossFileBoost = true;
  }

  // Mixed-authorship: bimodal distribution (AI files + human files in same PR)
  let mixedAuthorship = false;
  if (files.length >= 4) {
    const highAI = scorable.filter(f => f.ai_percentage > 0.65).length;
    const lowAI  = scorable.filter(f => f.ai_percentage < 0.25).length;
    if (highAI >= 2 && lowAI >= 2 && highAI + lowAI >= scorable.length * 0.70)
      mixedAuthorship = true;
  }

  // Average scan quality across scorable files
  const scan_quality = scorable.length === 0 ? 0
    : scorable.reduce((s, f) => s + f.scan_quality, 0) / scorable.length;

  // Scan summary — security findings separated from AI signals
  const securityIndicators = files.flatMap(f =>
    f.indicators.filter(i => !AI_SIGNAL_IDS.has(i.id))
  );
  const criticalCount = securityIndicators.filter(i => i.severity === "critical").length;
  const highCount     = securityIndicators.filter(i => i.severity === "high").length;
  const mediumCount   = securityIndicators.filter(i => i.severity === "medium").length;
  const lowCount      = securityIndicators.filter(i => i.severity === "low").length;

  const vulnFreq: Record<string, number> = {};
  securityIndicators.forEach(i => { vulnFreq[i.id] = (vulnFreq[i.id] ?? 0) + 1; });
  const topVulnTypes = Object.entries(vulnFreq)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 3)
    .map(([id]) => id);

  const scan_summary: ScanSummary = {
    total_security_findings:  criticalCount + highCount + mediumCount + lowCount,
    critical_count:           criticalCount,
    high_count:               highCount,
    medium_count:             mediumCount,
    low_count:                lowCount,
    top_vuln_types:           topVulnTypes,
    ai_high_confidence_files: scorable.filter(f => f.scan_quality >= 0.70).length,
    requires_immediate_action: criticalCount > 0 || highCount > 0,
  };

  const boostedAI = crossFileBoost ? Math.min(1, avgAI + 0.05) : avgAI;

  // ── Multi-signal evidence breakdown ─────────────────────────────────────────
  // Weights: Code 25%, PR Behavior 25%, Git 30%, Tool Evidence 15%, other 5%

  // 1. Code evidence (existing AI % from style/structure signals)
  const codeEvidence = boostedAI;

  // 2. PR behavior evidence
  const totalLinesInScan = files.reduce((s, f) => s + f.line_count, 0);
  const prMeta = input.pr_metadata;
  const prBehavior = prMeta
    ? scorePRBehavior(prMeta, totalLinesInScan)
    : { score: 0, boosts: [] as string[] };
  const prEvidence = prBehavior.score;

  // 3. Tool evidence (Cursor/Copilot/Claude artifacts found)
  // Will be populated after ai_tooling is computed below; placeholder for now
  let toolEvidence = 0;

  // 4. Git provenance evidence (from existing git_provenance analysis)
  let gitEvidence = 0;
  // Applied after git_provenance is computed below

  // 5. Developer baseline deviation
  const baselineData = input.developer_baseline;
  const baselineDev  = prMeta && baselineData
    ? scoreBaselineDeviation(prMeta, baselineData)
    : null;
  const baselineEvidence = baselineDev?.score ?? 0;

  const allBoosts: string[] = [...prBehavior.boosts, ...(baselineDev?.reasons ?? [])];

  // Hard boost: >1000 LOC in single commit and <15 min timing
  if (prMeta && prMeta.additions > 1000 && prMeta.commits === 1) {
    allBoosts.push(`High-confidence signal: ${prMeta.additions} lines in a single commit`);
  }

  const riskOrder: Record<string, number> = { LOW:0, MEDIUM:1, HIGH:2, CRITICAL:3 };
  const overallRisk = files.reduce<RiskLevel>((max, f) =>
    riskOrder[f.risk_score] > riskOrder[max] ? f.risk_score : max, "LOW");

  const scan_id = crypto.randomUUID();

  // CI/CD trust scoring — analyse any workflow/pipeline files in the PR
  const contentMap = new Map(input.files.map(f => [f.path, f.content]));
  const cicd_trust = scoreCICDTrust(input.files.map(f => f.path), contentMap);

  // Cryptographic TrustLedger signature chain
  const trust_chain = buildTrustChain(files, scan_id);

  // ── Cross-file consistency ────────────────────────────────────────────────
  const modelCounts2: Record<string, number> = {};
  for (const f of files) {
    if (f.attribution.confidence >= 0.40 && f.attribution.model !== "human" && f.attribution.model !== "unknown")
      modelCounts2[f.attribution.model] = (modelCounts2[f.attribution.model] ?? 0) + 1;
  }
  const dominantModel = Object.entries(modelCounts2).sort(([,a],[,b]) => b - a)[0]?.[0] ?? "unknown";
  const aiScoresArr   = scorable.map(f => f.ai_percentage);
  const meanAI2       = aiScoresArr.length ? aiScoresArr.reduce((a,b) => a+b,0) / aiScoresArr.length : 0;
  const styleAgreement = aiScoresArr.length < 2 ? 1
    : 1 - Math.sqrt(aiScoresArr.reduce((s,v) => s + (v - meanAI2) ** 2, 0) / aiScoresArr.length);
  const outlierFiles  = scorable
    .filter(f => Math.abs(f.ai_percentage - meanAI2) > 0.25)
    .map(f => f.file_path);
  const languages     = new Set(files.map(f => f.language).filter(l => l !== "text"));
  const cross_file_consistency: CrossFileConsistency = {
    dominant_model:  dominantModel,
    style_agreement: Math.max(0, styleAgreement),
    outlier_files:   outlierFiles,
    mixed_languages: languages.size > 1,
  };

  // ── Aggregated compliance report ──────────────────────────────────────────
  const compliance = aggregateComplianceReports(files.map(f => f.compliance).filter((c): c is ComplianceReport => c !== null));

  // ── v7: Git provenance analysis ───────────────────────────────────────────
  const git_provenance = input.git_log
    ? analyzeGitProvenance(input.git_log)
    : null;

  // ── AI tooling artifact detection (LLM-era governance visibility) ─────────
  // Use allFilePaths when provided so config/json files like .claude/settings.json
  // are checked even though they aren't scannable source files. Also pass
  // scannable files' content so attribution markers left directly in source
  // (generated-by comments, co-authorship trailers) are caught -- the
  // path-only check almost never fires on a normal feature PR since agent
  // config files are typically added once, early in a repo's life.
  const ai_tooling = detectAIToolingArtifacts(
    (input.all_file_paths ?? input.files.map(f => f.path)),
    input.files,
  );

  // ── Finalise evidence breakdown ───────────────────────────────────────────
  // Tool evidence: explicit AI tool artifacts found (Cursor, Copilot, etc.)
  toolEvidence = ai_tooling.length > 0 ? Math.min(1, ai_tooling.length * 0.35) : 0;
  if (ai_tooling.length > 0) {
    allBoosts.push(`AI tooling detected: ${ai_tooling.map(t => t.tool).join(", ")}`);
  }

  // Git evidence: from provenance analysis
  // ProvenanceSummary.overallRiskScore: 0=trusted, 1=critical
  // aiAuthoredCommits: commits explicitly referencing AI tools
  if (git_provenance) {
    const aiCommitSignal = Math.min(1, git_provenance.aiAuthoredCommits / Math.max(1, git_provenance.totalCommits));
    gitEvidence = Math.min(1, git_provenance.overallRiskScore * 0.5 + aiCommitSignal * 0.5);
    if (git_provenance.aiAuthoredCommits > 0) {
      allBoosts.push(`${git_provenance.aiAuthoredCommits} commit(s) mention AI tool in message`);
    }
  }

  // Exemption: lower PR evidence if many generated/vendor files detected
  const generatedFileRatio = input.files.filter(f => GENERATED_PATH_RE.test(f.path)).length / Math.max(1, input.files.length);
  const prEvidenceAdjusted = prEvidence * (1 - generatedFileRatio * 0.5);

  // Combined score (weights from architecture doc):
  //   Code Structure       25%
  //   PR Behavior          25%
  //   Git Provenance       25%  (reduced from 30% to make room for baseline)
  //   Developer Baseline   15%
  //   Tool Evidence        10%
  const combinedRaw = (
    codeEvidence       * 0.25 +
    prEvidenceAdjusted * 0.25 +
    gitEvidence        * 0.25 +
    baselineEvidence   * 0.15 +
    toolEvidence       * 0.10
  );

  // Hard boosts that override normal weighting
  let hardBoost = 0;
  if (prMeta && prMeta.additions > 1000 && prMeta.commits === 1) hardBoost = Math.max(hardBoost, 0.20);
  if (ai_tooling.length > 0 && codeEvidence > 0.40)              hardBoost = Math.max(hardBoost, 0.15);

  const combinedUnclamped = combinedRaw + hardBoost;
  const combined = Number.isFinite(combinedUnclamped) ? Math.min(1, combinedUnclamped) : codeEvidence;

  const evidence_breakdown: EvidenceBreakdown = {
    code_evidence:      codeEvidence,
    pr_evidence:        prEvidenceAdjusted,
    git_evidence:       gitEvidence,
    tool_evidence:      toolEvidence,
    baseline_evidence:  baselineEvidence,
    combined,
    likelihood:         classifyAILikelihood(combined),
    boosts:             allBoosts,
    baseline_deviation: baselineDev ?? undefined,
  };


  return {
    scan_id,
    repo:                 input.repo,
    pr_number:            input.pr_number,
    commit_sha:           input.commit_sha,
    overall_risk:         overallRisk,
    // Use multi-signal combined score as the primary AI likelihood metric.
    // Guarded against NaN: any NaN in sub-calculations falls back to code-only.
    total_ai_percentage: (() => {
      const blended = evidence_breakdown.combined;
      const fallback = Number.isFinite(boostedAI) ? boostedAI : avgAI;
      if (!Number.isFinite(blended)) return Number.isFinite(fallback) ? fallback : 0;
      return blended > fallback ? blended : fallback;
    })(),
    cross_file_ai_boost:  crossFileBoost,
    mixed_authorship:     mixedAuthorship,
    scan_quality,
    ai_distribution,
    files,
    duration_ms:          Date.now() - start,
    scan_summary,
    cicd_trust,
    trust_chain,
    cross_file_consistency,
    compliance,
    skipped_unchanged,
    semantic_graph,
    git_provenance,
    ai_tooling,
    evidence_breakdown,
  };
}

// ── Cryptographic helpers ──────────────────────────────────────────────────────

export function buildAttestationHash(
  scan_id: string, file_path: string, reviewer_email: string, timestamp: string,
): string {
  return crypto.createHash("sha256").update(`${scan_id}::${file_path}::${reviewer_email}::${timestamp}`).digest("hex");
}

export function buildAuditHash(
  prev_hash: string | null, event_type: string, actor_email: string, payload: string, timestamp: string,
): string {
  return crypto.createHash("sha256").update(`${prev_hash ?? "GENESIS"}::${event_type}::${actor_email}::${payload}::${timestamp}`).digest("hex");
}