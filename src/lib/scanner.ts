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
 *     dependency vulnerability analysis (depAnalysis.ts), compliance engine
 *     (compliance.ts), exploitability scoring (reachability.ts),
 *     precision/recall evaluation framework (benchmark.ts)
 *   +3 ScanOutput fields: cross_file_consistency, repository_trust_score, dep_report
 *   +1 incremental scanning: changedFiles in ScanInput skips unchanged hashes
 */

import crypto from "crypto";
import { attributeCode, type AttributionResult } from "./aiAttribution";
import { buildCallGraph }        from "./callGraph";
import { analyzePackages, parsePackageJson, parseRequirementsTxt, parseGoMod, extractImportedPackages } from "./depAnalysis";
import type { DependencyReport } from "./depAnalysis";
import { aggregateComplianceReports, evaluateCompliance } from "./compliance";
import type { ComplianceReport }  from "./compliance";
import { scoreExploitability }   from "./reachability";
import type { ReachabilityReport } from "./reachability";
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

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ScanIndicator {
  id:       string;
  label:    string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  line?:    number;
  detail?:  string;
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
  java: "java",   kt: "kotlin",     cs: "csharp",
  php: "php",     cpp: "cpp",       c:   "c",
  swift: "swift", yaml: "yaml",     yml: "yaml",
  json: "json",   sh: "shell",      sql: "sql",
  md: "markdown", tf: "terraform",  ex: "elixir",
};

export function detectLanguage(path: string): string {
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

  const SKIP_EXTS = new Set(["json","yaml","yml","toml","ini","env","lock","csv","sql","md","txt","xml","svg","png","jpg","ico","woff","woff2"]);
  if (SKIP_EXTS.has(ext)) return { skipAI:true, isGenerated:false, isTestFile:false, aiPriorBias:0 };

  const isGenerated =
    /\.(d\.ts|min\.js|bundle\.js|pb\.ts|pb\.js)$/.test(lower) ||
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

interface SecretPattern { re: RegExp; label: string; severity: ScanIndicator["severity"] }

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
  { re: /s\.[A-Za-z0-9]{24,}/,                                                  label: "HashiCorp Vault token",       severity: "critical" },
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
  { re: /jdbc:[a-z]+:\/\/[^\s"']+password=[^\s&"']+/i,                         label: "DB connection string",        severity: "critical" },
  { re: /(?:password|passwd|pwd)\s*=\s*["'][^"']{8,}["']/i,                   label: "Hardcoded password",          severity: "critical" },
  { re: /(?:api_key|apikey|api_secret)\s*=\s*["'][^"']{8,}["']/i,             label: "Hardcoded API key",           severity: "critical" },
  { re: /(?:secret|token)\s*=\s*["'][^"']{12,}["']/i,                         label: "Hardcoded secret",            severity: "high"     },
  { re: /(?:access_token|ACCESS_TOKEN)\s*=\s*["'][A-Za-z0-9_\-]{20,}["']/i,  label: "Hardcoded access token",      severity: "high"     },
];

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
// words that only appear in sample/demo/test data ("trustledger" referring
// to this product itself, "password"/"demo"/"sample"/"fake"/"dummy"/
// "placeholder"/"example"/"exmp").
const PLACEHOLDER_VALUE_RE = /\.\.\.|[xX]{4,}|trustledger|password|demo|sample|fake|dummy|placeholder|example|exmp/i;

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
const DEMO_DATA_FILE_RE = /\/(seed|seedFileSamples|vulnCatalog)\.ts$/;

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
function extractTaintedVars(lines: string[]): Set<string> {
  const tainted = new Set<string>();
  for (const line of lines) {
    if (isNonExecutableLine(line)) continue;
    // const/let/var x = req.query.x
    const single = /\b(?:const|let|var)\s+(\w+)\s*=\s*(?:req|request)\.(?:query|body|params|headers)\b/.exec(line);
    if (single) { tainted.add(single[1]); continue; }
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
    const pyAssign = /^(\w+)\s*=\s*request\.(?:args|form|json|data|POST|GET)/.exec(line.trim());
    if (pyAssign) { tainted.add(pyAssign[1]); continue; }
    // PHP: $url = $_GET['url']
    const phpAssign = /^\$(\w+)\s*=\s*\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\s*\[/.exec(line.trim());
    if (phpAssign) { tainted.add(phpAssign[1]); continue; }
  }
  return tainted;
}

// Individual detector patterns — module-level compilation
const SQL_INJECTION_RE = [
  /f["'].*\{.*\}.*(?:where|from|select|insert|delete|update)/i,
  /["']\s*\+\s*\w+\s*\+\s*["'].*(?:where|from|select)/i,
  /cursor\.execute\s*\(\s*(?:f["']|["'][^?])/i,
  /db\.query\s*\(\s*(?:`[^`]*\$\{|['"][^?][^'"]*\+)/i,
  /(?:execute|query)\s*\(\s*["'].*\+\s*\w/i,
  /\$\{[^}]+\}.*(?:WHERE|SELECT|INSERT|UPDATE|DELETE)/i,
  /knex\.raw\s*\(`[^`]*\$\{/i,
  /sequelize\.query\s*\(\s*`[^`]*\$\{/i,
];

const EVAL_EXEC_RE = [
  /\beval\s*\(/,
  /new\s+Function\s*\(/,
  /subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True/,
  /os\.system\s*\(/,
  /child_process\.exec\s*\(/,
  /\bexecSync\s*\(/,
];

const JWT_BYPASS_RE =
  /(?:algorithms?\s*=\s*\[.*["']none["']|verify\s*=\s*False|ignoreExpiration|{"alg"\s*:\s*"none"})/i;

const CMD_INJECTION_RE = [
  /subprocess\.(?:call|run)\s*\([^)]*f["']/,
  /os\.popen\s*\(\s*(?:f["']|[^)]*\+)/,
  /execSync\s*\(`[^`]*\$\{/,
  /child_process\.exec\s*\(`[^`]*\$\{/,
  /spawn\s*\([^,)]*\$\{[^}]+\}/,
  /\bexec\s*\(\s*`[^`]*\$\{/,
];

const SSRF_RE = [
  /(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.)\w+/i,
  /new\s+URL\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.)\w+/i,
  /https?\.(?:get|request)\s*\(\s*(?:req\.|request\.|body\.|params\.)\w+/i,
  /got\s*\(\s*(?:req\.|body\.|params\.|query\.)\w+/i,
  /axios\s*\(\s*\{\s*url\s*:\s*(?:req\.|body\.|params\.)\w+/i,
];

const PATH_TRAVERSAL_RE = [
  /path\.(?:join|resolve)\s*\([^)]*(?:req\.|request\.|body\.|params\.|query\.)\w+/i,
  /fs\.(?:readFile|writeFile|readdir|stat|unlink|createReadStream|createWriteStream)\s*\([^)]*(?:req\.|params\.|body\.|query\.)\w+/i,
  /__dirname\s*\+\s*(?:req\.|params\.|body\.|query\.)\w+/i,
  /path\.join\s*\([^)]*['"]\.\.['"]/,
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
];

const TIMING_ATTACK_RE = [
  /(?:token|secret|password|hash|hmac|signature|key)\s*(?:===|==)\s*(?:req\.|body\.|params\.|query\.|\w+)/i,
  /(?:req\.|body\.|params\.)[\w.]+\s*(?:===|==)\s*(?:token|secret|password|hash|hmac|signature)/i,
];

// SSTI — server-side template injection
const SSTI_RE = [
  /(?:ejs|nunjucks|pug|jade)\.render(?:File)?\s*\(\s*(?:req|request)\.(?:query|body|params)\b/i,
  /(?:Handlebars|Mustache|swig)\.compile\s*\(\s*(?:req|request)\.(?:query|body|params)\b/i,
  /Template\s*\(\s*(?:req|request)\.(?:query|body|params)\b/i,
  /render_template_string\s*\(\s*(?:request\.data|request\.json|request\.args)/i,
  /env\.from_string\s*\(\s*(?:request\.|req\.)\w+/i,
  /\.render\s*\(\s*(?:req|request)\.(?:body|query)\.\w+/i,
];

// HTTP Header Injection (CRLF injection into response headers)
const HEADER_INJECT_RE = [
  /res\.(?:setHeader|header)\s*\([^,]+,\s*(?:req|request)\.(?:query|body|params|headers)\b/i,
  /res\.setHeader\s*\(\s*["'](?:Location|Refresh|Set-Cookie)["'],\s*(?:req|request)\./i,
  /response\.headers\s*\[["'][\w-]+["']\]\s*=\s*(?:req|request)\./i,
  /headers\s*\[(?:req|request)\.(?:query|body|params)\b/i,
];

// Weak CORS policy
const WEAK_CORS_RE = [
  /Access-Control-Allow-Origin["']?\s*[,:]\s*["']?\*/,
  /cors\s*\(\s*\{\s*origin\s*:\s*["']\*["']/,
  /res\.(?:header|setHeader)\s*\(\s*["']Access-Control-Allow-Origin["'],\s*["']\*["']\)/,
  /app\.use\s*\(\s*cors\s*\(\s*\)\s*\)/,
  /allowedOrigins\s*=\s*\[\s*["']\*["']/,
];

// IDOR — insecure direct object reference (no ownership check)
const IDOR_RE = [
  /\.findById\s*\(\s*(?:req|request)\.(?:params|query|body)\b/i,
  /\.findOne\s*\(\s*\{[^}]{0,80}_?id\s*:\s*(?:req|request)\.(?:params|query|body)\b/i,
  /(?:db|conn|pool|client)\.(?:get|find|query)\s*\(\s*(?:req|request)\.(?:params|query)\b/i,
  /SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+(?:id|user_id|owner_id)\s*=\s*\$\{(?:req|request)\./i,
  /\bgetById\s*\(\s*(?:req|request)\.(?:params|query)\b/i,
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
];

// GraphQL injection (user input in query template)
const GRAPHQL_INJECT_RE = [
  /gql`[^`]*\$\{(?:req|request)\.(?:query|body|params)\b/i,
  /graphql\s*\(\s*\w+\s*,\s*(?:req|request)\.(?:body|query)\.\w+/i,
  /`\s*(?:query|mutation)\s+\w+[^`]*\$\{(?:req|request)\./i,
  /graphqlQuery\s*=\s*`[^`]*\$\{/,
  /makeExecutableSchema\s*\(\s*\{[^}]*typeDefs\s*:\s*`[^`]*\$\{(?:req|request)\./i,
];

// XML External Entity injection
const XXE_RE = [
  /new\s+DOMParser\s*\(\s*\)[\s\S]{0,100}\.parseFromString\s*\(\s*(?:req|request)\./i,
  /DocumentBuilderFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,300}setFeature\s*\([^)]*FEATURE_SECURE_PROCESSING)/,
  /SAXParserFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,300}setFeature)/,
  /XMLReaderFactory\.createXMLReader\s*\(\s*\)/,
  /etree\.(?:fromstring|parse)\s*\(\s*(?:req|request)\./i,
  /lxml\.etree\.(?:fromstring|parse)\s*\(\s*(?:req|request)\./i,
  /libxml\.parseXml(?:String)?\s*\(\s*(?:req|request)\./i,
];

// LDAP injection (filter construction with user input)
const LDAP_INJECT_RE = [
  /(?:searchFilter|filter|ldapFilter)\s*[:=]\s*`[^`]*\$\{/i,
  /(?:searchFilter|filter)\s*[:=]\s*['"][^'"]*['"]\s*\+\s*(?:req|request)\./i,
  /(?:ldap|ad)\.(?:search|query|findUser|bind)\s*\([^)]*\+\s*(?:req|request)\./i,
  /\(\s*(?:cn|uid|mail|sAMAccountName)\s*=\s*['"]?\s*\+\s*(?:req|request)\./i,
  /\.search(?:Entries)?\s*\([^)]*(?:req|request)\.(?:query|body|params)\b/i,
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
];

// Insecure deserialization
const INSECURE_DESERIAL_RE = [
  /pickle\.loads?\s*\(\s*(?!b["'])/,
  /yaml\.load\s*\([^,)]+\)(?!\s*,\s*Loader\s*=\s*yaml\.(?:Safe|Full)Loader)/,
  /jsonpickle\.decode\s*\(/,
  /unserialize\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)/,
  /Marshal\.load\s*\(\s*(?:params|request|body)/,
  /ObjectInputStream\s*\(\s*(?:request|socket)\.getInputStream/,
  /node-serialize\b.*\.unserialize/,
  /serialize-javascript.*eval\s*\(/i,
];

// Weak cryptography
const WEAK_CRYPTO_RE = [
  /createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/i,
  /hashlib\.(?:md5|sha1)\s*\(\s*(?:password|passwd|pwd)/i,
  /(?:MD5|SHA1|SHA128)\.new\s*\(/,
  /createCipheriv\s*\(\s*["'](?:des|rc4|rc2|bf|blowfish|idea)[-\w]*["']/i,
  /createCipheriv\s*\(\s*["']aes-\d+-ecb["']/i,
  /Cipher\.getInstance\s*\(\s*["'](?:DES|AES\/ECB|RC4|Blowfish)/i,
  /Digest\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']/i,
  /bcrypt\.(?:hash|hashSync)\s*\([^,]+,\s*[1-9]\s*[,)]/,  // rounds < 10
];

// PII in logs
const PII_LOG_RE = [
  /(?:console|logger|log)\.\w+\s*\([^)]*\b(?:email|mail)\b[^)]*\)/i,
  /(?:console|logger|log)\.\w+\s*\([^)]*\b(?:password|passwd|pwd|token|secret|auth)\b[^)]*\)/i,
  /(?:console|logger|log)\.\w+\s*\([^)]*\bssn\b[^)]*\)/i,
  /(?:console|logger|log)\.\w+\s*\([^)]*\b(?:credit.?card|ccnum|cvv|card.?number)\b[^)]*\)/i,
  /(?:console|logger|log)\.\w+\s*\([^)]*\bphone\b[^)]*\)/i,
  /logging\.(?:info|debug|warning|error)\s*\([^)]*(?:password|email|token|ssn)\b[^)]*\)/i,
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

function findSecrets(lines: string[], file_path: string): ScanIndicator[] {
  if (DEMO_DATA_FILE_RE.test(file_path)) return [];
  const found: ScanIndicator[] = [];
  for (const { re, label, severity } of SECRET_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      if (isNonExecutableLine(lines[i])) continue;
      if (isPlaceholderSecretLine(lines[i])) continue;
      if (re.test(lines[i]))
        found.push({ id:"hardcoded-secret", label:`Hardcoded ${label}`, severity, line:i+1, detail:`${label} detected` });
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

function findSQLInjection(lines: string[]): ScanIndicator[] {
  return runDetector(lines, SQL_INJECTION_RE, "sql-injection", "SQL Injection", "critical",
    "Query built with string interpolation — use parameterised queries");
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

function findSSRF(lines: string[]): ScanIndicator[] {
  return runDetector(lines, SSRF_RE, "ssrf", "Server-Side Request Forgery", "critical",
    "User-controlled URL in HTTP request — validate against allowlist or use SSRF-safe library");
}

function findPathTraversal(lines: string[]): ScanIndicator[] {
  return runDetector(lines, PATH_TRAVERSAL_RE, "path-traversal", "Path Traversal", "critical",
    "User input in file path — resolve and validate against base directory");
}

function findPrototypePollution(lines: string[]): ScanIndicator[] {
  return runDetector(lines, PROTO_POLLUTION_RE, "prototype-pollution", "Prototype Pollution", "high",
    "Unvalidated user input merged into object — may pollute Object prototype");
}

function findInsecureRandomness(lines: string[]): ScanIndicator[] {
  return runDetector(lines, INSECURE_RANDOM_RE, "insecure-randomness", "Insecure Randomness", "high",
    "Math.random() is not cryptographically secure — use crypto.randomBytes()");
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
  const HTTP_SINK_RE = /(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|got|needle|superagent|https?\.(?:get|request))\s*\(\s*(\w+)/i;
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

function findIDOR(lines: string[]): ScanIndicator[] {
  return runDetector(lines, IDOR_RE, "idor", "Insecure Direct Object Reference", "high",
    "User-supplied ID used in DB lookup without ownership check — verify caller owns the resource");
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

function findXXE(lines: string[]): ScanIndicator[] {
  return runDetector(lines, XXE_RE, "xxe", "XML External Entity (XXE)", "critical",
    "XML parser with external entities enabled — disable DTD processing in parser config");
}

function findLDAPInjection(lines: string[]): ScanIndicator[] {
  return runDetector(lines, LDAP_INJECT_RE, "ldap-injection", "LDAP Injection", "critical",
    "User input in LDAP filter — escape special chars or use parameterized LDAP libraries");
}

function findInsecureFileUpload(lines: string[]): ScanIndicator[] {
  return runDetector(lines, FILE_UPLOAD_RE, "insecure-file-upload", "Insecure File Upload", "high",
    "File upload without MIME validation and size limits — add fileFilter and limits to config");
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
];

function sigCommentPhrasing(content: string): number {
  let hits = 0;
  for (const re of COMMENT_PHRASING_RE) if (re.test(content)) hits++;
  // Raised from 5→6 minimum for max score. 1-2 matches are common in human
  // codebases (e.g. a single TSDoc @param or a "Step 1:" comment); require
  // at least 3 distinct patterns before contributing any evidence.
  return hits >= 6 ? 1.0 : hits === 5 ? 0.88 : hits === 4 ? 0.72 : hits === 3 ? 0.52 : 0;
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
  ["language-specific",       0.60],  // Stereotyped per-language AI patterns
  ["ngram-fingerprint",       0.60],  // Characteristic token bigrams (return {success:, const result=await, etc.)
  ["test-structure",          0.55],  // Robotically uniform AI test suites
  ["structural-clones",       0.55],  // 3+ near-identical function bodies = AI-generated CRUD
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
    coreNoisyOr * (1 + secNoisyOr * 0.60) + secOnlyFloor + priorBias,
  ));

  // Human-authorship dampening: genuine human-written signals (typos, dated
  // personal comments, debug prints, mixed indentation, etc., from
  // attributeCode's HUMAN_SIGNALS) pull the combined score down. Capped at a
  // 30% reduction so a few stray markers in otherwise AI-typical code don't
  // swing the verdict, but strong human evidence keeps a clearly AI-shaped
  // file from reading as 95%+ AI.
  combined *= (1 - Math.min(0.30, humanEvidence * 0.20));

  // Sigmoid centred at 0.50. The 0.55 centre was introduced to suppress false
  // positives on well-written human code; 0.50 restores detection sensitivity
  // without reintroducing those positives (secondary signals still cannot fire
  // when core evidence is absent).
  // Human expert with moderate core (≈ 0.35) → combined ≈ 0.46 → sigmoid ≈ 39%
  // Clear AI with strong core (≈ 0.94) → combined → 1.0 → sigmoid ≈ 98%
  const sigmoid = 1 / (1 + Math.exp(-7 * (combined - 0.50)));

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

// ── Risk calculation ───────────────────────────────────────────────────────────

function calculateRisk(indicators: ScanIndicator[], aiPct: number): RiskLevel {
  if (indicators.some(i => i.severity === "critical")) return "CRITICAL";
  if (indicators.some(i => i.severity === "high"))     return "HIGH";
  // Thresholds calibrated for the new three-phase sigmoid (centred at 0.55).
  // A clearly AI file scores 0.80–0.96; a borderline human/AI file scores ~0.50.
  if (aiPct > 0.75)                                    return "HIGH";
  if (aiPct > 0.52)                                    return "MEDIUM";
  if (aiPct > 0.38 && indicators.length >= 2)          return "MEDIUM";
  if (indicators.some(i => i.severity === "medium"))   return "MEDIUM";
  if (indicators.length > 0)                           return "MEDIUM";
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

/** Scan repo file paths for AI coding-agent config/rule files (governance visibility). */
export function detectAIToolingArtifacts(filePaths: string[]): AIToolingArtifact[] {
  const out: AIToolingArtifact[] = [];
  for (const fp of filePaths) {
    for (const { re, tool, label } of AI_TOOLING_PATTERNS) {
      if (re.test(fp)) out.push({ tool, file: fp, label });
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

// ── analyzeFile ────────────────────────────────────────────────────────────────

export function analyzeFile(file_path: string, content: string): FileAnalysis {
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

  // Security scan — all detectors
  const rawIndicators: ScanIndicator[] = [
    ...findSecrets(lines, file_path),
    ...findHighEntropySecrets(lines, file_path),
    ...findXSS(lines),
    ...findInsecureDeserialization(lines),
    ...findWeakCrypto(lines),
    ...findPIIInLogs(lines),
    ...findMassAssignment(lines),
    ...findSQLInjection(lines),
    ...findSQLInjectionTainted(lines),
    ...findEvalExec(lines),
    ...findJwtBypass(lines),
    ...findCommandInjection(lines),
    ...findSSRF(lines),
    ...findSSRFTainted(lines),
    ...findPathTraversal(lines),
    ...findPrototypePollution(lines),
    ...findInsecureRandomness(lines),
    ...findReDoS(lines),
    ...findOpenRedirect(lines),
    ...findTimingAttack(lines),
    ...findSSTI(lines),
    ...findHeaderInjection(lines),
    ...findWeakCORS(lines),
    ...findIDOR(lines),
    ...findSensitiveDataInURL(lines),
    ...findNamedTaintSSRF(lines),
    ...findNamedTaintXSS(lines),
    ...findNoSQLInjection(lines),
    ...findVerboseErrors(lines),
    ...findGraphQLInjection(lines),
    ...findXXE(lines),
    ...findLDAPInjection(lines),
    ...findInsecureFileUpload(lines),
    ...findTOCTOU(lines),
    ...findCookieInsecurity(lines),
  ];

  // Dedup by id+line
  const seen: Record<string, true> = {};
  const indicators = rawIndicators.filter(i => {
    const k = `${i.id}:${i.line ?? ""}`;
    if (seen[k]) return false;
    seen[k] = true;
    return true;
  });

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
      content, lang, lineCount, fileMeta.aiPriorBias, attribution.humanEvidence,
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

  // Exploitability scoring (CVSS-lite with call-graph reachability)
  const callGraph   = !fileMeta.skipAI ? buildCallGraph(content) : null;
  const exploitability = indicators.filter(i => !AI_SIGNAL_IDS.has(i.id)).length > 0
    ? scoreExploitability(indicators, content, callGraph)
    : null;

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
  repo:          string;
  pr_number:     number;
  commit_sha:    string;
  branch?:       string;
  files:         Array<{ path: string; content: string }>;
  prev_hashes?:  Record<string, string>;  // incremental: path → previous content_hash; skip if unchanged
  git_log?:      string;                  // optional: git log --format="%H|%an|%ae|%at|%G?|%s" output
  pr_metadata?:  PRMetadata;              // PR behavior signals (LOC, commits, timing)
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

export interface EvidenceBreakdown {
  code_evidence:  number;  // 0–1: style/structure/AI-pattern signals
  pr_evidence:    number;  // 0–1: PR behavior (LOC, commits, timing)
  git_evidence:   number;  // 0–1: git provenance (commit velocity, history)
  tool_evidence:  number;  // 0–1: explicit tool artifacts (Cursor, Copilot, etc.)
  combined:       number;  // 0–1: weighted combination
  likelihood:     AILikelihoodBand;
  boosts:         string[]; // human-readable reasons for score boosts
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

export interface RepositoryTrustScore {
  score:             number;  // 0–1 (1 = fully trusted)
  factors: {
    ai_percentage:    number;  // weighted AI% across all files
    security_density: number;  // security findings per 100 lines
    cicd_trust:       number;  // CI/CD pipeline score
    dep_risk:         number;  // dependency risk
    compliance_score: number;  // compliance score
    watermark_count:  number;  // total watermarks found
    backdoor_risk:    number;  // max behavioral risk score
  };
  label:  "TRUSTED" | "LOW_RISK" | "MODERATE_RISK" | "HIGH_RISK" | "CRITICAL_RISK";
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
  repository_trust:     RepositoryTrustScore;
  dep_report:           DependencyReport | null;
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

  const files = filesToScan.map(f => analyzeFile(f.path, f.content));

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
  // Mapped from ProvenanceSummary.drift_score and temporal_risk
  let gitEvidence = 0;
  // Applied after git_provenance is computed below

  // Combined score — weighted per the proposed architecture
  // Applied after tool evidence and git evidence are computed

  const allBoosts: string[] = [...prBehavior.boosts];

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

  // ── Dependency analysis ───────────────────────────────────────────────────
  // Parse any manifest files included in the PR; also collect imported package names
  let dep_report: DependencyReport | null = null;
  const pkgJsonFile = input.files.find(f => /(?:^|\/)package\.json$/.test(f.path));
  const reqTxtFile  = input.files.find(f => /requirements\.txt$/.test(f.path));
  const goModFile   = input.files.find(f => /go\.mod$/.test(f.path));
  if (pkgJsonFile || reqTxtFile || goModFile) {
    const pkgs = pkgJsonFile ? parsePackageJson(pkgJsonFile.content)
               : reqTxtFile  ? parseRequirementsTxt(reqTxtFile.content)
               : goModFile   ? parseGoMod(goModFile.content)
               : [];
    dep_report = analyzePackages(pkgs);
  } else {
    // Fall back: infer packages from import statements across all source files
    const allImports = Array.from(new Set(
      input.files.flatMap(f => extractImportedPackages(f.content))
    )).map(name => ({ name, version: "*", dev: false }));
    if (allImports.length > 0) dep_report = analyzePackages(allImports);
  }

  // ── Aggregated compliance report ──────────────────────────────────────────
  const compliance = aggregateComplianceReports(files.map(f => f.compliance).filter((c): c is ComplianceReport => c !== null));

  // ── v7: Git provenance analysis ───────────────────────────────────────────
  const git_provenance = input.git_log
    ? analyzeGitProvenance(input.git_log)
    : null;

  // ── AI tooling artifact detection (LLM-era governance visibility) ─────────
  const ai_tooling = detectAIToolingArtifacts(input.files.map(f => f.path));

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

  // Combined score:
  //   Code Structure   25%
  //   PR Behavior      25%
  //   Git Provenance   30%
  //   Tool Evidence    15%
  //   (baseline 5% handled via codeEvidence floor)
  const combinedRaw = (
    codeEvidence  * 0.25 +
    prEvidenceAdjusted * 0.25 +
    gitEvidence   * 0.30 +
    toolEvidence  * 0.15
  );

  // Hard boosts that override normal weighting
  let hardBoost = 0;
  if (prMeta && prMeta.additions > 1000 && prMeta.commits === 1) hardBoost = Math.max(hardBoost, 0.20);
  if (ai_tooling.length > 0 && codeEvidence > 0.40)              hardBoost = Math.max(hardBoost, 0.15);

  const combined = Math.min(1, combinedRaw + hardBoost);

  const evidence_breakdown: EvidenceBreakdown = {
    code_evidence:  codeEvidence,
    pr_evidence:    prEvidenceAdjusted,
    git_evidence:   gitEvidence,
    tool_evidence:  toolEvidence,
    combined,
    likelihood:     classifyAILikelihood(combined),
    boosts:         allBoosts,
  };

  // ── Repository trust score ────────────────────────────────────────────────
  const totalLines2 = files.reduce((s, f) => s + f.line_count, 0) || 1;
  const secDensity  = (criticalCount + highCount) / (totalLines2 / 100);
  const depRisk     = dep_report ? 1 - dep_report.overall_score : 0;
  const cicdScore   = cicd_trust ? cicd_trust.score : 1;
  const compScore   = compliance.overall_score;
  const maxBehav    = Math.max(0, ...files.map(f => f.behavioral_risk.score));
  const wmCount     = files.reduce((s, f) => s + f.watermarks.length, 0);
  const factors = {
    ai_percentage:    boostedAI,
    security_density: Math.min(1, secDensity / 5),
    cicd_trust:       cicdScore,
    dep_risk:         depRisk,
    compliance_score: compScore,
    watermark_count:  wmCount,
    backdoor_risk:    maxBehav,
  };
  const trustRaw = 1
    - boostedAI          * 0.25
    - factors.security_density * 0.20
    - (1 - cicdScore)    * 0.10
    - depRisk            * 0.15
    - (1 - compScore)    * 0.10
    - Math.min(1, wmCount * 0.3) * 0.10
    - maxBehav           * 0.10;
  const trustScore = Math.max(0, Math.min(1, trustRaw));
  const trustLabel: RepositoryTrustScore["label"] =
    trustScore >= 0.85 ? "TRUSTED"
    : trustScore >= 0.70 ? "LOW_RISK"
    : trustScore >= 0.50 ? "MODERATE_RISK"
    : trustScore >= 0.30 ? "HIGH_RISK"
    : "CRITICAL_RISK";
  const repository_trust: RepositoryTrustScore = { score: trustScore, factors, label: trustLabel };

  return {
    scan_id,
    repo:                 input.repo,
    pr_number:            input.pr_number,
    commit_sha:           input.commit_sha,
    overall_risk:         overallRisk,
    total_ai_percentage:  boostedAI,
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
    repository_trust,
    dep_report,
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