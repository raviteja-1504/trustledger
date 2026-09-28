/**
 * Turns one scanner finding into the reviewer-facing evidence shown inline under its flagged line on the
 * PR page: a one-sentence explanation, the source -> sink data-flow path, and a "why this was flagged"
 * checklist. Client-safe (no server imports).
 *
 * Every statement is derived from a field the scanner actually produced for THIS finding -- nothing is
 * inferred beyond it. In particular a pattern-only finding (no sourceExpr/trace) never gets a data-flow
 * path or a "no sanitiser on the path" claim: only the AST taint engines establish those, because they emit
 * a finding only when taint for the sink's class survives every sanitiser on the path.
 */
import type { FileIndicator, TraceStep } from "@/types";

/** A run of plain text or inline code; rendered as <code> by the UI. Never parsed from backticks, because
 * source expressions routinely contain backticks themselves (JS template literals). */
export type Part = string | { code: string };

export type CheckTone = "confirmed" | "absent" | "caution" | "neutral";
export interface EvidenceCheck { tone: CheckTone; parts: Part[] }

export interface FlowStep {
  kind: TraceStep["kind"];
  kindLabel: string;
  text: string;
  line?: number;
  /** Set only when the step is in a different file from the one being viewed. */
  otherFile?: string;
}

export interface FindingEvidence {
  isDataFlow: boolean;
  analysisLabel: string;
  summary: Part[];
  /** Human name for what kind of untrusted input the flow starts at, when recognisable. */
  inputKind?: string;
  flow: FlowStep[];
  /** True when the path was assembled from the source/sink endpoints only (no intermediate steps known). */
  flowFromEndpointsOnly: boolean;
  checks: EvidenceCheck[];
  /** For a pattern-only finding: the confirmed data-flow finding (same vulnerability) whose path runs
   * through this line, so the UI can link the two red lines instead of presenting them as unrelated. */
  onPathOf?: { line: number; step: number; steps: number };
}

interface SinkSemantics { effect: string; defense: string }

// What reaching this sink class means, and the defence whose absence makes it exploitable.
const SINK_SEMANTICS: Record<string, SinkSemantics> = {
  "sql-injection":            { effect: "it is used to build a SQL query",                    defense: "SQL parameterisation or escaping" },
  "nosql-injection":          { effect: "it is used in a NoSQL query",                        defense: "type validation of query values" },
  "graphql-injection":        { effect: "it is used to build a GraphQL query",                defense: "GraphQL variables" },
  "command-injection":        { effect: "it is used to build an OS command",                  defense: "an argument array or shell quoting" },
  "argument-injection":       { effect: "it is passed as an argument to an external program", defense: "a `--` separator or leading-dash check" },
  "xss":                      { effect: "it is written into an HTML response",                defense: "HTML escaping for this output context" },
  "ssrf":                     { effect: "it controls the destination of an outbound request", defense: "a host allowlist" },
  "open-redirect":            { effect: "it controls a redirect destination",                 defense: "a destination allowlist" },
  "path-traversal":           { effect: "it is used as a filesystem path",                    defense: "path canonicalisation with a base-directory check" },
  "file-inclusion":           { effect: "it controls which file is included and executed",    defense: "an allowlist of includable files" },
  "eval-exec":                { effect: "it is executed as code",                             defense: "a safe alternative to dynamic evaluation" },
  "insecure-deserialization": { effect: "it is deserialised into live objects",               defense: "a data-only format" },
  "ssti":                     { effect: "it is compiled as template source",                  defense: "passing it as template data instead" },
  "ldap-injection":           { effect: "it is used in an LDAP filter",                       defense: "LDAP filter escaping" },
  "xpath-injection":          { effect: "it is used in an XPath expression",                  defense: "XPath parameterisation" },
  "header-injection":         { effect: "it is written into an HTTP response header",         defense: "CR/LF stripping" },
  "xxe":                      { effect: "it is parsed as XML with external entities enabled", defense: "disabling external entity resolution" },
  "redos":                    { effect: "it is matched by a regex prone to catastrophic backtracking", defense: "an input length limit or a linear-time pattern" },
  "prototype-pollution":      { effect: "it controls object keys in a merge or assignment",   defense: "a key allowlist or __proto__ check" },
  "mass-assignment":          { effect: "it is bound wholesale onto a data model",            defense: "an explicit field allowlist" },
  "bola-missing-ownership-check": { effect: "it selects which record is loaded",              defense: "an ownership check against the current user" },
  "idor":                     { effect: "it selects which record is loaded",                  defense: "an ownership check against the current user" },
};

// Ordered: first match wins, so the more specific shapes come first.
const INPUT_KINDS: Array<[RegExp, string]> = [
  [/\b(?:req|request)\s*\.\s*(?:query|args|GET|query_params)\b|\$_GET\b|\bQuery(?:String)?\s*\[|\bgetQueryParam|\.URL\.Query\(\)|\bc\.Query\(|\bRequest\.Query\b/, "URL query parameter"],
  [/\b(?:req|request)\s*\.\s*params\b|\bpath_params\b|\bc\.Param\(|\bPathVariable\b|\bRouteValues\b|\bmux\.Vars\(/, "URL path parameter"],
  [/\b(?:req|request)\s*\.\s*(?:body|form|POST|data|json|files|FILES)\b|\$_POST\b|\$_FILES\b|\bFormValue\(|\bPostForm\b|\bRequest\.Form\b|\bRequestBody\b|\bget_json\(/, "request body"],
  [/\b(?:req|request)\s*\.\s*(?:headers|META)\b|\bgetHeader\(|\bHeader\.Get\(|\bRequest\.Headers\b|\$_SERVER\b/, "HTTP header"],
  [/\b(?:req|request)\s*\.\s*(?:cookies|COOKIES)\b|\$_COOKIE\b|\bgetCookies\(|\bRequest\.Cookies\b|\bCookie\(/, "cookie"],
  [/\$_REQUEST\b|\bgetParameter\(|\bRequest\[/, "request parameter"],
];

export function classifyInput(expr: string | undefined): string | undefined {
  if (!expr) return undefined;
  for (const [re, kind] of INPUT_KINDS) if (re.test(expr)) return kind;
  return undefined;
}

const KIND_LABEL: Record<TraceStep["kind"], string> = {
  source: "Input", assignment: "Assigned", call: "Passed into", sanitizer: "Sanitiser",
  "cross-file": "Crosses file", sink: "Sink",
};

const BOILERPLATE_RE = /\s*—\s*real data-flow match(?: across files)?, not a line-pattern guess/g;
const GENERIC_DETAIL_RE = /^Tainted expression '([\s\S]+)' flows into ([\s\S]+?)\(\.\.\.\)$/;
// Engine-specific explanations that mention a defence which IS present but does not protect this position.
const PARTIAL_DEFENSE_RE = /\b(?:encod|escap|saniti[sz]|quot)/i;

function splitNotes(detail: string): { text: string; notes: string[] } {
  const notes: string[] = [];
  const text = detail.replace(BOILERPLATE_RE, "").replace(/\s*\[([^\]]+)\]/g, (_m, note: string) => {
    notes.push(note.trim());
    return "";
  }).trim();
  return { text, notes };
}

function stepText(s: TraceStep): string {
  // A sink's snippet is the whole call; every other step's label is the more readable form
  // (`x = rhs` for an assignment, the crossing description for a cross-file hop).
  return (s.kind === "sink" ? s.snippet || s.label : s.label || s.snippet).replace(/\s+/g, " ").trim();
}

export function buildFindingEvidence(ind: FileIndicator, filePath: string, siblings: readonly FileIndicator[] = []): FindingEvidence {
  const trace = ind.trace ?? [];
  const isDataFlow = trace.length > 0 || !!ind.sourceExpr;
  const sink = SINK_SEMANTICS[ind.id];
  const { text: detailText, notes } = splitNotes(ind.detail ?? "");

  const flow: FlowStep[] = trace
    .map(s => ({
      kind: s.kind,
      kindLabel: KIND_LABEL[s.kind] ?? s.kind,
      text: stepText(s),
      line: s.line,
      otherFile: s.file && s.file !== filePath ? s.file : undefined,
    }))
    .filter((s, i, all) => s.text && (i === 0 || s.text !== all[i - 1].text || s.line !== all[i - 1].line));
  let flowFromEndpointsOnly = false;
  if (flow.length === 0 && ind.sourceExpr && ind.sinkExpr) {
    flowFromEndpointsOnly = true;
    flow.push(
      { kind: "source", kindLabel: KIND_LABEL.source, text: ind.sourceExpr },
      { kind: "sink", kindLabel: KIND_LABEL.sink, text: `${ind.sinkExpr}(…)`, line: ind.line },
    );
  }

  const origin = flow.find(s => s.kind === "source")?.text ?? ind.sourceExpr;
  const inputKind = classifyInput(origin) ?? classifyInput(ind.sourceExpr);

  // ── One-sentence explanation ──
  let summary: Part[];
  const generic = GENERIC_DETAIL_RE.exec(detailText);
  if (isDataFlow && (generic || !detailText)) {
    // Name where the value came from (the trace origin), not the expression that finally hit the sink --
    // that is often a local like `sql`, or the whole concatenation built from the input.
    const arg = generic?.[1] ?? ind.sourceExpr ?? "";
    const shown = origin ?? arg;
    const sinkName = generic?.[2] ?? ind.sinkExpr ?? "";
    summary = [inputKind ? "Untrusted input " : "Tainted value ", { code: shown }];
    if (inputKind) summary.push(` (${inputKind})`);
    if (shown !== arg && /^\$?[A-Za-z_]\w*$/.test(arg)) summary.push(" flows via ", { code: arg }, " into ", { code: `${sinkName}()` });
    else summary.push(" reaches ", { code: `${sinkName}()` });
    summary.push(sink ? `, where ${sink.effect}.` : ".");
  } else if (detailText) {
    summary = [detailText];
  } else {
    summary = [ind.label];
  }

  let onPathOf: FindingEvidence["onPathOf"];
  if (!isDataFlow && ind.line != null) {
    for (const sib of siblings) {
      if (sib === ind || sib.id !== ind.id || sib.line === ind.line || !sib.trace?.length) continue;
      const steps = sib.trace.filter(s => !s.file || s.file === filePath);
      const at = steps.findIndex(s => s.line === ind.line);
      if (at >= 0 && sib.line != null) { onPathOf = { line: sib.line, step: at + 1, steps: sib.trace.length }; break; }
    }
  }

  // ── Why this was flagged ──
  const checks: EvidenceCheck[] = [];
  if (isDataFlow) {
    if (origin) {
      checks.push(inputKind
        ? { tone: "confirmed", parts: [`Starts at untrusted input (${inputKind}): `, { code: origin }] }
        : { tone: "confirmed", parts: ["Starts at a value the engine tracks as tainted: ", { code: origin }] });
    }
    const hops = flow.filter(s => s.kind === "assignment" || s.kind === "call").length;
    if (hops > 0) checks.push({ tone: "confirmed", parts: [`Carried through ${hops} intermediate step${hops === 1 ? "" : "s"} without losing taint`] });
    for (const s of flow) {
      if (s.kind === "cross-file") checks.push({ tone: "confirmed", parts: ["Crosses a file boundary: ", { code: s.text }] });
      if (s.kind === "sanitizer") checks.push({ tone: "caution", parts: ["Passes through ", { code: s.text }, ", which does not neutralise this sink"] });
    }
    for (const n of notes) {
      if (/^crosses file boundary/i.test(n)) checks.push({ tone: "confirmed", parts: [n.charAt(0).toUpperCase() + n.slice(1)] });
      else if (/^input assumed untrusted/i.test(n)) checks.push({ tone: "caution", parts: [n.charAt(0).toUpperCase() + n.slice(1)] });
      else checks.push({ tone: "neutral", parts: [n] });
    }
    if (ind.sinkExpr) {
      checks.push({ tone: "confirmed", parts: sink
        ? ["Reaches ", { code: `${ind.sinkExpr}()` }, `, where ${sink.effect}`]
        : ["Reaches the sink ", { code: `${ind.sinkExpr}()` }] });
    }
    if (sink) {
      checks.push(!generic && PARTIAL_DEFENSE_RE.test(detailText)
        ? { tone: "caution", parts: ["A defence is applied, but not one that protects this position (see explanation)"] }
        : { tone: "absent", parts: [`No ${sink.defense} on this path`] });
    }
  } else {
    checks.push({ tone: "confirmed", parts: [`Matches the ${ind.label} detection pattern on this line`] });
    for (const n of notes) checks.push({ tone: "neutral", parts: [n] });
    if (onPathOf) {
      checks.push({ tone: "confirmed", parts: [`This line is step ${onPathOf.step} of ${onPathOf.steps} on the confirmed data-flow path of the finding at line ${onPathOf.line}`] });
    } else {
      checks.push({ tone: "caution", parts: ["Pattern match only — no source-to-sink data flow was traced for this finding"] });
    }
  }

  if (ind.supportingDetectors?.length) {
    const n = ind.supportingDetectors.length;
    checks.push({ tone: "confirmed", parts: [`Independently flagged by ${n} other detector${n === 1 ? "" : "s"}: ${ind.supportingDetectors.join(", ")}`] });
  }
  switch (ind.reachability) {
    case "entry-point":  checks.push({ tone: "confirmed", parts: ["Runs directly inside a request handler / entry point"] }); break;
    case "tainted-path": checks.push({ tone: "confirmed", parts: ["Call graph confirms tainted data reaches this code from an entry point"] }); break;
    case "reachable":    checks.push({ tone: "confirmed", parts: ["Reachable from an entry point via the call graph"] }); break;
    case "unreachable":  checks.push({ tone: "caution",   parts: ["No call path from an entry point was found — possibly dead code"] }); break;
  }

  return {
    isDataFlow,
    analysisLabel: isDataFlow ? "AST data-flow" : "Pattern match",
    summary,
    inputKind,
    flow,
    flowFromEndpointsOnly,
    checks,
    onPathOf,
  };
}
