/**
 * Canonical data-flow evidence: ONE structured description of a source -> sink flow, built once from the
 * engine's trace (see analyzeFile) and stored with the finding, so every surface -- the PR page, check-run
 * annotations, PR comments, SARIF, and the scan-wide correlation pass -- reads the same facts:
 *
 *  - where the flow starts, and whether that is real request input or an ASSUMED-untrusted parameter;
 *  - the exact sink (file, line, call) and the ROLE of the argument that reached it ("the SQL query text");
 *  - every file the value passes through, in order;
 *  - every sanitiser on the path, what it neutralises, and whether that protects THIS sink;
 *  - a canonical sink identity (`sinkKey`), so two findings reported in different files for the same sink
 *    are recognisably the same issue.
 *
 * Pure and client-safe (no server imports).
 */
import type { TraceStep } from "./taint/taintCore";
import { SinkClass, classOf } from "./taint/taintCore";
import { sanitizerClears, type SanitizerLang } from "./taint/sanitizers";

export interface DataFlowEvidence {
  source: {
    file: string; line: number; expr: string;
    /** What kind of request input it is ("URL query parameter"), when recognisable. */
    inputKind?: string;
    /** True when the flow starts at a value the engine only ASSUMES is untrusted (a service method's parameter),
     * not at request input it saw being read. */
    assumed: boolean;
  };
  sink: {
    file: string; line: number; expr: string;
    /** The argument of the sink the value reaches, by role: "the SQL query text", "the request URL", ... */
    role: string;
    cwe?: string;
  };
  /** Files the value passes through, in path order (first = the source's). */
  files: string[];
  crossesFiles: boolean;
  /** Intermediate steps between source and sink. */
  hops: number;
  sanitizers: SanitizerEvidence[];
  /** Canonical identity of the sink: the same sink reported from two files has the same key. */
  sinkKey: string;
}

export interface SanitizerEvidence {
  file: string;
  line: number;
  /** The sanitising call as written, e.g. "htmlspecialchars". */
  call: string;
  /** What it neutralises, in words ("HTML output", "SQL string contents", ...). */
  neutralises: string[];
  /** Whether it neutralises this finding's sink class (if so, the finding stands for another reason --
   * typically the value lands where that escaping does not apply). */
  protectsSink: boolean;
}

// ── Exact sink modeling: which argument of the sink the value reached, by role ──
export const SINK_ROLE: Record<string, string> = {
  "sql-injection": "the SQL query text",
  "nosql-injection": "the query filter document",
  "command-injection": "the command line (or program) that runs",
  "argument-injection": "an argument passed to another program",
  "xss": "the HTML written to the response",
  "ssrf": "the request's destination (URL / host)",
  "open-redirect": "the redirect location",
  "path-traversal": "the file path",
  "file-inclusion": "the path of the file included and executed",
  "eval-exec": "the code that is evaluated",
  "insecure-deserialization": "the data being deserialised",
  "ssti": "the template source",
  "ldap-injection": "the LDAP search filter",
  "xpath-injection": "the XPath expression",
  "header-injection": "the response header value",
  "xxe": "the XML document",
  "redos": "the regular expression pattern",
  "mass-assignment": "the fields bound onto the model",
  "bola-missing-ownership-check": "the id of the record loaded",
  "idor": "the id of the record loaded",
  "timing-attack": "a value compared against a secret",
};

const CLASS_WORDS: Array<[number, string]> = [
  [SinkClass.SQL, "SQL string contents"], [SinkClass.CMD, "shell commands"], [SinkClass.XSS, "HTML output"],
  [SinkClass.SSRF, "URLs"], [SinkClass.PATH, "file paths"], [SinkClass.REDIRECT, "redirects"],
  [SinkClass.DESERIAL, "deserialisation"], [SinkClass.INCLUDE, "file includes"], [SinkClass.LDAP, "LDAP filters"],
  [SinkClass.XPATH, "XPath"], [SinkClass.NOSQL, "NoSQL operators"], [SinkClass.HEADER, "HTTP headers"],
  [SinkClass.EVAL, "code evaluation"], [SinkClass.SSTI, "template source"],
];

/** Words for a sanitiser's cleared classes; a numeric conversion clears them all. */
export function describeClears(clears: number): string[] {
  const words = CLASS_WORDS.filter(([bit]) => clears & bit).map(([, w]) => w);
  return words.length >= CLASS_WORDS.length - 1 ? ["every injection class (numeric conversion)"] : words;
}

// ── Where a flow starts ──
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


// ── Sanitiser detection on the path ──
const LANG_BY_EXT: Array<[RegExp, SanitizerLang]> = [
  [/\.(?:[cm]?[jt]sx?)$/, "js"], [/\.py$/, "py"], [/\.go$/, "go"], [/\.(?:java|kt)$/, "java"], [/\.cs$/, "cs"], [/\.php\d?$/, "php"],
];
export function sanitizerLangOf(file: string): SanitizerLang | undefined {
  return LANG_BY_EXT.find(([re]) => re.test(file))?.[1];
}

// A call as written: `a.b.c(`, `$obj->method(`, `Cls::method(` -- the callee text and where its args start.
const CALL_RE = /((?:\$?[A-Za-z_][\w]*)(?:\s*(?:\.|->|::)\s*[A-Za-z_][\w]*)*)\s*\(/g;

/** The argument texts of the call whose `(` is at `open`, split at top-level commas (best-effort). */
function argsAt(text: string, open: number): string[] {
  const out: string[] = [];
  let depth = 0, cur = "", quote: string | null = null;
  for (let i = open + 1; i < text.length; i++) {
    const ch = text[i];
    if (quote) { cur += ch; if (ch === quote && text[i - 1] !== "\\") quote = null; continue; }
    if (ch === "'" || ch === '"' || ch === "`") { quote = ch; cur += ch; continue; }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    if (ch === ")" || ch === "]" || ch === "}") { if (depth === 0) { out.push(cur.trim()); return out; } depth--; }
    if (ch === "," && depth === 0) { out.push(cur.trim()); cur = ""; continue; }
    cur += ch;
  }
  return out;
}

/** Known sanitiser calls in one step's code, with the classes each neutralises. */
function sanitizersIn(step: TraceStep, lang: SanitizerLang): Array<{ call: string; clears: number }> {
  const found: Array<{ call: string; clears: number }> = [];
  for (const text of new Set([step.snippet, step.label])) {
    if (!text) continue;
    CALL_RE.lastIndex = 0;
    for (let m = CALL_RE.exec(text); m; m = CALL_RE.exec(text)) {
      const callee = m[1].replace(/\s+/g, "").replace(/->|::/g, ".");
      const clears = sanitizerClears(lang, callee, argsAt(text, m.index + m[0].length - 1));
      if (clears && !found.some(f => f.call === callee)) found.push({ call: callee, clears });
    }
  }
  return found;
}

/**
 * Marks the steps of `trace` that pass the value through a known sanitiser as `sanitizer` steps (in place of a
 * generic call/assignment step) and returns what each one neutralises. The engines already decided whether
 * taint survives; this only makes the sanitiser VISIBLE on the path.
 */
export function annotateSanitizers(trace: TraceStep[], sinkId: string): SanitizerEvidence[] {
  const sinkClass = classOf(sinkId);
  const out: SanitizerEvidence[] = [];
  trace.forEach((step, i) => {
    if (step.kind === "source" || step.kind === "sink" || step.kind === "parameter") return;
    const lang = sanitizerLangOf(step.file);
    if (!lang) return;
    const hits = sanitizersIn(step, lang);
    if (hits.length === 0) return;
    for (const h of hits) {
      out.push({ file: step.file, line: step.line, call: h.call, neutralises: describeClears(h.clears), protectsSink: !!(h.clears & sinkClass) });
    }
    if (step.kind === "assignment" || step.kind === "call") trace[i] = { ...step, kind: "sanitizer" };
  });
  return out;
}

/** A line of one file that another file's data flow passes through (or whose finding was folded into it). */
export interface CrossFileMark {
  line: number;
  /** The finding (in another file) whose path runs here. */
  fromFile: string;
  fromLine: number;
  /** That finding's title, e.g. "SQL Injection". */
  title: string;
  /** What this line is on that path. */
  role: "parameter" | "step" | "sink" | "merged";
}

interface MarkSource {
  file_path: string;
  indicators?: ReadonlyArray<{
    id: string; label: string; line?: number;
    trace?: ReadonlyArray<TraceStep>;
    relatedLocations?: ReadonlyArray<{ file?: string; line: number; reason: string }>;
  }> | null;
}

/**
 * For every file of a PR: the lines OTHER files' flows pass through, and the lines whose own finding was folded
 * into another file's (cross-file correlation). Lets a reviewer reading the callee see "the sink of the SQL
 * injection reported at users.ts:5" at the line, with a link, instead of nothing.
 */
export function crossFileMarks(files: readonly MarkSource[], titleOf: (id: string, label: string) => string = (_i, l) => l): Map<string, CrossFileMark[]> {
  const known = new Set(files.map(f => f.file_path));
  const out = new Map<string, CrossFileMark[]>();
  const push = (file: string, m: CrossFileMark) => {
    if (!known.has(file)) return;
    const list = out.get(file) ?? [];
    const same = list.find(x => x.line === m.line && x.fromFile === m.fromFile && x.fromLine === m.fromLine);
    if (!same) list.push(m);
    else if (m.role === "merged") same.role = "merged";   // a finding folded here says more than "a step"
    out.set(file, list);
  };
  for (const f of files) {
    for (const ind of f.indicators ?? []) {
      if (ind.line == null) continue;
      const title = titleOf(ind.id, ind.label);
      for (const s of ind.trace ?? []) {
        if (!s.file || s.file === f.file_path) continue;
        push(s.file, { line: s.line, fromFile: f.file_path, fromLine: ind.line, title, role: s.kind === "sink" ? "sink" : s.kind === "parameter" ? "parameter" : "step" });
      }
      for (const r of ind.relatedLocations ?? []) {
        if (r.file && r.file !== f.file_path && r.reason === "cross-file") push(r.file, { line: r.line, fromFile: f.file_path, fromLine: ind.line, title, role: "merged" });
      }
    }
  }
  for (const list of out.values()) list.sort((a, b) => a.line - b.line || a.fromFile.localeCompare(b.fromFile));
  return out;
}

/** What `buildDataFlowEvidence` reads from a finding (a structural subset of ScanIndicator / FileIndicator). */
export interface FlowInput {
  id: string;
  line?: number;
  cwe?: string;
  sourceExpr?: string;
  sinkExpr?: string;
  trace?: TraceStep[];
  /** The engine seeded the source as an assumed-untrusted parameter (it saw no request read or binding). */
  sourceAssumed?: boolean;
}

/**
 * The canonical evidence for one data-flow finding reported in `filePath`, or undefined for a finding without a
 * data flow. Marks sanitiser steps on `ind.trace` in place (see annotateSanitizers).
 */
export function buildDataFlowEvidence(ind: FlowInput, filePath: string): DataFlowEvidence | undefined {
  if (!ind.sourceExpr && !ind.trace?.length) return undefined;
  const trace = ind.trace ?? [];
  const first = trace[0];
  const last = trace[trace.length - 1];
  const sourceExpr = first?.kind === "source" ? first.label || first.snippet : ind.sourceExpr ?? "";
  const inputKind = classifyInput(sourceExpr) ?? classifyInput(ind.sourceExpr);
  const sinkStep = last?.kind === "sink" ? last : undefined;
  const sink = {
    file: sinkStep?.file || filePath,
    line: sinkStep?.line ?? ind.line ?? 0,
    expr: (sinkStep?.label || ind.sinkExpr || "").replace(/^.*\) -> /, ""),
    role: SINK_ROLE[ind.id] ?? "the sink's input",
    cwe: ind.cwe,
  };
  const files: string[] = [];
  for (const s of trace) { const f = s.file || filePath; if (files[files.length - 1] !== f && !files.includes(f)) files.push(f); }
  if (files.length === 0) files.push(filePath);
  return {
    source: {
      file: first?.file || filePath, line: first?.line ?? ind.line ?? 0, expr: sourceExpr,
      inputKind,
      // Only the engine knows: a bare name can equally be a framework-bound request parameter
      // (`@RequestParam String id`) or a parameter it assumed untrusted. Its flag, not the text, decides.
      assumed: !!ind.sourceAssumed,
    },
    sink,
    files,
    crossesFiles: files.length > 1,
    hops: Math.max(0, trace.length - 2),
    sanitizers: annotateSanitizers(trace, ind.id),
    sinkKey: `${sink.file}:${sink.line}:${ind.cwe ?? ind.id}`,
  };
}
