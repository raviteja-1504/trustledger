/**
 * Real AST-based taint and memory-safety engine for C and C++ -- the tenth engine, mirroring astTaintRust.ts /
 * astTaintKotlin.ts: sources, sinks, propagation, guards, interprocedural summaries, cross-file parameter -> sink
 * facts and source -> sink traces, plus intraprocedural memory-safety checks. Shared semantics come from
 * taint/taintCore.ts (bitmask classes, branch/loop/switch joins, traces) and taint/constEval.ts (constant sizes).
 *
 * Parsing uses tree-sitter-wasms' tree-sitter-cpp.wasm for both languages (it accepts C). Shapes confirmed by probing:
 *  - Calls are call_expression{function, arguments: argument_list}; the callee is an identifier, a qualified_identifier
 *    (`std::system`) or a field_expression{argument, field} (`obj.m()` / `p->m()`).
 *  - Declarations are declaration{type, declarator: init_declarator{declarator, value} | array_declarator{size} |
 *    pointer_declarator{declarator}}; `std::string s(x)` is init_declarator{declarator, value: argument_list}.
 *  - if_statement{condition: condition_clause{value}, consequence, alternative: else_clause}.
 *  - No preprocessor evaluation: both arms of an #ifdef are parsed as written (tree-sitter keeps them as preproc_*
 *    nodes whose children are walked in order), and macros are opaque calls.
 *
 * What is modelled (and what is not -- this is a syntax-tree engine without a compilation database):
 *  - Sources: main's argv (and wmain / WinMain's command line), getenv, stdin / file / socket reads that fill a
 *    buffer (fgets, gets, scanf family, read, recv, recvfrom, fread, ReadFile, getline, `std::cin >> s`).
 *  - Out-parameters and aliases: a read into `data + len` taints `data`, and `data = buffer` makes the two names one
 *    alias group, so a later read through either taints both.
 *  - Propagation through strcpy/strcat/memcpy/sprintf (the destination takes the source), strdup, std::string `+`,
 *    `append`, `c_str()`; atoi/strtol/... produce a number (no injection classes left, still attacker-CONTROLLED).
 *  - Sinks: command (system, popen, exec* with a shell or a tainted program), format strings (printf family with a
 *    tainted format), SQL (sqlite3 / MySQL / libpq / ODBC), paths (fopen, open, CreateFile, std::fstream), LDAP
 *    filters, libcurl URLs, dlopen / LoadLibrary, unbounded copies of input (strcpy/strcat/sprintf/scanf %s/gets),
 *    attacker-sized allocations and copy lengths with no bound check.
 *  - Memory safety within a function: use after free, double free, a malloc result dereferenced with no NULL check,
 *    malloc/new/new[] freed by the wrong deallocator, a constant copy longer than its destination array.
 *  - Not modelled: real alias/points-to analysis, template instantiation, overload resolution, macro expansion,
 *    concurrency and lifetime of C++ references -- those need a compiler front end (Clang) and the project's build.
 *
 * Runs ADDITIVELY next to the regex detectors in scanner.ts; a flow this engine proves safe vetoes their duplicate.
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Parser, Language } = require("web-tree-sitter") as typeof import("web-tree-sitter");
import type { Node as SyntaxNode, Language as LanguageT, Parser as ParserT } from "web-tree-sitter";
import { ensureTreeSitterInit, rootIfShallowEnough } from "./treeSitterRuntime";
import {
  ALL, FIXED_POINT_CAP, SinkClass, applySanitizer, buildBackwardTraceGeneric, classOf, cloneEnv, factStepsFromTrace,
  mergeSinkFacts, dropOnPathDuplicates, crossFileTrace, displayFnName, walkIfChain, walkLoop, walkSwitch, walkTry, wasCleared,
  type Branch, type Guard, type ParamSinkFact, type SuppressedSink, type TaintEnv, type TraceResolver, type TraceStep,
} from "./taint/taintCore";
import { NUMERIC_CLEARS } from "./taint/sanitizers";
import { evalConstExpr } from "./taint/constEval";

declare const __non_webpack_require__: NodeJS.Require | undefined;
function nodeRequire(): NodeJS.Require {
  // eslint-disable-next-line no-undef
  return typeof __non_webpack_require__ !== "undefined" ? __non_webpack_require__ : require;
}

export type AstTaintCppId =
  | "command-injection" | "sql-injection" | "path-traversal" | "format-string" | "buffer-overflow" | "ldap-injection"
  | "ssrf" | "eval-exec" | "integer-overflow" | "use-after-free" | "double-free" | "null-dereference"
  | "mismatched-deallocation" | "insecure-temp-file";

export interface AstTaintCppFinding {
  id: AstTaintCppId;
  line: number;
  detail: string;
  sourceExpr: string;
  sinkExpr: string;
  entryPointSeeded?: boolean;
  trace?: TraceStep[];
  calleeSink?: { file: string; line: number; sinkExpr: string; via: string[] };
}

const SEVERITY: Record<AstTaintCppId, "critical" | "high" | "medium"> = {
  "command-injection": "critical", "sql-injection": "critical", "path-traversal": "high", "format-string": "high",
  "buffer-overflow": "critical", "ldap-injection": "high", "ssrf": "high", "eval-exec": "critical", "integer-overflow": "high",
  "use-after-free": "critical", "double-free": "high", "null-dereference": "medium", "mismatched-deallocation": "medium",
  "insecure-temp-file": "medium",
};
const LABEL: Record<AstTaintCppId, string> = {
  "command-injection": "Command Injection", "sql-injection": "SQL Injection", "path-traversal": "Path Traversal",
  "format-string": "Format String Injection", "buffer-overflow": "Buffer Overflow", "ldap-injection": "LDAP Injection",
  "ssrf": "Server-Side Request Forgery", "eval-exec": "Untrusted Library Load", "integer-overflow": "Uncontrolled Size",
  "use-after-free": "Use After Free", "double-free": "Double Free", "null-dereference": "NULL Dereference",
  "mismatched-deallocation": "Mismatched Deallocation", "insecure-temp-file": "Insecure Temporary File",
};
export function astTaintCppSeverity(id: AstTaintCppId): "critical" | "high" | "medium" { return SEVERITY[id]; }
export function astTaintCppLabel(id: AstTaintCppId): string { return LABEL[id]; }

// ── Parser lifecycle (warm-cache pattern, see astTaintRust.ts) ─────────────────────────────────────────────────

let langPromise: Promise<LanguageT> | null = null;
let parserPool: ParserT | null = null;

function initCppParser(): Promise<LanguageT> {
  if (!langPromise) {
    langPromise = (async () => {
      await ensureTreeSitterInit();
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require("fs") as typeof import("fs");
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const path = require("path") as typeof import("path");
      const nodeModulesDir = path.dirname(path.dirname(nodeRequire().resolve("web-tree-sitter")));
      const wasmPath = path.join(nodeModulesDir, "tree-sitter-wasms", "out", "tree-sitter-cpp.wasm");
      const lang = await Language.load(new Uint8Array(fs.readFileSync(wasmPath)));
      const p = new Parser();
      p.setLanguage(lang);
      parserPool = p;
      console.log("[astTaintCpp] C/C++ AST taint engine ready");
      return lang;
    })().catch(err => {
      console.error("[astTaintCpp] WASM init failed -- C/C++ AST scanning disabled, regex detectors unaffected:", err);
      throw err;
    });
  }
  return langPromise;
}
if (!process.env.JEST_WORKER_ID) {
  void initCppParser().catch(() => { /* already logged above */ });
}

export function isCppParserReady(): boolean { return parserPool !== null; }
export async function warmCppTaintEngine(): Promise<void> {
  await initCppParser().catch(() => { /* already logged; callers just proceed regex-only */ });
}
export function parseCppSourceSync(content: string, filePath: string): SyntaxNode | null {
  if (!parserPool) return null;
  try {
    return rootIfShallowEnough(parserPool.parse(content)?.rootNode, "astTaintCpp", filePath);
  } catch (err) {
    console.error(`[astTaintCpp] parse threw for ${filePath}:`, err);
    return null;
  }
}

export function findNodeAtRowCpp(root: SyntaxNode, row: number): SyntaxNode {
  let node = root;
  for (;;) {
    const child = node.namedChildren.find(c => c && row >= c.startPosition.row && row <= c.endPosition.row);
    if (!child) return node;
    node = child;
  }
}
export function findEnclosingFunctionNameCpp(node: SyntaxNode): string {
  for (let cur: SyntaxNode | null = node; cur; cur = cur.parent) {
    if (cur.type === "function_definition") return functionName(cur) ?? "unknown";
  }
  return "unknown";
}

// ── Tree helpers ───────────────────────────────────────────────────────────────────────────────────────────

const lineOf = (n: SyntaxNode) => n.startPosition.row + 1;
const named = (n: SyntaxNode | null | undefined): SyntaxNode[] => (n ? n.namedChildren.filter((c): c is SyntaxNode => !!c && c.type !== "comment") : []);
const field = (n: SyntaxNode | null | undefined, f: string): SyntaxNode | null => n?.childForFieldName(f) ?? null;

function findAllNodes(root: SyntaxNode, type: string | ReadonlySet<string>, acc: SyntaxNode[] = []): SyntaxNode[] {
  if (typeof type === "string" ? root.type === type : type.has(root.type)) acc.push(root);
  for (const c of root.namedChildren) if (c) findAllNodes(c, type, acc);
  return acc;
}
function operatorOf(n: SyntaxNode): string {
  const op = n.childForFieldName("operator");
  if (op) return op.type;
  for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c && !c.isNamed) return c.type; }
  return "";
}

/** The name a declarator declares (`*p`, `buf[100]`, `&r`, `p = ...`). */
function declaredName(d: SyntaxNode | null): string | null {
  if (!d) return null;
  if (d.type === "identifier" || d.type === "field_identifier") return d.text;
  if (d.type === "qualified_identifier") return field(d, "name")?.text ?? null;
  const inner = field(d, "declarator") ?? named(d).find(c => /declarator|identifier/.test(c.type)) ?? null;
  return inner && inner !== d ? declaredName(inner) : null;
}
function functionName(fn: SyntaxNode): string | null {
  let d = field(fn, "declarator");
  while (d && d.type !== "function_declarator") d = field(d, "declarator");
  const nm = d ? field(d, "declarator") : null;
  if (!nm) return null;
  if (nm.type === "qualified_identifier") return field(nm, "name")?.text ?? nm.text;
  return nm.text;
}

/** The variable an argument names (`data`, `&data`, `data + len`, `(char *)data`, `*p`, `buf[i]`, `s.f`). */
function rootName(e: SyntaxNode | null): string | null {
  if (!e) return null;
  switch (e.type) {
    case "identifier": return e.text;
    case "parenthesized_expression": return rootName(named(e)[0] ?? null);
    case "cast_expression": return rootName(field(e, "value"));
    case "pointer_expression": return rootName(field(e, "argument"));
    case "subscript_expression": return rootName(field(e, "argument"));
    case "binary_expression": return operatorOf(e) === "+" || operatorOf(e) === "-" ? rootName(field(e, "left")) : null;
    case "field_expression": {
      const base = rootName(field(e, "argument"));
      const f = field(e, "field")?.text;
      return base && f ? `${base}.${f}` : base;
    }
    case "update_expression": return rootName(field(e, "argument"));
    default: return null;
  }
}

interface CallInfo { name: string; recv: SyntaxNode | null; args: SyntaxNode[] }
function callInfo(call: SyntaxNode): CallInfo {
  const fn = field(call, "function");
  const args = named(field(call, "arguments"));
  if (fn?.type === "field_expression") return { name: field(fn, "field")?.text ?? "", recv: field(fn, "argument"), args };
  if (fn?.type === "qualified_identifier") return { name: (field(fn, "name")?.text ?? fn.text).replace(/^::/, ""), recv: null, args };
  if (fn?.type === "template_function") return { name: field(fn, "name")?.text ?? "", recv: null, args };
  return { name: fn?.text ?? "", recv: null, args };
}
/**
 * Object-like macros of the file being scanned (`#define GETENV getenv`, `#define COMMAND_ARG1 "-c"`): the first
 * definition wins, so of an #ifdef _WIN32 / #else pair the first arm is used. Set by makeCtx; every scan of a file
 * is synchronous from makeCtx to its last walk, so one module-level table is never shared by two files at once.
 */
let MACROS: ReadonlyMap<string, string> = new Map();
function collectMacros(root: SyntaxNode): Map<string, string> {
  const out = new Map<string, string>();
  for (const d of findAllNodes(root, "preproc_def")) {
    const nm = field(d, "name")?.text, v = field(d, "value")?.text.trim();
    if (nm && v && !out.has(nm)) out.set(nm, v);
  }
  return out;
}
const STRING_MACRO_RE = /^(?:[LuU8]*"(?:[^"\\]|\\.)*"\s*)+$/;
/** `CreateFileA` / `ldap_search_ext_sW` / `_wfopen` / `EXECL` (#define'd to execl) -> the base API name. */
const baseApi = (name: string) => {
  const m = MACROS.get(name);
  const real = m && /^[A-Za-z_]\w*$/.test(m) ? m : name;
  return real.replace(/^(?:_|std::)/, "").replace(/(?<=[a-z_])[AW]$/, "");
};

function stringValue(n: SyntaxNode | null | undefined): string | null {
  if (!n) return null;
  if (n.type === "string_literal") return n.text.replace(/^[LuU8]*"/, "").replace(/"$/, "");
  if (n.type === "concatenated_string") return named(n).map(s => stringValue(s) ?? "").join("");
  if (n.type === "identifier") {
    const m = MACROS.get(n.text);
    if (m && STRING_MACRO_RE.test(m)) return [...m.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(x => x[1]).join("");
  }
  return null;
}

// ── Engine state ───────────────────────────────────────────────────────────────────────────────────────────

type Env = TaintEnv;

interface LocalFn { name: string; decl: SyntaxNode; body: SyntaxNode | null; params: Array<{ name: string; index: number }>; isStatic: boolean }

interface EngineCtx {
  filePath: string;
  content: string;
  lines: string[];
  root: SyntaxNode;
  fns: Map<string, LocalFn>;
  /** fn -> (param index -> classes surviving to the return value) */
  propagating: Map<string, Map<number, number>>;
  /** fn -> classes its return carries regardless of arguments (it reads input itself) */
  intrinsic: Map<string, number>;
  /** fn -> (param index -> classes tainted at some call site) */
  seeded: Map<string, Map<number, number>>;
  suppressed?: SuppressedSink[];
  findings: AstTaintCppFinding[];
  seen: Set<string>;
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>;
  /** per walk of one function: name -> alias group id; array name -> capacity in bytes */
  aliases: Map<string, string>;
  capacity: Map<string, number>;
  /** fn -> (param index -> memory state at some call site: "alloc" kind, "unchecked") */
  seededMem: Map<string, Map<number, Map<string, number>>>;
  /** fn -> indices of the pointer parameters it frees (free(p) / delete p, directly or through another local fn) */
  freesParam: Map<string, Map<number, Release>>;
  /** per walk: alias group -> characters in the string the buffer holds, when known */
  strLen: Map<string, number>;
  /** per walk: local function pointer -> the function it was initialised with */
  fnAlias: Map<string, string>;
  /** file-scope variables, and the classes any real (non-speculative) walk stored into each */
  globalNames: Set<string>;
  globalTaint: Map<string, number>;
  /** a walk with parameters seeded hypothetically (summaries, facts): its writes to globals are not real */
  speculative: boolean;
  current: LocalFn | null;
}

const KIND_KEY = (kind: string, name: string) => `!${kind}:${name}`;

function emit(ctx: EngineCtx, id: AstTaintCppId, node: SyntaxNode, sourceExpr: string, sinkExpr: string, detail?: string) {
  const line = lineOf(node);
  const key = `${id}:${line}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.findings.push({
    id, line, sinkExpr, sourceExpr,
    detail: detail ?? `Tainted expression '${sourceExpr.slice(0, 80)}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
    trace: buildBackwardTraceGeneric(ctx.filePath, node, sourceExpr, sinkExpr, cppTraceResolver),
  });
}
/** Report when `m` carries the sink's class, or record a positive proof (cleared) so the regex duplicate is vetoed. */
function fireOn(ctx: EngineCtx, id: AstTaintCppId, at: SyntaxNode, source: SyntaxNode, m: number, sinkExpr: string, cls = classOf(id), detail?: string): boolean {
  if (m & cls) { emit(ctx, id, at, source.text, sinkExpr, detail); return true; }
  if (wasCleared(m, cls)) ctx.suppressed?.push({ id, line: lineOf(at) });
  return false;
}

function enclosingScope(node: SyntaxNode): SyntaxNode | null {
  for (let cur = node.parent; cur; cur = cur.parent) if (cur.type === "function_definition" || cur.type === "lambda_expression") return cur;
  return null;
}
function assignmentsIn(scope: SyntaxNode): Array<{ name: string; position: number; rhsText: string; line: number }> {
  const out: Array<{ name: string; position: number; rhsText: string; line: number }> = [];
  const visit = (n: SyntaxNode) => {
    if (n !== scope && n.type === "function_definition") return;
    if (n.type === "init_declarator") {
      const nm = declaredName(field(n, "declarator")), v = field(n, "value");
      if (nm && v) out.push({ name: nm, position: n.startIndex, rhsText: v.text, line: lineOf(v) });
    } else if (n.type === "assignment_expression") {
      const nm = rootName(field(n, "left")), v = field(n, "right");
      if (nm && v) out.push({ name: nm, position: n.startIndex, rhsText: v.text, line: lineOf(v) });
    } else if (n.type === "call_expression") {
      // fgets(data, ...) / strcpy(dest, src): the call is the assignment that fills the buffer
      const { name, args } = callInfo(n);
      const slot = OUT_PARAM_SOURCES[baseApi(name)] ?? (COPY_INTO[baseApi(name)] !== undefined ? 0 : undefined);
      const target = slot !== undefined && slot >= 0 ? rootName(args[slot] ?? null) : null;
      if (target) out.push({ name: target.split(".")[0], position: n.startIndex, rhsText: n.text, line: lineOf(n) });
    }
    for (const c of named(n)) visit(c);
  };
  visit(scope);
  return out;
}
const cppTraceResolver: TraceResolver<SyntaxNode> = {
  enclosingScope, assignmentsIn,
  fileScope: n => { let c = n; while (c.parent) c = c.parent; return c; },
  position: n => n.startIndex, line: lineOf, text: n => n.text,
};

// ── Vocabulary ─────────────────────────────────────────────────────────────────────────────────────────────

/** Reads that fill a caller's buffer with outside data: API -> index of the buffer argument (-1: every arg after the format). */
const OUT_PARAM_SOURCES: Record<string, number> = {
  fgets: 0, fgetws: 0, gets: 0, gets_s: 0, read: 1, recv: 1, recvfrom: 1, fread: 0, ReadFile: 1, getline: 0, getdelim: 0,
  scanf: -1, wscanf: -1, fscanf: -2, fwscanf: -2, sscanf: -3, swscanf: -3, scanf_s: -1, fscanf_s: -2,
  getcwd: -9, // not a source: placeholder so the trace resolver doesn't treat it as one (see isSource below)
};
const RETURN_SOURCES = new Set(["getenv", "wgetenv","secure_getenv", "GetCommandLine", "readline"]);
/** Copies: destination argument index 0 takes the taint of the listed source arguments. */
const COPY_INTO: Record<string, number[]> = {
  strcpy: [1], strncpy: [1], strcat: [1], strncat: [1], wcscpy: [1], wcsncpy: [1], wcscat: [1], wcsncat: [1],
  memcpy: [1], memmove: [1], wmemcpy: [1], wmemmove: [1], lstrcpy: [1], lstrcat: [1], StringCbCopy: [2], StringCchCopy: [2],
  sprintf: [1, 2, 3, 4, 5, 6], swprintf: [2, 3, 4, 5, 6, 7], snprintf: [2, 3, 4, 5, 6, 7], snwprintf: [2, 3, 4, 5, 6, 7],
  vsprintf: [1, 2], vsnprintf: [2, 3], vsnwprintf: [2, 3],
  strcpy_s: [2], strcat_s: [2], strncpy_s: [2], memcpy_s: [2], wcscpy_s: [2],
};
/** Unbounded copies: writing attacker data through these overflows the destination. */
const UNBOUNDED_COPY = new Set(["strcpy", "strcat", "wcscpy", "wcscat", "sprintf", "swprintf", "vsprintf", "lstrcpy", "lstrcat"]);
const RETURN_PASSTHROUGH = new Set(["strdup", "strndup", "wcsdup", "_strdup", "_wcsdup", "strchr", "strrchr", "strstr", "strtok", "basename", "dirname", "string", "wstring", "c_str", "data", "substr", "str", "to_string"]);
const NUMERIC_CONVERSIONS = new Set(["atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll", "strtoull", "strtod", "strtof", "wcstol", "wcstoul", "_wtoi", "stoi", "stol", "stoul", "stoll", "stof", "stod"]);
const ALLOCATORS = new Set(["malloc", "calloc", "realloc", "aligned_alloc", "valloc", "alloca", "strdup", "strndup", "wcsdup"]);
/** Library calls that dereference a pointer argument (index -1: every argument): passing NULL to them crashes. */
const DEREF_ARGS: Record<string, number> = {
  strcpy: -1, strncpy: -1, strcat: -1, strncat: -1, wcscpy: -1, wcsncpy: -1, wcscat: -1, wcsncat: -1, memcpy: -1, memmove: -1,
  wmemcpy: -1, wmemmove: -1, memset: 0, wmemset: 0, strlen: 0, wcslen: 0, strcmp: -1, wcscmp: -1, sprintf: 0, swprintf: 0,
  snprintf: 0, fgets: -1, fgetws: -1, fputs: 1, fputws: 1, fprintf: 0, fwprintf: 0, fwrite: -1, fread: -1, fclose: 0, fseek: 0, fgetc: 0,
};
const FORMAT_ARG: Record<string, number> = {
  printf: 0, vprintf: 0, wprintf: 0, vwprintf: 0, fprintf: 1, vfprintf: 1, fwprintf: 1, vfwprintf: 1, dprintf: 1,
  sprintf: 1, vsprintf: 1, swprintf: 2, vswprintf: 2, snprintf: 2, vsnprintf: 2, snwprintf: 2, vsnwprintf: 2,
  syslog: 1, vsyslog: 1, err: 1, warn: 0, warnx: 0, errx: 1,
};
const SQL_ARG: Record<string, number> = {
  sqlite3_exec: 1, sqlite3_prepare: 1, sqlite3_prepare_v2: 1, sqlite3_prepare_v3: 1, sqlite3_prepare16: 1,
  mysql_query: 1, mysql_real_query: 1, PQexec: 1, PQsendQuery: 1, SQLExecDirect: 1, SQLPrepare: 1,
};
const PATH_ARG: Record<string, number> = {
  fopen: 0, freopen: 0, wfopen: 0, open: 0, openat: 1, creat: 0, CreateFile: 0, remove: 0, unlink: 0, rmdir: 0, rename: 0,
  mkdir: 0, chmod: 0, chown: 0, opendir: 0, truncate: 0, ifstream: 0, ofstream: 0, fstream: 0,
};
const LDAP_FILTER_ARG: Record<string, number> = { ldap_search: 3, ldap_search_s: 3, ldap_search_ext: 3, ldap_search_ext_s: 3, ldap_search_st: 3 };
/** Byte sizes of basic types (LP64; wchar_t as on Linux). */
const SIZEOF: Record<string, number> = {
  char: 1, "unsigned char": 1, "signed char": 1, int8_t: 1, uint8_t: 1, wchar_t: 4, short: 2, int16_t: 2, int: 4, "unsigned int": 4,
  int32_t: 4, uint32_t: 4, float: 4, long: 8, "long long": 8, int64_t: 8, uint64_t: 8, double: 8, size_t: 8,
};
const SHELL_PROGRAM_RE =/^(?:\/usr)?\/bin\/(?:ba|z|da|k)?sh$|^(?:ba|z|da|k)?sh$|cmd(?:\.exe)?$/i;

// ── Taint of an expression ─────────────────────────────────────────────────────────────────────────────────

function mask(e: SyntaxNode | null, env: Env, ctx: EngineCtx): number {
  if (!e) return 0;
  switch (e.type) {
    case "identifier": {
      // `#define COMMAND_ARG3 data`: the macro names a variable
      const m = !env.has(e.text) ? MACROS.get(e.text) : undefined;
      return groupMask(m && /^[A-Za-z_]\w*$/.test(m) ? m : e.text, env, ctx);
    }
    case "string_literal": case "raw_string_literal": case "concatenated_string": case "number_literal": case "char_literal":
    case "true": case "false": case "null": case "nullptr": case "sizeof_expression":
      return 0;
    case "parenthesized_expression": case "comma_expression":
      return named(e).reduce((m, c) => m | mask(c, env, ctx), 0);
    case "cast_expression": return mask(field(e, "value"), env, ctx);
    case "pointer_expression": return mask(field(e, "argument"), env, ctx);
    case "subscript_expression": return mask(field(e, "argument"), env, ctx);
    case "field_expression": {
      const k = rootName(e);
      return (k ? env.get(k) ?? 0 : 0) | mask(field(e, "argument"), env, ctx);
    }
    case "conditional_expression": return mask(field(e, "consequence"), env, ctx) | mask(field(e, "alternative"), env, ctx);
    case "binary_expression": {
      const op = operatorOf(e);
      // `std::cin >> s` evaluates to the stream; comparisons and logic are booleans
      if (/^(?:==|!=|<|>|<=|>=|&&|\|\||>>|<<)$/.test(op)) return 0;
      return mask(field(e, "left"), env, ctx) | mask(field(e, "right"), env, ctx);
    }
    case "unary_expression": return operatorOf(e) === "!" ? 0 : mask(field(e, "argument"), env, ctx);
    case "update_expression": return mask(field(e, "argument"), env, ctx);
    case "assignment_expression": return mask(field(e, "right"), env, ctx);
    case "initializer_list": case "argument_list": return named(e).reduce((m, c) => m | mask(c, env, ctx), 0);
    case "new_expression": return mask(field(e, "arguments"), env, ctx);
    case "call_expression": return callMask(e, env, ctx);
    default: return 0;
  }
}

function groupMask(name: string, env: Env, ctx: EngineCtx): number {
  if (!env.has(name) && ctx.globalNames.has(name)) return ctx.globalTaint.get(name) ?? 0;
  const g = ctx.aliases.get(name);
  if (!g) return env.get(name) ?? 0;
  let m = 0;
  for (const [n, gid] of ctx.aliases) if (gid === g) m |= env.get(n) ?? 0;
  return m | (env.get(name) ?? 0);
}

function callMask(call: SyntaxNode, env: Env, ctx: EngineCtx): number {
  const { name, recv, args } = callInfo(call);
  const api = baseApi(name);
  if (RETURN_SOURCES.has(api)) return ALL;
  if (NUMERIC_CONVERSIONS.has(api)) return applySanitizer(mask(args[0] ?? null, env, ctx), NUMERIC_CLEARS);
  if (RETURN_PASSTHROUGH.has(api)) return recv ? mask(recv, env, ctx) : mask(args[0] ?? null, env, ctx);
  if (recv && /^(?:append|insert|replace|assign|operator\+=)$/.test(api)) return mask(recv, env, ctx) | args.reduce((m, a) => m | mask(a, env, ctx), 0);
  // a local function: what its return carries from these arguments, plus what it reads itself
  const target = ctx.fnAlias.get(name) ?? name;
  const fn = !recv ? ctx.fns.get(target) : undefined;
  if (fn) {
    let m = ctx.intrinsic.get(target) ?? 0;
    const prop = ctx.propagating.get(target);
    if (prop) for (const [i, surviving] of prop) m |= mask(args[i] ?? null, env, ctx) & surviving;
    return m;
  }
  return 0;
}

// ── Guards: `if (n < 100)` bounds a size; `if (strchr(data, ';') != NULL) return` ... ─────────────────────

/** Bound checks on a size variable: in the arm where `n` is at most a constant (or at least 0 and below one). */
function guardsOf(cond: SyntaxNode | null, ctx: EngineCtx): Guard[] {
  if (!cond) return [];
  const e = cond.type === "condition_clause" ? field(cond, "value") : cond;
  if (!e) return [];
  if (e.type === "parenthesized_expression") return guardsOf(named(e)[0] ?? null, ctx);
  if (e.type === "unary_expression" && operatorOf(e) === "!") {
    return guardsOf(field(e, "argument"), ctx).map(g => ({ ...g, holds: g.holds === "true" ? "false" : "true" }));
  }
  if (e.type !== "binary_expression") return [];
  const op = operatorOf(e);
  if (op === "&&") return [...guardsOf(field(e, "left"), ctx), ...guardsOf(field(e, "right"), ctx)].filter(g => g.holds === "true");
  const l = field(e, "left"), r = field(e, "right");
  const ln = l?.type === "identifier" ? l.text : null, rn = r?.type === "identifier" ? r.text : null;
  const isBound = (n: SyntaxNode | null) => !!n && (n.type === "number_literal" || n.type === "sizeof_expression" || /^[A-Z_][A-Z0-9_]*$/.test(n.text)
    || (n.type === "identifier" && !!ctx.current && !ctx.current.params.some(p => p.name === n.text)));
  const SIZE = SinkClass.CONTROL;
  // n < K / n <= K: bounded where true; n > K / n >= K: bounded where false; K > n / K >= n mirror
  if (ln && isBound(r)) {
    if (op === "<" || op === "<=") return [{ name: ln, holds: "true", clears: SIZE }];
    if (op === ">" || op === ">=") return [{ name: ln, holds: "false", clears: SIZE }];
  }
  if (rn && isBound(l)) {
    if (op === ">" || op === ">=") return [{ name: rn, holds: "true", clears: SIZE }];
    if (op === "<" || op === "<=") return [{ name: rn, holds: "false", clears: SIZE }];
  }
  return [];
}

// ── Statement walker ───────────────────────────────────────────────────────────────────────────────────────

interface WalkOpts { onReturn?: (e: SyntaxNode | null, env: Env) => void; quiet?: boolean }

function createWalker(ctx: EngineCtx, opts: WalkOpts) {
  const m = (e: SyntaxNode | null, env: Env) => mask(e, env, ctx);

  const setVar = (name: string, value: number, env: Env, orInto: boolean) => {
    env.set(name, orInto ? (env.get(name) ?? 0) | value : value);
  };
  /** Taint a buffer through an out-parameter: every name in its alias group. */
  const taintBuffer = (name: string, value: number, env: Env) => {
    const base = name.split(".")[0];
    const g = ctx.aliases.get(base);
    env.set(name, (env.get(name) ?? 0) | value);
    if (name !== base) env.set(base, (env.get(base) ?? 0) | value);
    if (g) for (const [n, gid] of ctx.aliases) if (gid === g) env.set(n, (env.get(n) ?? 0) | value);
  };
  const alias = (a: string, b: string) => {
    const gid = ctx.aliases.get(b) ?? ctx.aliases.get(a) ?? b;
    ctx.aliases.set(a, gid); ctx.aliases.set(b, gid);
    const cap = ctx.capacity.get(b);
    if (cap !== undefined) ctx.capacity.set(a, cap);
  };

  // ── buffer sizes: capacity (bytes) per name, known string length (characters) per alias group ──
  const groupKey = (n: string) => ctx.aliases.get(n) ?? n;
  /** Known length of a literal or buffer, without falling back to capacity (for tracking, not for sizing). */
  const strLenOfName = (e: SyntaxNode | null): number | undefined => {
    const lit = stringValue(e);
    if (lit !== null) return lit.replace(/\\./g, "x").length;
    return e?.type === "identifier" ? ctx.strLen.get(groupKey(e.text)) : undefined;
  };
  const setLen = (n: string, len: number | undefined) => { if (len === undefined) ctx.strLen.delete(groupKey(n)); else ctx.strLen.set(groupKey(n), len); };
  /** A constant byte count: sizeof of basic types, and strlen/wcslen of a buffer whose length is known. */
  const constBytes = (text: string): number | undefined => {
    let unknown = false;
    const t = text
      .replace(/\b(?:strlen|wcslen)\s*\(\s*(\w+)\s*\)/g, (_, v: string) => { const n = ctx.strLen.get(groupKey(v)); if (n === undefined) unknown = true; return String(n ?? 0); })
      .replace(/sizeof\s*\(\s*([\w\s]+?)\s*\)/g, (_, ty: string) => {
        const b = SIZEOF[ty.replace(/\s+/g, " ")] ?? ctx.capacity.get(ty.trim()); // sizeof(buf) of a known array
        if (b === undefined) unknown = true;
        return String(b ?? 0);
      });
    if (unknown) return undefined;
    const v = evalConstExpr(t, () => undefined);
    return typeof v === "number" ? v : undefined;
  };

  // ── memory-state bookkeeping (env keys `!freed:p`, `!alloc:p`, `!unchecked:p`) ──
  /** >0 while walkLoop re-runs a body to reach its fixed point: memory states are still tracked there, but a
   * free/use seen only on that hypothetical second pass (`for (j = 0; j < 1; j++) free(p);`) is not reported. */
  let loopRepeat = 0;
  const loopBody = (f: (e: Env) => boolean) => {
    let pass = 0;
    return (e: Env) => {
      const repeat = ++pass > 1;
      if (repeat) loopRepeat++;
      try { return f(e); } finally { if (repeat) loopRepeat--; }
    };
  };
  /** `char *copy = data;`: the copy is the same allocation, in the same state. */
  const copyMemory = (to: string, from: SyntaxNode | null, env: Env) => {
    let s = from;
    while (s && (s.type === "cast_expression" || s.type === "parenthesized_expression")) s = s.type === "cast_expression" ? field(s, "value") : named(s)[0] ?? null;
    if (s?.type !== "identifier" || s.text === to) return;
    for (const k of ["freed", "alloc", "unchecked"]) {
      const v = env.get(KIND_KEY(k, s.text));
      if (v) env.set(KIND_KEY(k, to), v);
    }
  };
  const ALLOC_MALLOC = 1, ALLOC_NEW = 2, ALLOC_NEW_ARRAY = 4;
  const allocKindOf = (v: SyntaxNode | null): number => {
    let e = v;
    while (e && (e.type === "cast_expression" || e.type === "parenthesized_expression")) e = e.type === "cast_expression" ? field(e, "value") : named(e)[0] ?? null;
    if (!e) return 0;
    if (e.type === "new_expression") return field(e, "declarator")?.type === "new_declarator" || /\[/.test(e.text.split("(")[0]) ? ALLOC_NEW_ARRAY : ALLOC_NEW;
    if (e.type === "call_expression" && ALLOCATORS.has(baseApi(callInfo(e).name))) return ALLOC_MALLOC;
    return 0;
  };
  const resetMemory = (name: string, env: Env) => {
    env.delete(KIND_KEY("freed", name)); env.delete(KIND_KEY("alloc", name)); env.delete(KIND_KEY("unchecked", name)); env.delete(KIND_KEY("tmpname", name));
  };
  const recordAlloc = (name: string, value: SyntaxNode | null, env: Env) => {
    resetMemory(name, env);
    let g = value;
    while (g && (g.type === "cast_expression" || g.type === "parenthesized_expression")) g = g.type === "cast_expression" ? field(g, "value") : named(g)[0] ?? null;
    if (g?.type === "call_expression" && /^w?(?:tmpnam|tempnam|mktemp)$/.test(baseApi(callInfo(g).name))) env.set(KIND_KEY("tmpname", name), 1);
    // fopen reports failure as NULL too
    if (g?.type === "call_expression" && /^w?fopen$/.test(baseApi(callInfo(g).name))) env.set(KIND_KEY("unchecked", name), 1);
    const kind = allocKindOf(value);
    if (!kind) return;
    env.set(KIND_KEY("alloc", name), kind);
    // malloc/calloc/realloc report failure as NULL (new throws instead; alloca never returns NULL)
    if (kind === ALLOC_MALLOC && !(g?.type === "call_expression" && /^_?alloca$/.test(baseApi(callInfo(g).name)))) env.set(KIND_KEY("unchecked", name), 1);
    // `new char[n]` / `malloc(n)` with an attacker-chosen n and no bound check
    let e = value;
    while (e && (e.type === "cast_expression" || e.type === "parenthesized_expression")) e = e.type === "cast_expression" ? field(e, "value") : named(e)[0] ?? null;
    const sizeArg = e?.type === "call_expression" ? callInfo(e).args[baseApi(callInfo(e).name) === "realloc" ? 1 : 0] ?? null
      // `new char[n]`: the expression inside the brackets
      : e?.type === "new_expression" ? (() => { const d = findAllNodes(e, "new_declarator")[0]; return d ? field(d, "length") ?? named(d)[0] ?? null : null; })() : null;
    // a constant size is the buffer's capacity: malloc(50*sizeof(char)), calloc(50, 1), new wchar_t[50]
    if (sizeArg && e) {
      const ci = e.type === "call_expression" ? callInfo(e) : null;
      const bytes = ci && baseApi(ci.name) === "calloc" && ci.args[1] ? constBytes(`(${ci.args[0]?.text})*(${ci.args[1].text})`)
        : ci ? constBytes(sizeArg.text)
        : (() => { const n = constBytes(sizeArg.text); const el = SIZEOF[field(e, "type")?.text ?? ""]; return n !== undefined && el ? n * el : undefined; })();
      if (bytes !== undefined) ctx.capacity.set(name, bytes);
    }
    if (sizeArg && !opts.quiet) fireOn(ctx, "integer-overflow", e!, sizeArg, m(sizeArg, env), "allocation size", SinkClass.CONTROL,
      `Attacker-controlled '${sizeArg.text.slice(0, 60)}' sizes an allocation with no upper bound checked first — a huge or wrapped size exhausts memory or under-allocates`);
  };
  const freeVar = (name: string, at: SyntaxNode, how: "free" | "delete" | "delete[]", env: Env) => {
    if (opts.quiet || loopRepeat > 0) { env.set(KIND_KEY("freed", name), 1); return; }
    if (env.get(KIND_KEY("freed", name))) {
      emit(ctx, "double-free", at, name, how, `'${name}' is freed again after an earlier ${how} on the same path, with no reassignment in between — corrupts the allocator's state`);
    }
    const kind = env.get(KIND_KEY("alloc", name)) ?? 0;
    const expected = how === "free" ? ALLOC_MALLOC : how === "delete" ? ALLOC_NEW : ALLOC_NEW_ARRAY;
    if (kind && !(kind & expected) && [ALLOC_MALLOC, ALLOC_NEW, ALLOC_NEW_ARRAY].includes(kind)) {
      const made = kind === ALLOC_MALLOC ? "malloc" : kind === ALLOC_NEW ? "new" : "new[]";
      emit(ctx, "mismatched-deallocation", at, name, how, `'${name}' was allocated with ${made} but released with ${how} — undefined behaviour (heap corruption, destructors not run)`);
    }
    env.set(KIND_KEY("freed", name), 1);
  };
  /** A read or write through `name` (deref, index, member access, passing it on). */
  const touchVar = (name: string, at: SyntaxNode, env: Env, deref: boolean) => {
    if (opts.quiet || loopRepeat > 0) return;
    if (env.get(KIND_KEY("freed", name))) {
      emit(ctx, "use-after-free", at, name, at.text.slice(0, 40), `'${name}' is used after it was freed on this path — the memory may already belong to another allocation`);
    }
    if (deref && env.get(KIND_KEY("unchecked", name))) {
      emit(ctx, "null-dereference", at, name, at.text.slice(0, 40), `'${name}' comes from an allocator that returns NULL on failure and is dereferenced without a NULL check`);
      env.delete(KIND_KEY("unchecked", name));
    }
  };
  /** Names a condition tests (`if (p == NULL)`, `if (!p)`, `if (p)`): no longer an unchecked allocation. */
  const markChecked = (cond: SyntaxNode | null, env: Env) => {
    if (!cond) return;
    for (const id of findAllNodes(cond, "identifier")) env.delete(KIND_KEY("unchecked", id.text));
  };

  // ── calls ──
  const checkCall = (call: SyntaxNode, env: Env) => {
    const { name, recv, args } = callInfo(call);
    const api = baseApi(name);
    const argM = args.map(a => m(a, env));

    // temp-name generators that fill their argument: tmpnam(buf), mktemp(tmpl), GetTempFileName(dir, pfx, 0, buf)
    const tmpOut = /^w?(?:tmpnam|mktemp)(?:_s)?$/.test(api) ? 0 : api === "GetTempFileName" && args[2]?.text === "0" ? 3 : -1;
    if (tmpOut >= 0 && args[tmpOut] && args[tmpOut].type !== "null" && args[tmpOut].text !== "NULL") {
      const nm = rootName(args[tmpOut]); if (nm) env.set(KIND_KEY("tmpname", nm), 1);
    }
    // sources that fill a buffer
    const slot = OUT_PARAM_SOURCES[api];
    if (slot !== undefined && slot > -9) {
      const targets = slot >= 0 ? [args[slot]] : args.slice(-slot);
      for (const t of targets) { const nm = rootName(t ?? null); if (nm) taintBuffer(nm, ALL, env); }
      if (api === "gets" && !opts.quiet) emit(ctx, "buffer-overflow", call, "stdin", "gets", "gets() reads an unbounded line into a fixed buffer — any input longer than the buffer overflows it (removed from C11); use fgets");
      // scanf("%s", buf): an unbounded %s conversion
      const fmtIdx = slot === -1 ? 0 : slot === -2 ? 1 : slot === -3 ? 1 : -1;
      const fmt = fmtIdx >= 0 ? stringValue(args[fmtIdx]) : null;
      if (fmt && /%s|%\[/.test(fmt) && !opts.quiet) emit(ctx, "buffer-overflow", call, "input", api, `${api}("${fmt.slice(0, 20)}") reads a string with no field width into a fixed buffer — bound it (%99s) or use fgets`);
    }
    if (api === "getline" && args.length === 2 && args[1]) { const nm = rootName(args[1]); if (nm) taintBuffer(nm, ALL, env); } // std::getline(cin, s)

    // copies: the destination takes the source's taint
    const from = COPY_INTO[api];
    if (from && args[0]) {
      const src = from.reduce((acc, i) => acc | (argM[i] ?? 0), 0);
      const dest = rootName(args[0]);
      if (dest && src) taintBuffer(dest, src, env);
      if (UNBOUNDED_COPY.has(api) && !opts.quiet) {
        // string data only: a number formatted with %d has a bounded length
        const STRINGY = ALL & ~SinkClass.CONTROL;
        const culprit = from.map(i => args[i]).find((a, k) => a && (argM[from[k]] ?? 0) & STRINGY);
        if (culprit) fireOn(ctx, "buffer-overflow", call, culprit, argM[from[from.findIndex(i => args[i] === culprit)]] ?? 0, api, STRINGY,
          `Attacker-controlled '${culprit.text.slice(0, 60)}' is copied by ${api} with no length limit — input longer than the destination overflows it; use a bounded copy (snprintf, strlcpy) and check the length`);
      }
      if (!opts.quiet) checkConstantOverflow(call, api, args, env);
    }
    // tainted copy length (memcpy/strncpy/...) with no bound check
    if (/^(?:memcpy|memmove|wmemcpy|wmemmove|strncpy|strncat|wcsncpy|wcsncat|memset)$/.test(api) && args[2] && !opts.quiet) {
      fireOn(ctx, "buffer-overflow", call, args[2], argM[2] ?? 0, `${api} length`, SinkClass.CONTROL,
        `Attacker-controlled length '${args[2].text.slice(0, 60)}' is passed to ${api} with no bound check against the destination's size`);
    }

    if (opts.quiet) return;
    // format strings
    const fi = FORMAT_ARG[api];
    if (fi !== undefined && args[fi]) {
      fireOn(ctx, "format-string", call, args[fi], argM[fi] ?? 0, api, ALL & ~SinkClass.CONTROL,
        `Attacker-controlled '${args[fi].text.slice(0, 60)}' is used as the format string of ${api} — %n writes memory and %s/%x read the stack; pass it as an argument ("%s", value)`);
    }
    // command execution
    if (/^(?:system|wsystem|popen|wpopen)$/.test(api) && args[0]) fireOn(ctx, "command-injection", call, args[0], argM[0] ?? 0, api);
    // exec*(path, ...) / spawn*(mode, path, ...): a tainted program, or tainted text after a shell's -c / /c
    const progIdx = /^w?exec(?:l|lp|le|v|vp|ve|vpe)$/.test(api) ? 0 : /^w?spawn(?:l|lp|le|v|vp|ve|vpe)$/.test(api) ? 1 : -1;
    if (progIdx >= 0 && args[progIdx]) {
      const program = stringValue(args[progIdx]);
      if (argM[progIdx] & classOf("command-injection")) fireOn(ctx, "command-injection", call, args[progIdx], argM[progIdx], api);
      else if (program && SHELL_PROGRAM_RE.test(program)) {
        const cIdx = args.findIndex(a => /^\/?c$|^-c$/.test(stringValue(a) ?? ""));
        for (const [i, a] of args.entries()) if (i > Math.max(progIdx, cIdx) && fireOn(ctx, "command-injection", call, a, argM[i], `${api} ${program} -c`)) break;
      }
    }
    if (api === "CreateProcess" && args[1]) fireOn(ctx, "command-injection", call, args[1], argM[1] ?? 0, name);
    if (api === "ShellExecute" && args[2]) fireOn(ctx, "command-injection", call, args[2], argM[2] ?? 0, name);
    // SQL
    const si = SQL_ARG[api];
    if (si !== undefined && args[si]) fireOn(ctx, "sql-injection", call, args[si], argM[si] ?? 0, api);
    // paths (also `std::ifstream f(path)` handled at the declaration, and `f.open(path)`)
    const pi = PATH_ARG[api];
    if (pi !== undefined && args[pi] && (!recv || api === "open")) fireOn(ctx, "path-traversal", call, args[pi], argM[pi] ?? 0, name);
    // LDAP filter
    const li = LDAP_FILTER_ARG[api];
    if (li !== undefined && args[li]) fireOn(ctx, "ldap-injection", call, args[li], argM[li] ?? 0, name);
    // libcurl URL
    if (api === "curl_easy_setopt" && /CURLOPT_URL/.test(args[1]?.text ?? "") && args[2]) fireOn(ctx, "ssrf", call, args[2], argM[2] ?? 0, "curl_easy_setopt(CURLOPT_URL)");
    // loading a library the caller names
    if (/^(?:dlopen|LoadLibrary|LoadLibraryEx)$/.test(api) && args[0]) fireOn(ctx, "eval-exec", call, args[0], argM[0] ?? 0, name);
    // a generated temp name opened non-exclusively: another process can create (or symlink) it between the two calls
    const tmpArg = args[0] && rootName(args[0]);
    if (tmpArg && env.get(KIND_KEY("tmpname", tmpArg)) && /^(?:open|wopen|creat|wcreat|fopen|wfopen|CreateFile)$/.test(api)) {
      const exclusive = api === "creat" || api === "wcreat" ? false
        : /fopen$/.test(api) ? /x/.test(stringValue(args[1]) ?? "x")
        : api === "CreateFile" ? /CREATE_NEW/.test(args[4]?.text ?? "CREATE_NEW")
        : /O_EXCL/.test(args[1]?.text ?? "O_EXCL");
      if (!exclusive) emit(ctx, "insecure-temp-file", call, tmpArg, name,
        `'${tmpArg}' is a predictable temporary name (tmpnam/mktemp/tempnam) opened without exclusive creation — another process can create or symlink it first; use mkstemp / tmpfile, or O_CREAT|O_EXCL`);
    }
    // a local function called with tainted arguments: walk it with those (same file); a call through a local
    // function pointer goes to the function it was initialised with
    const target = ctx.fnAlias.get(name) ?? name;
    const fn = !recv ? ctx.fns.get(target) : undefined;
    if (fn) {
      let seeded = ctx.seeded.get(target);
      for (const [i, am] of argM.entries()) {
        if (!(am & ALL) || !fn.params[i]) continue;
        seeded ??= new Map();
        seeded.set(i, (seeded.get(i) ?? 0) | am);
      }
      if (seeded) ctx.seeded.set(target, seeded);
      // the allocation state of pointer arguments (how it was allocated, whether it was NULL-checked): the callee
      // is walked again in that state, so a dereference of an unchecked pointer is reported in it. A parameter the
      // callee frees is already judged at this call (freeVar), so it is not seeded twice.
      const frees = ctx.freesParam.get(target);
      for (const [i, a] of args.entries()) {
        if (a.type !== "identifier" || !fn.params[i] || frees?.has(i)) continue;
        for (const k of ["alloc", "unchecked"]) {
          const v = env.get(KIND_KEY(k, a.text));
          if (!v) continue;
          const perFn = ctx.seededMem.get(target) ?? new Map<number, Map<string, number>>();
          const perParam = perFn.get(i) ?? new Map<string, number>();
          perParam.set(k, v);
          perFn.set(i, perParam);
          ctx.seededMem.set(target, perFn);
        }
      }
    }
    // a function in another file of the batch whose parameter reaches a sink there
    const facts = !recv && !fn ? ctx.crossFileFacts?.get(target) : undefined;
    if (facts) {
      for (const fact of facts) {
        const a = args[fact.index];
        if (!a) continue;
        const am = argM[fact.index] ?? 0;
        if (!(am & fact.sinkClass)) { if (wasCleared(am, fact.sinkClass)) ctx.suppressed?.push({ id: fact.id, line: lineOf(call) }); continue; }
        const line = lineOf(call);
        const key = `${fact.id}:${line}`;
        if (ctx.seen.has(key)) continue;
        ctx.seen.add(key);
        const via = fact.via.length > 1 ? ` (${fact.via.map(displayFnName).join(" -> ")})` : "";
        ctx.findings.push({
          id: fact.id as AstTaintCppId, line, sourceExpr: a.text, sinkExpr: `${name}() -> ${fact.sinkExpr}`,
          detail: `Tainted expression '${a.text.slice(0, 60)}' is passed to ${name}(...), which reaches ${fact.sinkExpr}(...) at ${fact.file}:${fact.line} [crosses file boundary${via}] — real data-flow match across files, not a line-pattern guess`,
          trace: crossFileTrace(buildBackwardTraceGeneric(ctx.filePath, call, a.text, name, cppTraceResolver), name, fact),
          calleeSink: { file: fact.file, line: fact.line, sinkExpr: fact.sinkExpr, via: fact.via },
        });
      }
    }
  };

  /** Characters in the string held by `e`: a literal, or a buffer whose length this walk knows (memset + NUL, a
   * literal initialiser, strcpy), else the buffer's capacity less its terminator. */
  const strLenOf = (e: SyntaxNode | null, elem: number): number | undefined => {
    const lit = stringValue(e);
    if (lit !== null) return lit.replace(/\\./g, "x").length;
    const nm = rootName(e);
    if (!nm || nm.includes(".")) return undefined;
    const known = ctx.strLen.get(groupKey(nm));
    if (known !== undefined) return known;
    const cap = ctx.capacity.get(nm);
    return cap !== undefined ? Math.floor(cap / elem) - 1 : undefined;
  };

  /** memcpy(dest[50], src, 100) / strcpy(dest[50], src) with a 99-char src / snprintf(dest[50], strlen(src), ...). */
  const checkConstantOverflow = (call: SyntaxNode, api: string, args: SyntaxNode[], env: Env) => {
    void env;
    const dest = rootName(args[0] ?? null);
    const cap = dest && !dest.includes(".") ? ctx.capacity.get(dest) : undefined;
    if (cap === undefined) return;
    const elem = /^(?:w|lstrcpyW)/.test(api) ? 4 : 1;
    let need: number | undefined;
    const lenArg = /^(?:memcpy|memmove|strncpy|strncat|wmemcpy|wmemmove|wcsncpy|wcsncat)$/.test(api) ? args[2]
      : /^(?:snprintf|snwprintf|swprintf|vsnprintf|vsnwprintf)$/.test(api) ? args[1] : undefined;
    if (lenArg) {
      const len = constBytes(lenArg.text);
      // wmemcpy / wcsncpy / snwprintf count characters, memcpy counts bytes
      if (len !== undefined) need = /^(?:w|snw|vsnw|sw)/.test(api) ? len * 4 : len;
    } else if (/^(?:strcpy|wcscpy|lstrcpy)$/.test(api) && args[1]) {
      const n = strLenOf(args[1], elem);
      if (n !== undefined) need = (n + 1) * elem;
    } else if (/^(?:strcat|wcscat|lstrcat)$/.test(api) && args[1]) {
      const n = strLenOf(args[1], elem);
      if (n !== undefined) need = ((ctx.strLen.get(groupKey(dest!)) ?? 0) + n + 1) * elem;
    }
    if (need !== undefined && need > cap) {
      emit(ctx, "buffer-overflow", call, args[1]?.text ?? api, api, `${api} writes up to ${need} bytes into '${dest}', which holds ${cap} — a constant overflow of the destination`);
    }
  };

  /** Bytes per element of `name`'s declared (pointer / array) type in the enclosing function or file, if basic. */
  const elemSizeOf = (name: string, at: SyntaxNode): number | undefined => {
    let fn: SyntaxNode | null = at;
    while (fn && fn.type !== "function_definition") fn = fn.parent;
    const re = new RegExp(`\\b((?:unsigned\\s+|signed\\s+)?[A-Za-z_]\\w*)\\s*\\*?\\s*\\b${name}\\b\\s*(?:\\[|=|;|,)`);
    const hit = re.exec(fn?.text ?? "") ?? re.exec(ctx.root?.text ?? "");
    return hit ? SIZEOF[hit[1].replace(/\s+/g, " ")] : undefined;
  };
  /** `for (i = 0; i < 100; i++) data[i] = ...;` into a buffer of 50 elements: the last iterations write past it. */
  const checkConstantLoopOverflow = (loop: SyntaxNode) => {
    const cond = field(loop, "condition");
    if (cond?.type !== "binary_expression" || !/^<=?$/.test(operatorOf(cond))) return;
    const iv = field(cond, "left");
    const bound = constBytes(field(cond, "right")?.text ?? "");
    if (iv?.type !== "identifier" || bound === undefined) return;
    // the counter starts at a constant (0 in practice); a variable start says nothing about the range
    const init = field(loop, "initializer");
    const startText = init?.type === "assignment_expression" ? field(init, "right")?.text
      : init?.type === "declaration" ? field(findAllNodes(init, "init_declarator")[0] ?? init, "value")?.text : undefined;
    if (startText === undefined || constBytes(startText) === undefined) return;
    const lastIndex = operatorOf(cond) === "<" ? bound - 1 : bound;
    const body = field(loop, "body");
    for (const a of body ? findAllNodes(body, "assignment_expression") : []) {
      const l = field(a, "left");
      if (l?.type !== "subscript_expression") continue;
      const idx = named(field(l, "indices"))[0] ?? field(l, "index");
      const buf = field(l, "argument");
      if (idx?.text !== iv.text || buf?.type !== "identifier") continue;
      const cap = ctx.capacity.get(buf.text);
      const elem = elemSizeOf(buf.text, loop);
      if (cap === undefined || !elem || (lastIndex + 1) * elem <= cap) continue;
      emit(ctx, "buffer-overflow", a, iv.text, `${buf.text}[${iv.text}]`,
        `The loop writes '${buf.text}[${iv.text}]' up to index ${lastIndex}, but '${buf.text}' holds ${Math.floor(cap / elem)} elements — the last iterations write past its end`);
      return;
    }
  };

  const walkExpr = (e: SyntaxNode | null, env: Env): void => {
    if (!e) return;
    switch (e.type) {
      case "lambda_expression": return;
      case "assignment_expression": {
        const l = field(e, "left"), r = field(e, "right");
        walkExpr(r, env);
        if (l && l.type !== "identifier") walkExpr(l, env);
        const nm = rootName(l);
        if (!nm) return;
        const op = operatorOf(e);
        const rm = m(r, env);
        if (l?.type === "identifier") {
          setVar(nm, rm, env, op !== "=");
          if (ctx.globalNames.has(nm) && !ctx.speculative && rm) ctx.globalTaint.set(nm, (ctx.globalTaint.get(nm) ?? 0) | rm);
          if (op === "=") {
            // a new value: the old buffer's size and contents no longer describe it
            ctx.capacity.delete(nm);
            if (!ctx.aliases.has(nm)) ctx.strLen.delete(nm);
            ctx.aliases.delete(nm);
            recordAlloc(nm, r, env);
            copyMemory(nm, r, env);
            const rn = r?.type === "identifier" ? r.text : null;
            if (rn && (ctx.capacity.has(rn) || ctx.aliases.has(rn))) alias(nm, rn);
          }
        } else {
          // *p = x / p[i] = x / s.f = x: writing through the variable
          const base = nm.split(".")[0];
          touchVar(base, l!, env, true);
          if (rm) taintBuffer(nm, rm, env);
          // buf[k] = '\0': the string is now at most k characters
          const arg = l?.type === "subscript_expression" ? field(l, "argument") : null;
          if (arg?.type === "identifier" && r && /^(?:[LuU]?'\\0'|0)$/.test(r.text)) {
            const k = constBytes(named(field(l, "indices"))[0]?.text ?? field(l, "index")?.text ?? "");
            const known = ctx.strLen.get(groupKey(arg.text));
            if (k !== undefined) setLen(arg.text, known !== undefined ? Math.min(known, k) : k);
          }
        }
        return;
      }
      case "call_expression": {
        for (const a of named(field(e, "arguments"))) walkExpr(a, env);
        const fnNode = field(e, "function");
        if (fnNode?.type === "field_expression") walkExpr(field(fnNode, "argument"), env);
        const { name, recv, args } = callInfo(e);
        const api = baseApi(name);
        // free releases; a local function that frees its parameter releases that argument; everything else that
        // takes the pointer uses it
        const frees = !recv ? ctx.freesParam.get(ctx.fnAlias.get(name) ?? name) : undefined;
        if (/^(?:free|cfree|kfree|g_free)$/.test(api) && args[0]) { const nm = rootName(args[0]); if (nm && args[0].type === "identifier") freeVar(nm, e, "free", env); }
        else for (const [i, a] of args.entries()) {
          const nm = a.type === "identifier" ? a.text : null;
          if (!nm) continue;
          const dIdx = DEREF_ARGS[api];
          const how = frees?.get(i);
          if (how) freeVar(nm, e, how, env); else touchVar(nm, a, env, dIdx === -1 || dIdx === i);
        }
        if (recv?.type === "identifier") touchVar(recv.text, recv, env, fnNode?.text.includes("->") ?? false);
        checkCall(e, env);
        // what the call leaves in its destination buffer (after checkCall, which sizes the copy by the old length)
        const dst = args[0]?.type === "identifier" ? args[0].text : null;
        if (dst) {
          if (/^w?memset$/.test(api) && args[2]) setLen(dst, constBytes(args[2].text));
          else if (/^(?:strcpy|wcscpy|lstrcpy)$/.test(api)) setLen(dst, strLenOfName(args[1] ?? null));
          else if (/^(?:strcat|wcscat|lstrcat)$/.test(api)) {
            const a = ctx.strLen.get(groupKey(dst)), b = strLenOfName(args[1] ?? null);
            setLen(dst, a !== undefined && b !== undefined ? a + b : undefined);
          } else if (COPY_INTO[api] || OUT_PARAM_SOURCES[api] !== undefined) setLen(dst, undefined);
        }
        return;
      }
      case "delete_expression": {
        const target = named(e).find(c => c.type === "identifier");
        if (target) freeVar(target.text, e, /\[\s*\]/.test(e.text) ? "delete[]" : "delete", env);
        return;
      }
      case "pointer_expression": {
        walkExpr(field(e, "argument"), env);
        if (operatorOf(e) === "*" && field(e, "argument")?.type === "identifier") touchVar(field(e, "argument")!.text, e, env, true);
        return;
      }
      case "subscript_expression": case "field_expression": {
        walkExpr(field(e, "argument"), env);
        if (e.type === "subscript_expression") for (const c of named(field(e, "indices"))) walkExpr(c, env);
        const base = field(e, "argument");
        if (base?.type === "identifier") touchVar(base.text, e, env, e.type === "subscript_expression" || e.text.includes("->"));
        return;
      }
      case "binary_expression": {
        walkExpr(field(e, "left"), env); walkExpr(field(e, "right"), env);
        // std::cin >> s / in >> s: the right side is filled from the stream
        const l = field(e, "left");
        if (operatorOf(e) === ">>" && l && /(?:^|::)(?:cin|wcin)$|^(?:in|is|stream|file|ifs|input)$/.test(l.text.split(" >>")[0])) {
          const nm = rootName(field(e, "right")); if (nm) taintBuffer(nm, ALL, env);
        }
        return;
      }
      default:
        for (const c of named(e)) walkExpr(c, env);
    }
  };

  const declare = (decl: SyntaxNode, env: Env) => {
    const typeText = field(decl, "type")?.text ?? "";
    for (const d of named(decl).filter(c => c.type !== "primitive_type" && c !== field(decl, "type") && !/qualifier|specifier/.test(c.type))) {
      const target = d.type === "init_declarator" ? field(d, "declarator") : d;
      const nm = declaredName(target);
      if (!nm) continue;
      resetMemory(nm, env);
      // `void (*funcPtr)(char *) = badSink;`: calls through funcPtr go to badSink
      if (target?.type === "function_declarator" && d.type === "init_declarator") {
        const v = field(d, "value");
        const fnName = v?.type === "identifier" ? v.text : v?.type === "pointer_expression" ? field(v, "argument")?.text : undefined;
        if (fnName) ctx.fnAlias.set(nm, fnName);
        continue;
      }
      // `std::ifstream in(path);` parses as a function declaration (the most vexing parse): inside a body, when every
      // "parameter" is a bare name the function already has, it is a constructor call with those arguments
      if (target?.type === "function_declarator") {
        const ps = named(field(target, "parameters"));
        const argNames = ps.map(p => (named(p).length === 1 && named(p)[0].type === "type_identifier" && env.has(p.text) ? p.text : null));
        if (ps.length && argNames.every(Boolean)) {
          const am = argNames.reduce((acc, a) => acc | groupMask(a!, env, ctx), 0);
          env.set(nm, am);
          if (/(?:^|::)(?:i|o)?fstream$/.test(typeText) && !opts.quiet) fireOn(ctx, "path-traversal", d, ps[0], groupMask(argNames[0]!, env, ctx), typeText);
        }
        continue;
      }
      // char buf[100] / wchar_t w[50]: capacity in bytes
      const arr = target && (target.type === "array_declarator" ? target : findAllNodes(target, "array_declarator")[0]);
      const size = arr ? evalConstExpr(field(arr, "size")?.text ?? "", () => undefined) : undefined;
      if (typeof size === "number") ctx.capacity.set(nm, size * (/wchar_t|int\b|long\b|float\b/.test(typeText) ? 4 : /double|int64/.test(typeText) ? 8 : 1));
      if (d.type !== "init_declarator") { env.set(nm, 0); continue; }
      const v = field(d, "value");
      // char src[11] = SRC_STRING / char dest[50] = "": a known string length
      if (arr && v) setLen(nm, strLenOfName(v));
      walkExpr(v, env);
      env.set(nm, m(v, env));
      recordAlloc(nm, v, env);
      copyMemory(nm, v, env);
      const vn = v?.type === "identifier" ? v.text : null;
      if (vn && (ctx.capacity.has(vn) || ctx.aliases.has(vn) || /\*/.test(target?.text ?? ""))) alias(nm, vn);
      // std::ifstream f(path) / std::fstream f(path, mode)
      if (v?.type === "argument_list" && /(?:^|::)(?:i|o)?fstream$/.test(typeText) && named(v)[0] && !opts.quiet) {
        fireOn(ctx, "path-traversal", d, named(v)[0], m(named(v)[0], env), typeText);
      }
    }
  };

  const walk = (node: SyntaxNode | null, env: Env): boolean => {
    if (!node) return false;
    switch (node.type) {
      case "compound_statement": case "translation_unit": case "preproc_if": case "preproc_ifdef": case "preproc_else": case "preproc_elif":
      case "declaration_list": case "labeled_statement":
        return walkStmts(named(node), env);
      case "declaration": declare(node, env); return false;
      case "expression_statement": for (const c of named(node)) walkExpr(c, env); return false;
      case "return_statement": {
        const v = named(node)[0] ?? null;
        walkExpr(v, env);
        if (v?.type === "identifier") touchVar(v.text, v, env, false);
        opts.onReturn?.(v, env);
        return true;
      }
      case "throw_statement": for (const c of named(node)) walkExpr(c, env); return true;
      case "break_statement": case "continue_statement": case "goto_statement": return false;
      case "if_statement": {
        const cond = field(node, "condition");
        const cons = field(node, "consequence");
        const altClause = field(node, "alternative");
        const alt = altClause?.type === "else_clause" ? named(altClause)[0] ?? null : altClause;
        const branches: Branch[] = [{
          visitCond: (e) => { walkExpr(cond, e); markChecked(cond, e); },
          guards: () => guardsOf(cond, ctx),
          body: (e) => walk(cons, e),
        }];
        if (alt) branches.push({ body: (e) => walk(alt, e) });
        const term = walkIfChain(env, branches);
        markChecked(cond, env);
        return term;
      }
      case "while_statement": case "do_statement": {
        const cond = field(node, "condition");
        walkExpr(cond, env); markChecked(cond, env);
        const body = field(node, "body");
        return walkLoop(env, loopBody((e) => walk(body, e)));
      }
      case "for_statement": case "for_range_loop": {
        for (const k of ["initializer", "condition", "right"]) { const c = field(node, k); if (c) { if (c.type === "declaration") declare(c, env); else walkExpr(c, env); } }
        if (node.type === "for_statement" && !opts.quiet) checkConstantLoopOverflow(node);
        const body = field(node, "body");
        const update = field(node, "update");
        // `for (T *x : items)`: x is a fresh element each iteration (a `delete x` in two such loops is two objects)
        const rangeVar = node.type === "for_range_loop" ? declaredName(field(node, "declarator")) : null;
        if (rangeVar) env.set(rangeVar, m(field(node, "right"), env));
        return walkLoop(env, loopBody((e) => {
          if (rangeVar) resetMemory(rangeVar, e);
          const t = walk(body, e);
          if (!t && update) walkExpr(update, e);
          return t;
        }));
      }
      case "switch_statement": {
        walkExpr(field(node, "condition"), env);
        const body = field(node, "body");
        const cases = named(body).filter(c => c.type === "case_statement");
        return walkSwitch(env, cases.map(c => ({
          isDefault: !field(c, "value"),
          body: (e: Env) => walkStmts(named(c).filter(x => x !== field(c, "value")), e),
        })));
      }
      case "try_statement": {
        const body = field(node, "body");
        const handlers = named(node).filter(c => c.type === "catch_clause");
        return walkTry(env, (e) => walk(body, e), handlers.map(h => ({ bind: [], body: (e: Env) => walk(field(h, "body"), e) })));
      }
      case "function_definition": case "class_specifier": case "struct_specifier": case "namespace_definition":
        return false;
      default:
        for (const c of named(node)) walkExpr(c, env);
        return false;
    }
  };
  const walkStmts = (nodes: SyntaxNode[], env: Env): boolean => {
    for (const n of nodes) if (walk(n, env)) return true;
    return false;
  };
  return { walk, checkCall };
}

// ── Functions, summaries and entry points ──────────────────────────────────────────────────────────────────

function collectFns(root: SyntaxNode): LocalFn[] {
  return findAllNodes(root, "function_definition").map(f => {
    let d = field(f, "declarator");
    while (d && d.type !== "function_declarator") d = field(d, "declarator");
    const params = named(field(d, "parameters")).filter(p => /parameter_declaration/.test(p.type))
      .map((p, index) => ({ name: declaredName(field(p, "declarator")) ?? "", index }));
    return {
      name: functionName(f) ?? "", decl: f, body: field(f, "body"), params,
      isStatic: named(f).some(c => c.type === "storage_class_specifier" && c.text === "static"),
    };
  }).filter(f => !!f.name);
}

type Release = "free" | "delete" | "delete[]";
function collectFreesParam(fns: ReadonlyMap<string, LocalFn>): Map<string, Map<number, Release>> {
  const out = new Map<string, Map<number, Release>>();
  for (let round = 0; round < 4; round++) {
    let changed = false;
    for (const [name, f] of fns) {
      if (!f.body) continue;
      const map = out.get(name) ?? new Map<number, Release>();
      const before = map.size;
      for (const p of f.params) {
        if (!p.name || map.has(p.index)) continue;
        const del = findAllNodes(f.body, "delete_expression").find(d => named(d).some(c => c.type === "identifier" && c.text === p.name));
        let how: Release | undefined = del ? (/\[\s*\]/.test(del.text) ? "delete[]" : "delete") : undefined;
        if (!how) for (const c of findAllNodes(f.body, "call_expression")) {
          const ci = callInfo(c);
          if (/^(?:free|cfree|kfree|g_free)$/.test(baseApi(ci.name))) {
            if (ci.args[0]?.type === "identifier" && ci.args[0].text === p.name) { how = "free"; break; }
            continue;
          }
          const callee = out.get(ci.name);
          const i = callee ? ci.args.findIndex((a, k) => callee.has(k) && a.type === "identifier" && a.text === p.name) : -1;
          if (i >= 0) { how = callee!.get(i); break; }
        }
        if (how) map.set(p.index, how);
      }
      if (map.size !== before) { out.set(name, map); changed = true; }
    }
    if (!changed) break;
  }
  return out;
}

/** Variables declared at file scope (outside every function), including inside namespaces and #if blocks. */
function collectGlobals(root: SyntaxNode): Set<string> {
  const out = new Set<string>();
  const visit = (n: SyntaxNode) => {
    for (const c of named(n)) {
      if (c.type === "declaration") {
        for (const d of named(c)) {
          if (d === field(c, "type")) continue;
          const t = d.type === "init_declarator" ? field(d, "declarator") : d;
          if (t && t.type !== "function_declarator" && /declarator|identifier/.test(t.type)) { const nm = declaredName(t); if (nm) out.add(nm); }
        }
      } else if (/^(?:namespace_definition|declaration_list|preproc_\w+|linkage_specification)$/.test(c.type)) visit(c);
    }
  };
  visit(root);
  return out;
}

function freshWalkState(ctx: EngineCtx) { ctx.aliases = new Map(); ctx.capacity = new Map(); ctx.strLen = new Map(); ctx.fnAlias = new Map(); }

function returnMask(fn: LocalFn, ctx: EngineCtx, seedIndex: number | null): number {
  if (!fn.body) return 0;
  let surviving = 0;
  const saved = { findings: ctx.findings, seen: ctx.seen, suppressed: ctx.suppressed, seeded: ctx.seeded, aliases: ctx.aliases, capacity: ctx.capacity, strLen: ctx.strLen, fnAlias: ctx.fnAlias, current: ctx.current, speculative: ctx.speculative };
  ctx.findings = []; ctx.seen = new Set(); ctx.suppressed = undefined; ctx.seeded = new Map(); ctx.current = fn;
  ctx.speculative = saved.speculative || seedIndex !== null;
  freshWalkState(ctx);
  const env: Env = new Map();
  for (const p of fn.params) env.set(p.name, seedIndex === p.index ? ALL : 0);
  createWalker(ctx, { quiet: true, onReturn: (e, en) => { surviving |= mask(e, en, ctx); } }).walk(fn.body, env);
  Object.assign(ctx, saved);
  return surviving & ALL;
}

function buildSummaries(ctx: EngineCtx) {
  const globalsSig = () => [...ctx.globalTaint].map(([k, v]) => `${k}=${v}`).join(",");
  for (let round = 0; round < FIXED_POINT_CAP; round++) {
    const before = globalsSig();
    let changed = false;
    for (const [name, f] of ctx.fns) {
      const intrinsic = returnMask(f, ctx, null);
      if ((intrinsic | (ctx.intrinsic.get(name) ?? 0)) !== (ctx.intrinsic.get(name) ?? 0)) { ctx.intrinsic.set(name, (ctx.intrinsic.get(name) ?? 0) | intrinsic); changed = true; }
      const prop = new Map(ctx.propagating.get(name) ?? []);
      let grew = false;
      for (const p of f.params) {
        const r = returnMask(f, ctx, p.index) & ~intrinsic;
        const next = (prop.get(p.index) ?? 0) | r;
        if (r && next !== (prop.get(p.index) ?? 0)) { prop.set(p.index, next); grew = true; }
      }
      if (grew) { ctx.propagating.set(name, prop); changed = true; }
    }
    if (!changed && globalsSig() === before) break;
  }
}

function makeCtx(content: string, filePath: string, root: SyntaxNode, suppressed?: SuppressedSink[],
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>): EngineCtx {
  MACROS = collectMacros(root);
  const fns = new Map<string, LocalFn>();
  for (const f of collectFns(root)) if (!fns.has(f.name)) fns.set(f.name, f);
  const ctx: EngineCtx = {
    filePath, content, lines: content.split("\n"), root, fns, propagating: new Map(), intrinsic: new Map(), seeded: new Map(),
    suppressed, findings: [], seen: new Set(), crossFileFacts, aliases: new Map(), capacity: new Map(), strLen: new Map(), fnAlias: new Map(), freesParam: collectFreesParam(fns), seededMem: new Map(),
    globalNames: collectGlobals(root), globalTaint: new Map(), speculative: false, current: null,
  };
  buildSummaries(ctx);
  return ctx;
}

/** Parameters that are input at a function's entry: main/wmain's argv, WinMain's command line. */
function entryEnv(fn: LocalFn, seedEntry: boolean): Env {
  const env: Env = new Map();
  for (const p of fn.params) env.set(p.name, 0);
  if (/^(?:main|wmain|_tmain)$/.test(fn.name) && fn.params[1]) env.set(fn.params[1].name, ALL);
  if (/^(?:WinMain|wWinMain)$/.test(fn.name) && fn.params[2]) env.set(fn.params[2].name, ALL);
  if (seedEntry) for (const p of fn.params) if (p.name) env.set(p.name, ALL);
  return env;
}

/** Pointer/string parameters of exported functions nothing in the file calls: library API taking caller data. */
const STRINGY_PARAM_RE = /\bchar\s*\*|\bwchar_t\s*\*|std::(?:w?string|string_view)|\bLPC?[TW]?STR\b|\bconst\s+char\b/;

function runScan(ctx: EngineCtx, withEntryPoints: boolean): AstTaintCppFinding[] {
  const called = new Set(findAllNodes(ctx.root, "call_expression").map(c => callInfo(c).name));
  for (const [, f] of ctx.fns) {
    if (!f.body) continue;
    ctx.current = f;
    freshWalkState(ctx);
    const isEntry = withEntryPoints && !f.isStatic && !called.has(f.name) && !/^(?:main|wmain|_tmain|WinMain|wWinMain)$/.test(f.name)
      && STRINGY_PARAM_RE.test(field(f.decl, "declarator")?.text ?? "");
    ctx.speculative = isEntry;
    createWalker(ctx, {}).walk(f.body, entryEnv(f, isEntry));
    ctx.speculative = false;
  }
  drainSeeded(ctx);
  ctx.current = null;
  return ctx.findings;
}

function drainSeeded(ctx: EngineCtx) {
  const walked = new Set<string>();
  for (let round = 0; round < FIXED_POINT_CAP; round++) {
    let changed = false;
    for (const name of new Set([...ctx.seeded.keys(), ...ctx.seededMem.keys()])) {
      const f = ctx.fns.get(name);
      if (!f?.body) continue;
      const idx = ctx.seeded.get(name) ?? new Map<number, number>();
      const mem = ctx.seededMem.get(name) ?? new Map<number, Map<string, number>>();
      const sig = `${name}:${[...idx].sort((a, b) => a[0] - b[0]).map(([i, v]) => `${i}=${v}`).join(",")}`
        + `|${[...mem].sort((a, b) => a[0] - b[0]).map(([i, ks]) => `${i}=${[...ks].map(([k, v]) => `${k}${v}`).join("+")}`).join(",")}`;
      if (walked.has(sig)) continue;
      walked.add(sig);
      changed = true;
      const env: Env = new Map();
      for (const p of f.params) {
        env.set(p.name, idx.get(p.index) ?? 0);
        for (const [k, v] of mem.get(p.index) ?? []) env.set(KIND_KEY(k, p.name), v);
      }
      const prev = ctx.current;
      ctx.current = f;
      freshWalkState(ctx);
      createWalker(ctx, {}).walk(f.body, env);
      ctx.current = prev;
    }
    if (!changed) break;
  }
}

export interface CppScanOptions {
  /** Also treat the string/pointer parameters of exported functions nothing in the file calls as untrusted; findings
   * that exist ONLY because of this come back with `entryPointSeeded: true`. */
  entryPoints?: boolean;
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>;
}

/** Sinks reported from an exported function's parameters alone. A library API that takes a path or a buffer and
 * length from its caller is the caller's contract, not a flaw of the library (seen on real code: file watchers'
 * snapshot paths, parsers' memcpy(dst, data, length)); running a command or a format string the caller passed is. */
const SEEDED_IDS: ReadonlySet<string> = new Set(["command-injection", "sql-injection", "format-string", "ldap-injection", "ssrf", "eval-exec"]);

export function scanAstTaintCpp(
  content: string, filePath: string, root: SyntaxNode, suppressedOut?: SuppressedSink[], opts?: CppScanOptions,
): AstTaintCppFinding[] {
  try {
    const strict = runScan(makeCtx(content, filePath, root, suppressedOut, opts?.crossFileFacts), false);
    if (!opts?.entryPoints) return strict;
    const relaxed = runScan(makeCtx(content, filePath, root, suppressedOut, opts.crossFileFacts), true);
    const have = new Set(strict.map(f => `${f.id}:${f.line}`));
    return [...strict, ...relaxed.filter(f => !have.has(`${f.id}:${f.line}`) && SEEDED_IDS.has(f.id)).map(f => ({ ...f, entryPointSeeded: true }))];
  } catch (err) {
    console.error(`[astTaintCpp] threw scanning ${filePath}:`, err);
    return [];
  }
}

const NON_FLOW_IDS: ReadonlySet<string> = new Set(["use-after-free", "double-free", "null-dereference", "mismatched-deallocation", "insecure-temp-file"]);

/**
 * Parameter -> sink facts for every non-static function in one file, keyed by its bare name (C has one global
 * namespace for external functions; a C++ method is keyed by its unqualified name too -- the call site rarely knows
 * the class without overload resolution). Computed with the scan's own sink logic, each parameter walked alone.
 */
export function computeCppFnSinkFacts(
  content: string, filePath: string, root: SyntaxNode, incoming: ReadonlyMap<string, readonly ParamSinkFact[]>,
): Map<string, ParamSinkFact[]> {
  const out = new Map<string, ParamSinkFact[]>();
  try {
    const ctx = makeCtx(content, filePath, root, undefined, incoming);
    ctx.speculative = true;
    const all = [...ctx.fns.values()];
    const ranges = all.map(f => ({ name: f.name, start: f.decl.startPosition.row + 1, end: f.decl.endPosition.row + 1 }));
    const run = (f: LocalFn, env: Env): AstTaintCppFinding[] => {
      ctx.findings = []; ctx.seen = new Set(); ctx.seeded = new Map(); ctx.seededMem = new Map(); ctx.current = f;
      freshWalkState(ctx);
      createWalker(ctx, {}).walk(f.body!, env);
      drainSeeded(ctx);
      ctx.current = null;
      return ctx.findings;
    };
    for (const f of all) {
      if (!f.body || f.isStatic || f.params.length === 0 || /^(?:main|wmain)$/.test(f.name)) continue;
      const zero = () => { const e: Env = new Map(); for (const p of f.params) e.set(p.name, 0); return e; };
      const baseline = new Set(run(f, zero()).map(x => `${x.id}:${x.line}`));
      const facts: ParamSinkFact[] = [];
      for (const p of f.params) {
        const env = zero();
        env.set(p.name, ALL);
        for (const x of dropOnPathDuplicates(run(f, env))) {
          if (baseline.has(`${x.id}:${x.line}`) || NON_FLOW_IDS.has(x.id)) continue;
          const where = x.calleeSink;
          mergeSinkFacts(facts, [{
            index: p.index, isRest: false, id: x.id, sinkClass: x.id === "integer-overflow" ? SinkClass.CONTROL : classOf(x.id),
            sinkExpr: where?.sinkExpr ?? x.sinkExpr, file: where?.file ?? filePath, line: where?.line ?? x.line,
            via: [f.name, ...(where?.via ?? [])],
            steps: x.trace?.length ? factStepsFromTrace(x.trace, f.name, filePath, f.decl.startPosition.row + 1, p.name,
              { fnEnd: f.decl.endPosition.row + 1, functions: ranges, lines: ctx.lines }) : undefined,
          }]);
        }
      }
      if (facts.length === 0) continue;
      const list = out.get(f.name) ?? [];
      mergeSinkFacts(list, facts);
      out.set(f.name, list);
    }
  } catch (err) {
    console.error(`[astTaintCpp] threw computing fn sink facts for ${filePath}:`, err);
  }
  return out;
}
