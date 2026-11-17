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
import { recordEngineFailure } from "./taint/engineFailures";
import type { Node as SyntaxNode, Language as LanguageT, Parser as ParserT } from "web-tree-sitter";
import { ensureTreeSitterInit, rootIfShallowEnough } from "./treeSitterRuntime";
import {
  ALL, FIXED_POINT_CAP, SinkClass, applySanitizer, buildBackwardTraceGeneric, classOf, cloneEnv, factStepsFromTrace,
  mergeSinkFacts, dropOnPathDuplicates, crossFileTrace, displayFnName, walkIfChain, walkLoop, walkSwitch, walkTry, wasCleared,
  type Branch, type Guard, type ParamSinkFact, type SuppressedSink, type TaintEnv, type TraceResolver, type TraceStep,
} from "./taint/taintCore";
import { NodeCache } from "./taint/nodeCache";
import { sanitizerClears } from "./taint/sanitizers";
import { propagatorNames } from "./taint/models/propagators";
import { sinkLabel, sinkModelsFor } from "./taint/models/sinks";
import { evalConstExpr } from "./taint/constEval";

declare const __non_webpack_require__: NodeJS.Require | undefined;
function nodeRequire(): NodeJS.Require {
  // eslint-disable-next-line no-undef
  return typeof __non_webpack_require__ !== "undefined" ? __non_webpack_require__ : require;
}

export type AstTaintCppId =
  | "command-injection" | "sql-injection" | "path-traversal" | "format-string" | "buffer-overflow" | "ldap-injection"
  | "ssrf" | "eval-exec" | "integer-overflow" | "use-after-free" | "double-free" | "null-dereference"
  | "mismatched-deallocation" | "insecure-temp-file" | "xxe" | "insecure-deserialization";

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
  "insecure-temp-file": "medium", "xxe": "high", "insecure-deserialization": "critical",
};
const LABEL: Record<AstTaintCppId, string> = {
  "command-injection": "Command Injection", "sql-injection": "SQL Injection", "path-traversal": "Path Traversal",
  "format-string": "Format String Injection", "buffer-overflow": "Buffer Overflow", "ldap-injection": "LDAP Injection",
  "ssrf": "Server-Side Request Forgery", "eval-exec": "Untrusted Library Load", "integer-overflow": "Uncontrolled Size",
  "use-after-free": "Use After Free", "double-free": "Double Free", "null-dereference": "NULL Dereference",
  "mismatched-deallocation": "Mismatched Deallocation", "insecure-temp-file": "Insecure Temporary File",
  "xxe": "XML External Entity (XXE)", "insecure-deserialization": "Insecure Deserialization",
};
export function astTaintCppSeverity(id: AstTaintCppId): "critical" | "high" | "medium" { return SEVERITY[id]; }
export function astTaintCppLabel(id: AstTaintCppId): string { return LABEL[id]; }

// ── Parser lifecycle (warm-cache pattern, see astTaintRust.ts) ─────────────────────────────────────────────────

let langPromise: Promise<LanguageT> | null = null;
let parserPool: ParserT | null = null;
let lastCppEngineError: string | null = null;

/** Engine health for telemetry: ready / parser_unavailable (init failed or unfinished), and the last failure. */
export function getCppEngineStatus(): { status: "ready" | "parser_unavailable"; lastError: string | null } {
  return { status: parserPool ? "ready" : "parser_unavailable", lastError: lastCppEngineError };
}

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
      langPromise = null;   // a rejected init must not be cached forever: the next call retries
      lastCppEngineError = String((err as Error)?.message ?? err);
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
    recordEngineFailure(filePath, "parse-failed");
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
/** Every definition of each macro, in source order: an #ifdef _WIN32 / #else pair defines one name twice. */
let MACRO_DEFS: ReadonlyMap<string, readonly string[]> = new Map();
function collectMacros(root: SyntaxNode): Map<string, string> {
  const out = new Map<string, string>();
  const all = new Map<string, string[]>();
  for (const d of findAllNodes(root, "preproc_def")) {
    const nm = field(d, "name")?.text, v = field(d, "value")?.text.trim();
    if (!nm || !v) continue;
    if (!out.has(nm)) out.set(nm, v);
    all.set(nm, [...(all.get(nm) ?? []), v]);
  }
  MACRO_DEFS = all;
  return out;
}
const STRING_MACRO_RE = /^(?:[LuU8]*"(?:[^"\\]|\\.)*"\s*)+$/;
const normalizeApi = (n: string) => n.replace(/^(?:_|std::)/, "").replace(/^.*::/, "").replace(/(?<=[a-z_])[AW]$/, "");
/** APIs some check models (sources, sinks, copies, allocators) -- see baseApi. */
let KNOWN_APIS: ReadonlySet<string> | null = null;
const knownApis = (): ReadonlySet<string> => KNOWN_APIS ??= new Set([
  ...Object.keys(OUT_PARAM_SOURCES), ...RETURN_SOURCES, ...Object.keys(COPY_INTO), ...UNBOUNDED_COPY, ...ALLOCATORS, ...Object.keys(DEREF_ARGS),
  ...Object.keys(FORMAT_ARG), ...Object.keys(SQL_ARG), ...Object.keys(PATH_ARG), ...Object.keys(LDAP_FILTER_ARG),
  "system", "wsystem", "popen", "wpopen", "execl", "execlp", "execle", "execv", "execvp", "execve", "CreateProcess", "ShellExecute", "WinExec",
]);
/**
 * `CreateFileA` / `ldap_search_ext_sW` / `_wfopen` / `EXECL` (#define'd to execl) -> the base API name. A macro
 * defined in several preprocessor arms (`EXECUTE` -> WinExec on Windows, system elsewhere) names the arm's API a check
 * models -- whichever configuration is built, that call runs.
 */
const baseApi = (name: string) => {
  const defs = (MACRO_DEFS.get(name) ?? []).filter(d => /^[A-Za-z_]\w*$/.test(d));
  const real = defs.find(d => knownApis().has(normalizeApi(d))) ?? defs[0] ?? name;
  // `ALLOCA` is the usual spelling of alloca where the platform header that maps it is not in the scanned file
  return real === "ALLOCA" ? "alloca" : normalizeApi(real);
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

/** A declared type whose objects hold elements the engine tracks as one slot (`vector<int *>`, `std::list<char *>`, `map<int, int *>`). */
const CONTAINER_TYPE_RE = /(?:^|::|\b)(?:vector|list|deque|map|unordered_map|set|unordered_set|queue|stack)\s*</;
/** Union types of the file being scanned: every member of a union object shares one slot. */
let UNION_TYPES: ReadonlySet<string> = new Set();
function collectUnionTypes(root: SyntaxNode): Set<string> {
  const names = new Set<string>();
  for (const u of findAllNodes(root, "union_specifier")) {
    const n = field(u, "name")?.text;
    if (n) names.add(n);
    const par = u.parent;
    if (par?.type === "type_definition") for (const d of named(par)) if (d !== u && (d.type === "type_identifier" || d.type === "primitive_type")) names.add(d.text);
  }
  return names;
}

/** What one pointer variable is known to be: how it was allocated (ALLOC_*), whether it was released, whether it may be NULL unchecked. */
interface MemState {
  alloc: number; freed: number; unchecked: number;
  /** bytes the pointer's buffer holds, when known (`malloc(50)`, `char buf[50]`) */
  cap?: number;
  /** characters of the string it holds, when known (filled with memset / strcpy of a literal) */
  len?: number;
  /** an out-parameter reached through a pointer (`int **p`, `&data` at the call), not a reference */
  viaPtr?: boolean;
}
/** What a function leaves behind: the pointer it returns, what it stores through out-parameters, and how many bytes it
 * writes into each buffer it was handed (a constant-size memcpy / strcpy / loop), keyed like freesParam. */
interface MemSummary { ret?: MemState; outs: Map<number, MemState>; writes: Map<string, number> }
const MEM_KINDS = ["alloc", "freed", "unchecked"] as const;
const memEmpty = (s: MemState | undefined): boolean => !s || (!s.alloc && !s.freed && !s.unchecked && s.cap === undefined && s.len === undefined);

/** `out`: a parameter the caller's object is reached through -- a C++ reference (`char *&data`), or a pointer the
 * function never re-points (`char *buf`, `char **p`) so its writes land in the caller's buffer. */
interface LocalFn {
  name: string; decl: SyntaxNode; body: SyntaxNode | null; params: Array<{ name: string; index: number; out?: "ref" | "ptr"; bufLike: boolean }>; isStatic: boolean;
  /** the class a member function belongs to: its class body, or the `T::` of an out-of-line definition; null when free */
  cls: string | null;
  /** identity: `Class::name` for a member function, the name for a free one (see resolveLocalFns) */
  id: string;
}

interface EngineCtx {
  filePath: string;
  content: string;
  lines: string[];
  root: SyntaxNode;
  /** same-file functions by identity (LocalFn.id) */
  fns: Map<string, LocalFn>;
  /** bare name -> every same-file function of that name (see resolveLocalFns) */
  byName: Map<string, LocalFn[]>;
  /** local variables holding a lambda (`auto run = [&](...) { ... };`), per walk -- walked where they run */
  lambdas: Map<string, SyntaxNode>;
  /** lambdas being walked right now (a lambda that calls itself, or two that call each other, stop there) */
  lambdaStack?: Set<number>;
  /** unique_ptr variable -> raw pointers taken from it with .get(), per walk */
  borrows: Map<string, Set<string>>;
  /** container variable -> iterators / data() pointers taken from it, per walk (invalidated by a reallocating call) */
  views: Map<string, Set<string>>;
  /** class -> its direct base classes (`class Bad : public Base`) */
  bases: Map<string, string[]>;
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
  freesParam: Map<string, Map<string, Release>>;
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
  /** per walk: C++ reference -> the variable it is bound to (`char *&dataRef = data;`), for good. Every write to
   * one of them is made to all (setVar / taintBuffer), so a read of either sees the object's value. */
  refs: Map<string, string>;
  /** per walk: `*pp` -> the variable a pointer-to-pointer points at (`int **pp = &data;`), so a write or read through pp is data's */
  slots: Map<string, string>;
  /** fn id -> the memory state it leaves behind: what it returns, and what it stores through each out-parameter */
  memSum: Map<string, MemSummary>;
  /** fn id -> memory state of file-scope pointers at a call site (`badData = data; badSink();`): the callee is walked in it */
  seededGlobals: Map<string, Map<string, MemState>>;
  /** while a function is summarised: bytes it writes into each named buffer (see MemSummary.writes) */
  writeObs?: Map<string, number>;
  /** fn -> (out-parameter index -> (source -> classes it stores there)); source -1 is input the fn reads itself,
   * j >= 0 is its parameter j (`copy(dst, src)` wrapping strcpy) */
  fills: Map<string, Map<number, Map<number, number>>>;
}

/** The other names a C++ reference binds to `name`: `r` and `x` after `T &r = x;` always name one object. */
function refPeers(name: string, ctx: EngineCtx): string[] {
  if (!ctx.refs.size) return [];
  const root = ctx.refs.get(name) ?? name;
  const out = root !== name ? [root] : [];
  for (const [r, t] of ctx.refs) if (t === root && r !== name) out.push(r);
  return out;
}

const KIND_KEY = (kind: string, name: string) => `!${kind}:${name}`;

/**
 * The pointers a condition genuinely tests against null: `p`, `!p`, `p == NULL` / `p != nullptr` / `p == 0` (either side),
 * through `&&` / `||` / parentheses, and an assignment in the test (`(p = malloc(n)) == NULL`). `p == other`, a call that
 * merely mentions `p`, or a comparison of something else prove nothing about `p`.
 */
/** Does a #if / #ifdef chain end in a plain #else (so one arm is always compiled)? */
function hasFinalElse(node: SyntaxNode): boolean {
  let cur: SyntaxNode | null = node;
  while (cur) {
    const alt: SyntaxNode | null = field(cur, "alternative");
    if (!alt) return false;
    if (alt.type === "preproc_else") return true;
    cur = alt;
  }
  return false;
}

function nullTestedNames(cond: SyntaxNode): string[] {
  const out: string[] = [];
  const nullish = (n: SyntaxNode | null) => !!n && (n.type === "null" || n.type === "nullptr" || n.text === "NULL" || n.text === "nullptr" || (n.type === "number_literal" && /^0[uUlL]*$/.test(n.text)));
  const unwrap = (n: SyntaxNode | null): SyntaxNode | null => {
    let cur = n;
    while (cur && (cur.type === "parenthesized_expression" || cur.type === "condition_clause")) cur = named(cur)[0] ?? null;
    return cur;
  };
  const subject = (n: SyntaxNode | null): string | null => {
    const u = unwrap(n);
    if (!u) return null;
    if (u.type === "identifier") return u.text;
    if (u.type === "assignment_expression") { const l = unwrap(field(u, "left")); return l?.type === "identifier" ? l.text : null; }
    return null;
  };
  const visit = (n: SyntaxNode | null) => {
    const u = unwrap(n);
    if (!u) return;
    if (u.type === "identifier" || u.type === "assignment_expression") { const nm = subject(u); if (nm) out.push(nm); return; }
    if (u.type === "unary_expression" && u.text.startsWith("!")) { const nm = subject(field(u, "argument") ?? named(u)[0] ?? null); if (nm) out.push(nm); return; }
    if (u.type === "binary_expression") {
      const op = (u.children.find(c => c && !c.isNamed && /^(?:&&|\|\||==|!=)$/.test(c.type))?.type) ?? "";
      const l = field(u, "left"), r = field(u, "right");
      if (op === "&&" || op === "||") { visit(l); visit(r); return; }
      if (op === "==" || op === "!=") {
        if (nullish(unwrap(r))) { const nm = subject(l); if (nm) out.push(nm); }
        else if (nullish(unwrap(l))) { const nm = subject(r); if (nm) out.push(nm); }
      }
    }
  };
  visit(cond);
  return out;
}

function emit(ctx: EngineCtx, id: AstTaintCppId, node: SyntaxNode, sourceExpr: string, sinkExpr: string, detail?: string) {
  const line = lineOf(node);
  // one finding per sink node: two calls of one class on a line are two findings (the scanner folds them into one record per id+line)
  const key = `${id}:${line}:${node.startIndex}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.findings.push({
    id, line, sinkExpr, sourceExpr,
    detail: detail ?? `Tainted expression '${sourceExpr.slice(0, 80)}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
    trace: (cppTraceRoot = ctx.root, buildBackwardTraceGeneric(ctx.filePath, node, sourceExpr, sinkExpr, cppTraceResolver)),
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
// The file the trace being built is in (set by emit) -- functionInfo / callSitesOf are asked by name only.
let cppTraceRoot: SyntaxNode | null = null;
function paramNamesCpp(fn: SyntaxNode): string[] {
  let d = field(fn, "declarator");
  while (d && d.type !== "function_declarator") d = field(d, "declarator");
  return named(field(d, "parameters")).filter(p => /parameter_declaration/.test(p.type)).map(p => declaredName(field(p, "declarator")) ?? "");
}
function returnsOfCpp(fn: SyntaxNode): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  const visit = (n: SyntaxNode) => {
    if (n !== fn && (n.type === "function_definition" || n.type === "lambda_expression")) return;
    if (n.type === "return_statement" && named(n)[0]) out.push(named(n)[0]);
    for (const c of named(n)) visit(c);
  };
  visit(fn);
  return out;
}
const cppTraceResolver: TraceResolver<SyntaxNode> = {
  enclosingScope, assignmentsIn,
  fileScope: n => { let c = n; while (c.parent) c = c.parent; return c; },
  position: n => n.startIndex, line: lineOf, text: n => n.text,
  scopeInfo: scope => {
    const name = scope.type === "function_definition" ? functionName(scope) : null;
    return name ? { name, params: paramNamesCpp(scope), line: lineOf(scope) } : null;
  },
  functionInfo: name => {
    const fn = cppTraceRoot ? findAllNodes(cppTraceRoot, "function_definition").find(f => functionName(f) === name) : undefined;
    if (!fn) return null;
    const returns = returnsOfCpp(fn).map(r => ({ text: r.text, position: r.startIndex, line: lineOf(r) }));
    return { scope: fn, params: paramNamesCpp(fn), line: lineOf(fn), returns };
  },
  callSitesOf: name => (cppTraceRoot ? findAllNodes(cppTraceRoot, "call_expression") : [])
    .filter(c => { const f = field(c, "function"); return f?.type === "identifier" && f.text === name; })
    .map(c => ({ scope: enclosingScope(c), position: c.startIndex, line: lineOf(c), text: c.text })),
};

// ── Vocabulary ─────────────────────────────────────────────────────────────────────────────────────────────

/** Reads that fill a caller's buffer with outside data: API -> index of the buffer argument (-1: every arg after the format). */
const OUT_PARAM_SOURCES: Record<string, number> = {
  fgets: 0, fgetws: 0, gets: 0, gets_s: 0, read: 1, recv: 1, recvfrom: 1, fread: 0, ReadFile: 1, getline: 0, getdelim: 0,
  scanf: -1, wscanf: -1, fscanf: -2, fwscanf: -2, sscanf: -3, swscanf: -3, scanf_s: -1, fscanf_s: -2,
  // TLS / BIO streams (OpenSSL), Apache httpd request bodies and buckets, FastCGI, WinInet, positional reads
  SSL_read: 1, SSL_peek: 1, SSL_read_ex: 1, SSL_peek_ex: 1, BIO_read: 1, BIO_read_ex: 1, BIO_gets: 1, ap_get_client_block: 1, apr_bucket_read: 1,
  FCGX_GetStr: 0, FCGX_GetLine: 0, X509_NAME_oneline: 1, InternetReadFile: 1, pread: 1,
  // Boost.Asio sockets: `sock.read_some(buffer(b))` / `boost::asio::read(sock, buffer(b))` (the `read` entry above)
  read_some: 0, receive: 0, receive_from: 0, async_read_some: 0, async_receive: 0, async_receive_from: 0,
  getcwd: -9, // not a source: placeholder so the trace resolver doesn't treat it as one (see isSource below)
};
/** `boost::asio::buffer(b)` / `asio::buffer(b, n)` wraps the buffer a read fills: the buffer is its first argument. */
function unwrapBufferArg(a: SyntaxNode | null | undefined): SyntaxNode | null {
  if (!a) return null;
  if (a.type === "call_expression") {
    const ci = callInfo(a);
    if (/^(?:buffer|const_buffer|mutable_buffer)$/.test(ci.name.split("::").pop() ?? "") && ci.args[0]) return ci.args[0];
  }
  return a;
}
const RETURN_SOURCES = new Set(["getenv", "wgetenv","secure_getenv", "GetCommandLine", "readline",
  // Qt's environment, HTTP request accessors of libevent / libmicrohttpd / FastCGI / Wt / POCO
  "qgetenv", "qEnvironmentVariable", "evhttp_request_get_uri", "evhttp_find_header", "evhttp_uri_get_path", "evhttp_uri_get_query", "evhttp_decode_uri",
  "MHD_lookup_connection_value", "FCGX_GetParam", "getCgiValue", "getParameter", "getParameterValues", "headerValue", "clientFileName", "internalPath",
  "mg_http_get_header",
  // an archive member's name is whatever its author wrote ("../../etc/cron.d/x"): libarchive, libzip
  "archive_entry_pathname", "archive_entry_pathname_w", "archive_entry_pathname_utf8", "zip_get_name"]);
/** Copies: destination argument index 0 takes the taint of the listed source arguments. */
const COPY_INTO: Record<string, number[]> = {
  strcpy: [1], strncpy: [1], strcat: [1], strncat: [1], wcscpy: [1], wcsncpy: [1], wcscat: [1], wcsncat: [1],
  memcpy: [1], memmove: [1], wmemcpy: [1], wmemmove: [1], lstrcpy: [1], lstrcat: [1], StringCbCopy: [2], StringCchCopy: [2],
  sprintf: [1, 2, 3, 4, 5, 6], swprintf: [2, 3, 4, 5, 6, 7], snprintf: [2, 3, 4, 5, 6, 7], snwprintf: [2, 3, 4, 5, 6, 7],
  vsprintf: [1, 2], vsnprintf: [2, 3], vsnwprintf: [2, 3],
  strcpy_s: [2], strcat_s: [2], strncpy_s: [2], memcpy_s: [2], wcscpy_s: [2],
};
/**
 * Calls that fill an out-parameter from another argument: API -> [destination index, source indexes]. Apache's `ap_args_to_table(r, &GET)`,
 * `ap_parse_form_data(r, NULL, &pairs, ...)`, `apr_brigade_flatten(bb, buf, &len)`; POCO's `StreamCopier::copyToString(in, out)`.
 */
const FILL_OUT: Record<string, [number, number[]]> = {
  ap_args_to_table: [1, [0]], ap_parse_form_data: [2, [0]], apr_brigade_flatten: [1, [0]], copyToString: [1, [0]], copyStream: [1, [0]], copyStreamUnbuffered: [1, [0]],
};
/** Calls whose result carries the taint of ANY argument (a pool comes first in Apache's: `apr_pstrcat(r->pool, "ls ", r->args, NULL)`). */
const ANY_ARG_PASSTHROUGH = new Set([
  "apr_pstrcat", "apr_pstrdup", "apr_pstrndup", "apr_psprintf", "apr_pstrmemdup", "apr_table_get", "apr_table_getm", "ap_getword", "ap_getword_nc", "ap_getword_white",
  "ap_getword_white_nc", "ap_getword_conf", "ap_getword_conf_nc", "apr_array_pop", "apr_array_pstrcat", "ap_make_dirstr_parent", "ap_make_full_path",
  "load", "parse", "QString", "QByteArray", "QUrl", "QVariant", "make_address", "make_address_v4", "make_address_v6", "endpoint",
]);
/**
 * Classes whose objects hold what a client sent (a request, a socket, a form, a text widget, a parsed command line): any string a method returns
 * is input. Matched on the last segment of the declared type.
 */
const INPUT_CLASSES = new Set([
  "request", "Request", "HTTPServerRequest", "HttpRequest", "HttpRequestPtr", "HTTPRequest", "QHttpServerRequest", "request_rec", "evhttp_request", "FCGX_Request",
  "mg_http_message", "WEnvironment", "HTMLForm", "variables_map", "QTcpSocket", "QSslSocket", "QAbstractSocket", "QUdpSocket", "QNetworkReply", "QWebSocket", "QLineEdit",
  "QTextEdit", "QPlainTextEdit", "QUrlQuery", "WLineEdit", "WTextArea", "WTextEdit", "WFileUpload", "WebRequest", "HttpServerRequest",
]);
/** Methods of such an object that return no client text (a length, a flag, a status) -- everything else is input. */
const INPUT_NON_DATA_RE = /^(?:size|length|empty|count|has\w*|contains|find|begin|end|method|version|error\w*|isValid|isOpen|is\w+|write\w*|close|state|bytesAvailable|atEnd|port|status\w*|keepAlive|setHeader|set\w+|disconnect\w*)$/;
/** Conversions that keep a string's content: carry the receiver's (or first argument's) taint through. */
const STRING_CARRY_METHODS = new Set([
  "asString", "toStdString", "toUtf8", "toLatin1", "toLocal8Bit", "constData", "trimmed", "simplified", "toString", "getQuery", "getPath", "getHost", "getFragment",
  "getPathEtc", "getPathAndQuery", "first", "second", "left", "right", "mid", "toLower", "toUpper", "queryItemValue", "text", "fromUtf8", "fromLatin1", "fromLocal8Bit",
  "fromStdString", "fromEncoded", "fromRawData", "u8string", "generic_string", "native", "string_view", "get", "as", "s", "path",
]);
/** Constructors of a type that runs, opens or connects to what it is given: declared type -> [class, argument index, message]. */
const CTOR_SINKS: Array<[RegExp, AstTaintCppId, number]> = [
  [/^(?:QFile|QDir|QFileInfo|QSaveFile|QDirIterator|QTemporaryFile)$/, "path-traversal", 0],
  [/^(?:File|FileInputStream|FileOutputStream|Path|DirectoryIterator)$/, "path-traversal", 0],
  [/^(?:QLibrary|QPluginLoader)$/, "eval-exec", 0],
  [/^(?:HTTPClientSession|HTTPSClientSession|SocketAddress|StreamSocket|SecureStreamSocket|WebSocket)$/, "ssrf", 0],
  [/^(?:QNetworkRequest|QWebSocket)$/, "ssrf", 0],
  [/^(?:child)$/, "command-injection", 0],
  [/^(?:Statement)$/, "sql-injection", 1],
];
/** Receivers' methods that run a statement / command / connection, by the declared class of the receiver: class -> [method regex, rule, argument index]. */
const METHOD_SINKS: Array<[RegExp, RegExp, AstTaintCppId, number]> = [
  [/^QSqlQuery$|^QSqlDatabase$/, /^(?:exec|prepare|exec_)$/, "sql-injection", 0],
  [/^(?:Database|Statement|Session|DbClient)$/, /^(?:exec|execAndGet|execute|execSqlSync|execSqlAsync|execSqlAsyncFuture|prepare)$/, "sql-injection", 0],
  [/^QProcess$/, /^(?:start|startCommand|setProgram)$/, "command-injection", 0],
  [/^(?:resolver|tcp_resolver)$/, /^(?:resolve|async_resolve)$/, "ssrf", 0],
  [/^(?:socket|tcp_socket|stream|basic_stream_socket|QTcpSocket|QSslSocket|QAbstractSocket)$/, /^(?:connect|async_connect|connectToHost|connectToHostEncrypted)$/, "ssrf", 0],
  [/^(?:QNetworkRequest)$/, /^setUrl$/, "ssrf", 0],
  [/^(?:QLibrary)$/, /^setFileName$/, "eval-exec", 0],
  [/^(?:File)$/, /^(?:remove|copyTo|moveTo|renameTo|createFile|list)$/, "path-traversal", 0],
];
/** Unbounded copies: writing attacker data through these overflows the destination. */
const UNBOUNDED_COPY = new Set(["strcpy", "strcat", "wcscpy", "wcscat", "sprintf", "swprintf", "vsprintf", "lstrcpy", "lstrcat"]);
const RETURN_PASSTHROUGH = propagatorNames("cpp", "call-args");
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
  ap_rprintf: 1, ap_log_rerror: 5,
};
const SQL_ARG: Record<string, number> = {
  sqlite3_get_table: 1, sqlite3_exec: 1, sqlite3_prepare: 1, sqlite3_prepare_v2: 1, sqlite3_prepare_v3: 1, sqlite3_prepare16: 1,
  mysql_query: 1, mysql_real_query: 1, PQexec: 1, PQsendQuery: 1, SQLExecDirect: 1, SQLPrepare: 1,
};
const PATH_ARG: Record<string, number> = {
  apr_file_open: 1, apr_dir_open: 1, apr_stat: 1, fopen: 0, freopen: 0, wfopen: 0, open: 0, openat: 1, creat: 0, CreateFile: 0, remove: 0, unlink: 0, rmdir: 0, rename: 0,
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
      const arg = field(e, "argument");
      // `u.role`: its own field write (if any) and u's own value -- not what another field of u was given
      if (arg?.type === "identifier") return (k ? env.get(k) ?? 0 : 0) | groupMask(arg.text, env, ctx, true);
      return (k ? env.get(k) ?? 0 : 0) | mask(arg, env, ctx);
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

/** `u.*`: what was written into any field of u (see taintBuffer) -- part of u as a whole, not of its other fields. */
const FIELDS_KEY = (name: string) => `${name}.*`;

/** A variable's value, with its alias group; `ownOnly` leaves out what its fields were given (a field read). */
function groupMask(name: string, env: Env, ctx: EngineCtx, ownOnly = false): number {
  if (!env.has(name) && ctx.globalNames.has(name)) return ctx.globalTaint.get(name) ?? 0;
  const fields = ownOnly ? 0 : env.get(FIELDS_KEY(name)) ?? 0;
  const g = ctx.aliases.get(name);
  if (!g) return (env.get(name) ?? 0) | fields;
  let m = 0;
  for (const [n, gid] of ctx.aliases) if (gid === g) m |= env.get(n) ?? 0;
  return m | (env.get(name) ?? 0) | fields;
}

const definitionCounts = new NodeCache<Map<string, number>>();
function definitionCount(root: SyntaxNode, name: string): number {
  let counts = definitionCounts.get(root);
  if (!counts) {
    counts = new Map();
    for (const f of findAllNodes(root, "function_definition")) { const n = functionName(f); if (n) counts.set(n, (counts.get(n) ?? 0) + 1); }
    definitionCounts.set(root, counts);
  }
  return counts.get(name) ?? 0;
}

/** The variable a receiver chain starts at: `req.url_params`, `request.query()`, `(*j)["c"]`, `p->first`. */
function receiverRoot(e: SyntaxNode | null): string | null {
  let cur: SyntaxNode | null = e;
  for (let i = 0; cur && i < 12; i++) {
    switch (cur.type) {
      case "identifier": return cur.text;
      case "call_expression": cur = field(cur, "function"); break;
      case "field_expression": case "subscript_expression": case "pointer_expression": cur = field(cur, "argument"); break;
      case "parenthesized_expression": cur = named(cur)[0] ?? null; break;
      default: return null;
    }
  }
  return null;
}

function callMask(call: SyntaxNode, env: Env, ctx: EngineCtx): number {
  const { name, recv, args } = callInfo(call);
  const api = baseApi(name);
  if (RETURN_SOURCES.has(api)) return ALL;
  // `req->getParameter("n")`, `request.query().get("n")`, `form.get("c")`, `socket->readAll()`: a method of a request / socket / form object returns what the client sent
  if (recv && !INPUT_NON_DATA_RE.test(api)) {
    const root = receiverRoot(recv);
    const cls = root ? declaredClassOf(root, call) : null;
    if (cls && INPUT_CLASSES.has(cls)) return ALL;
  }
  // Apache / Qt / Boost plumbing: the result keeps what any argument holds
  if (ANY_ARG_PASSTHROUGH.has(api)) return args.reduce((acc, a) => acc | mask(a, env, ctx), 0);
  // sqlite3_mprintf("... '%s'", x): a statement built from x -- unless every substitution is %q / %Q / %w (SQLite's own quoting)
  if (api === "sqlite3_mprintf" || api === "sqlite3_vmprintf") {
    const fmt = stringValue(args[0] ?? null);
    const quoted = fmt !== null && /%[qQw]/.test(fmt) && !/%(?:\d+)?[sSdxXcf]/.test(fmt);
    const m = args.slice(1).reduce((acc, a) => acc | mask(a, env, ctx), 0);
    return quoted ? applySanitizer(m, SinkClass.SQL) : m;
  }
  // a conversion that keeps the text (`.toStdString()`, `.asString()`, `QString::fromUtf8(x)`, `.trimmed()`)
  if (STRING_CARRY_METHODS.has(api) && (recv || args.length > 0)) {
    const carried = recv ? mask(recv, env, ctx) : mask(args[0] ?? null, env, ctx);
    if (carried) return carried;
  }
  // the shared sanitizer table (taint/sanitizers.ts, the model registry's sanitizer models): atoi/strtol/stoi...
  const clears = sanitizerClears("cpp", api);
  if (clears !== null) return applySanitizer(mask(args[0] ?? null, env, ctx), clears);
  if (RETURN_PASSTHROUGH.has(api)) return recv ? mask(recv, env, ctx) : mask(args[0] ?? null, env, ctx);
  if (recv && /^(?:append|insert|replace|assign|operator\+=)$/.test(api)) return mask(recv, env, ctx) | args.reduce((m, a) => m | mask(a, env, ctx), 0);
  // a local function: what its return carries from these arguments, plus what it reads itself (of every function
  // the call may run -- see resolveLocalFns)
  const target = ctx.fnAlias.get(name) ?? name;
  const fns = resolveLocalFns(call, target, recv, ctx);
  if (fns.length) {
    let m = 0;
    for (const fn of fns) {
      m |= ctx.intrinsic.get(fn.id) ?? 0;
      const prop = ctx.propagating.get(fn.id);
      if (prop) for (const [i, surviving] of prop) m |= mask(args[i] ?? null, env, ctx) & surviving;
    }
    return m;
  }
  // a function in another file of the batch: what its return carries (input it reads itself; what flows through from an argument)
  if (!recv) {
    const aux = ctx.crossFileFacts?.get(AUX_PREFIX + target);
    if (aux) {
      let far = 0;
      for (const f of aux) {
        if (f.id === "taint-ret") far |= f.sinkClass;
        else if (f.id === "taint-prop") far |= mask(args[f.index] ?? null, env, ctx) & f.sinkClass;
      }
      return far;
    }
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
  // `if (n < 0 || n > MAX) return;`: where the condition is false BOTH operands are, so each one's false-arm bound holds
  if (op === "||") return [...guardsOf(field(e, "left"), ctx), ...guardsOf(field(e, "right"), ctx)].filter(g => g.holds === "false");
  const l = field(e, "left"), r = field(e, "right");
  const ln = l?.type === "identifier" ? l.text : null, rn = r?.type === "identifier" ? r.text : null;
  // a literal, sizeof, a constant-looking name or a local -- or arithmetic over those: `(10)`, `sizeof(b) / sizeof(b[0])`, `N - 1`
  const isBound = (n: SyntaxNode | null): boolean => {
    if (!n) return false;
    if (n.type === "parenthesized_expression") return isBound(named(n)[0] ?? null);
    if (n.type === "binary_expression") return isBound(field(n, "left")) && isBound(field(n, "right"));
    if (n.type === "cast_expression") return isBound(field(n, "value"));
    return n.type === "number_literal" || n.type === "sizeof_expression" || /^[A-Z_][A-Z0-9_]*$/.test(n.text)
      || (n.type === "identifier" && !!ctx.current && !ctx.current.params.some(p => p.name === n.text));
  };
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
    for (const n of [name, ...refPeers(name, ctx)]) env.set(n, orInto ? (env.get(n) ?? 0) | value : value);
  };
  /** Taint a buffer through an out-parameter: every name in its alias group, and the references bound to it. */
  const taintBuffer = (name: string, value: number, env: Env) => {
    const base = name.split(".")[0];
    const g = ctx.aliases.get(base);
    env.set(name, (env.get(name) ?? 0) | value);
    // `u.name = x`: that field, and the object as a whole (`u.*`, read with u) -- not u's other fields
    if (name !== base) env.set(FIELDS_KEY(base), (env.get(FIELDS_KEY(base)) ?? 0) | value);
    if (g) for (const [n, gid] of ctx.aliases) if (gid === g) env.set(n, (env.get(n) ?? 0) | value);
    for (const p of refPeers(base, ctx)) env.set(p, (env.get(p) ?? 0) | value);
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
    const src = slotOf(from);
    if (!src || src === to) return;
    for (const k of ["freed", "alloc", "unchecked"]) {
      const v = env.get(KIND_KEY(k, src));
      if (v) env.set(KIND_KEY(k, to), v);
    }
    const cap = ctx.capacity.get(src);
    if (cap !== undefined) ctx.capacity.set(to, cap);
    const len = ctx.strLen.get(groupKey(src));
    if (len !== undefined) ctx.strLen.set(groupKey(to), len);
  };
  const unwrapValue = (v: SyntaxNode | null): SyntaxNode | null => {
    let s = v;
    while (s && (s.type === "cast_expression" || s.type === "parenthesized_expression")) s = s.type === "cast_expression" ? field(s, "value") : named(s)[0] ?? null;
    return s;
  };
  /** The variable whose memory state a pointer-valued expression reads: `p`; `dataRef` (a reference names the variable it was
   * bound to, however that is reassigned later -- an assignment drops it from its alias group, the reference stays); `*pp`
   * (what a pointer-to-pointer points at: the variable it was set to, else the slot `*pp` itself); a member or element
   * (see memberSlot). */
  const slotOf = (v: SyntaxNode | null): string | null => {
    const s = unwrapValue(v);
    if (!s) return null;
    if (s.type === "identifier") return ctx.refs.get(s.text) ?? s.text;
    if (s.type === "pointer_expression" && s.text.startsWith("*")) {
      const o = unwrapValue(field(s, "argument") ?? named(s)[0] ?? null);
      if (o?.type === "identifier") return ctx.slots.get(`*${o.text}`) ?? `*${o.text}`;
    }
    return memberSlot(s);
  };
  /** The slot a member or element of `base` is tracked under: a union's members share one (`u.*`), a container's elements share one (`c[*]`). */
  const slotFor = (base: string | null, suffix: string): string | null => {
    if (!base) return null;
    if (suffix === "") return base;
    if (suffix.startsWith(".")) return ctx.slots.has(`u:${base}`) ? `${base}.*` : `${base}${suffix}`;
    if (suffix.startsWith("[")) return ctx.slots.has(`c:${base}`) ? `${base}[*]` : suffix === "[*]" ? null : `${base}${suffix}`;
    return null;
  };
  /** `s.f`, `p->f`, `arr[2]`, `vec[i]`, `vec.back()`: the member / element of a variable that a pointer is stored in or read from. */
  const memberSlot = (s: SyntaxNode | null): string | null => {
    if (!s) return null;
    if (s.type === "field_expression") {
      const b = unwrapValue(field(s, "argument")), f = field(s, "field")?.text;
      return b?.type === "identifier" && f ? slotFor(b.text, `.${f}`) : null;
    }
    if (s.type === "subscript_expression") {
      const b = unwrapValue(field(s, "argument"));
      if (b?.type !== "identifier") return null;
      if (ctx.slots.has(`c:${b.text}`)) return slotFor(b.text, "[*]");
      const idx = (named(field(s, "indices"))[0] ?? field(s, "index"))?.text ?? "";
      return /^\d+$/.test(idx) ? slotFor(b.text, `[${idx}]`) : null;
    }
    if (s.type === "call_expression") {
      const ci = callInfo(s);
      return ci.recv?.type === "identifier" && ctx.slots.has(`c:${ci.recv.text}`) && /^(?:back|front|at|top)$/.test(ci.name) ? slotFor(ci.recv.text, "[*]") : null;
    }
    return null;
  };
  /** The variable an out-argument names: `data`, or `&data`. */
  const argSlot = (a: SyntaxNode | null): string | null => {
    const s = unwrapValue(a);
    if (s?.type === "pointer_expression" && s.text.startsWith("&")) return slotOf(field(s, "argument") ?? named(s)[0] ?? null);
    return s?.type === "identifier" ? slotOf(s) : null;
  };
  /** What a pointer argument points at: `&data` -> data; a pointer-to-pointer variable `pp` -> what it was set to. */
  const pointeeSlot = (a: SyntaxNode | null): string | null => {
    const s = unwrapValue(a);
    if (s?.type === "pointer_expression" && s.text.startsWith("&")) return slotOf(field(s, "argument") ?? named(s)[0] ?? null);
    return s?.type === "identifier" ? ctx.slots.get(`*${s.text}`) ?? `*${s.text}` : null;
  };
  /** The caller-side slot a summary key (`0`, `0*`, `0.f`, `0[2]`, `g:name`) names at this call, and the argument it came through. */
  const keyTarget = (key: string, args: SyntaxNode[]): { slot: string; arg: SyntaxNode | null } | null => {
    const km = /^(?:(\d+)|g:(\w+))(.*)$/.exec(key);
    if (!km) return null;
    const [, idx, gname, suffix] = km;
    if (idx !== undefined) {
      const a = args[Number(idx)];
      if (!a) return null;
      const slot = suffix === "" ? argSlot(a) : suffix === "*" ? pointeeSlot(a) : slotFor(argSlot(a), suffix);
      return slot ? { slot, arg: a } : null;
    }
    const slot = suffix === "" ? gname : suffix === "*" ? ctx.slots.get(`*${gname}`) ?? `*${gname}` : slotFor(gname, suffix);
    return slot ? { slot, arg: null } : null;
  };
  const readState = (name: string, env: Env): MemState => ({
    alloc: env.get(KIND_KEY("alloc", name)) ?? 0, freed: env.get(KIND_KEY("freed", name)) ?? 0, unchecked: env.get(KIND_KEY("unchecked", name)) ?? 0,
    cap: ctx.capacity.get(name), len: ctx.strLen.get(groupKey(name)),
  });
  const writeState = (name: string, st: MemState, env: Env) => {
    for (const k of MEM_KINDS) { if (st[k]) env.set(KIND_KEY(k, name), st[k]); else env.delete(KIND_KEY(k, name)); }
    if (st.cap !== undefined) ctx.capacity.set(name, st.cap); else ctx.capacity.delete(name);
    if (st.len !== undefined) ctx.strLen.set(groupKey(name), st.len); else ctx.strLen.delete(groupKey(name));
  };
  /** The state a call's result is in, from the callee's summary (a function in this file, or one in another file of the batch). */
  const retStateOf = (v: SyntaxNode | null): MemState | undefined => {
    const e = unwrapValue(v);
    if (e?.type !== "call_expression") return undefined;
    const ci = callInfo(e);
    const own = resolveLocalFns(e, ctx.fnAlias.get(ci.name) ?? ci.name, ci.recv, ctx);
    if (own.length === 1) return ctx.memSum.get(own[0].id)?.ret;
    if (own.length === 0 && !ci.recv) return crossFileMem(ctx.fnAlias.get(ci.name) ?? ci.name)?.ret;
    return undefined;
  };
  const crossFileMem = (fn: string): MemSummary | undefined => {
    const facts = ctx.crossFileFacts?.get(AUX_PREFIX + fn);
    return facts ? decodeMemFacts(facts) : undefined;
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
    env.delete(KIND_KEY("invalid", name)); env.delete(KIND_KEY("moved", name));
  };
  /**
   * What a new value of `nm` says about other memory: `q = realloc(p, n)` frees p (when the result lands elsewhere);
   * `it = v.begin()` / `p = v.data()` borrow v's storage (a reallocating call invalidates them); `b = std::move(up)`
   * leaves the unique_ptr up empty.
   */
  const noteMemoryEffects = (nm: string, v: SyntaxNode | null, at: SyntaxNode, env: Env) => {
    const old = reallocSource(v);
    if (old && old !== nm) env.set(KIND_KEY("freed", old), 1);
    if (v?.type === "call_expression") {
      const ci = callInfo(v);
      if (ci.recv?.type === "identifier" && VIEW_METHODS_RE.test(ci.name) && isReallocatingContainer(ci.recv.text, at)) {
        ctx.views.set(ci.recv.text, new Set([...(ctx.views.get(ci.recv.text) ?? []), nm]));
      }
      if (/^(?:std::)?move$/.test(ci.name) && ci.args[0]?.type === "identifier" && isUniquePtr(ci.args[0].text, at)) env.set(KIND_KEY("moved", ci.args[0].text), 1);
    }
  };
  /** A reallocating call on container `c` (push_back, insert, clear, ...): its iterators and data() pointers dangle. */
  const invalidateViews = (c: string, env: Env) => {
    for (const v of ctx.views.get(c) ?? []) env.set(KIND_KEY("invalid", v), 1);
    ctx.views.delete(c);
  };
  /** A function of this file run as a callback with these argument masks (`std::thread t(run, x)`): walked with them. */
  const seedCallbackFn = (fnName: string, masks: number[]) => {
    const fns = (ctx.byName.get(fnName) ?? []).filter(f => !f.cls);
    if (fns.length !== 1) return;
    const f = fns[0];
    let seeded = ctx.seeded.get(f.id);
    masks.forEach((am, i) => { if ((am & ALL) && f.params[i]) { seeded ??= new Map(); seeded.set(i, (seeded.get(i) ?? 0) | am); } });
    if (seeded) ctx.seeded.set(f.id, seeded);
  };
  const recordAlloc = (name: string, value: SyntaxNode | null, env: Env) => {
    // `int *data = *dataPtr;` / `data = dataRef;` where that names the very variable being assigned: its state stands
    if (slotOf(value) === name) return;
    resetMemory(name, env);
    // `data = badSource(data)`: the callee returns an allocation (or one already released, or one never NULL-checked)
    const ret = retStateOf(value);
    if (ret && !memEmpty(ret)) writeState(name, ret, env);
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
    // a pointer copied from it (`char *alias = ptr;`) names the same memory: freed too
    const g = ctx.aliases.get(name);
    if (g) for (const [n, gid] of ctx.aliases) if (gid === g && n !== name) env.set(KIND_KEY("freed", n), 1);
  };
  /** Raw pointers borrowed from a unique_ptr (`int *raw = up.get();`): up's reset / reassignment frees what they name. */
  const releaseBorrows = (owner: string, env: Env) => {
    for (const raw of ctx.borrows.get(owner) ?? []) env.set(KIND_KEY("freed", raw), 1);
    ctx.borrows.delete(owner);
  };
  /** A read or write through `name` (deref, index, member access, passing it on). */
  const touchVar = (name: string, at: SyntaxNode, env: Env, deref: boolean) => {
    if (opts.quiet || loopRepeat > 0) return;
    if (env.get(KIND_KEY("freed", name))) {
      emit(ctx, "use-after-free", at, name, at.text.slice(0, 40), `'${name}' is used after it was freed on this path — the memory may already belong to another allocation`);
    } else if (deref && env.get(KIND_KEY("invalid", name))) {
      emit(ctx, "use-after-free", at, name, at.text.slice(0, 40), `'${name}' points into a container's storage that was reallocated since (push_back / insert / clear / ...) — the iterator or pointer dangles; take it again after the change`);
    }
    if (deref && env.get(KIND_KEY("moved", name))) {
      emit(ctx, "null-dereference", at, name, at.text.slice(0, 40), `'${name}' is dereferenced after std::move handed its object to another owner — it is empty (null) now`);
      env.delete(KIND_KEY("moved", name));
    }
    if (deref && env.get(KIND_KEY("unchecked", name))) {
      emit(ctx, "null-dereference", at, name, at.text.slice(0, 40), `'${name}' comes from an allocator that returns NULL on failure and is dereferenced without a NULL check`);
      env.delete(KIND_KEY("unchecked", name));
    }
  };
  /** Names a condition tests (`if (p == NULL)`, `if (!p)`, `if (p)`): no longer an unchecked allocation. */
  const markChecked = (cond: SyntaxNode | null, env: Env) => {
    if (!cond) return;
    for (const nm of nullTestedNames(cond)) env.delete(KIND_KEY("unchecked", nm));
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
      const targets = slot >= 0 ? [unwrapBufferArg(args[slot])] : args.slice(-slot);
      for (const t of targets) { const nm = rootName(t ?? null); if (nm) taintBuffer(nm, ALL, env); }
      if (api === "gets" && !opts.quiet) emit(ctx, "buffer-overflow", call, "stdin", "gets", "gets() reads an unbounded line into a fixed buffer — any input longer than the buffer overflows it (removed from C11); use fgets");
      // scanf("%s", buf): an unbounded %s conversion
      const fmtIdx = slot === -1 ? 0 : slot === -2 ? 1 : slot === -3 ? 1 : -1;
      const fmt = fmtIdx >= 0 ? stringValue(args[fmtIdx]) : null;
      if (fmt && /%s|%\[/.test(fmt) && !opts.quiet) emit(ctx, "buffer-overflow", call, "input", api, `${api}("${fmt.slice(0, 20)}") reads a string with no field width into a fixed buffer — bound it (%99s) or use fgets`);
    }
    if (api === "getline" && args.length === 2 && args[1]) { const nm = rootName(args[1]); if (nm) taintBuffer(nm, ALL, env); } // std::getline(cin, s)

    // out-parameter filled from another argument (ap_args_to_table(r, &GET), StreamCopier::copyToString(in, out))
    const fill = FILL_OUT[api];
    if (fill && args[fill[0]]) {
      const src = fill[1].reduce((acc, i) => acc | (argM[i] ?? 0), 0);
      const dest = rootName(unwrapBufferArg(args[fill[0]]));
      if (dest && src) taintBuffer(dest, src, env);
    }

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
      checkConstantOverflow(call, api, args, env);
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
    // WinExec(cmdLine, show) runs a command line, like system()
    if (/^(?:system|wsystem|popen|wpopen|WinExec)$/.test(api) && args[0]) fireOn(ctx, "command-injection", call, args[0], argM[0] ?? 0, api);
    // apr_proc_create(&proc, program, args, env, attr, pool): the program (and, run through a shell, its arguments)
    if (api === "apr_proc_create" && args[1]) fireOn(ctx, "command-injection", call, args[1], argM[1] ?? 0, api);
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
    // libcurl URL (models/sinks.ts)
    for (const { model, positions } of sinkModelsFor("cpp", api)) {
      const when = model.args.whenArg;
      if (when && !new RegExp(when.pattern).test(args[when.index]?.text ?? "")) continue;
      for (const p of positions) if (args[p]) fireOn(ctx, model.rule as AstTaintCppId, call, args[p], argM[p] ?? 0, sinkLabel(model, api));
    }
    // Qt / POCO / Boost / Apache: a command, statement, path or address the call is given (by the receiver's declared class, or the written class)
    {
      const fnText = (field(call, "function")?.text ?? "").replace(/\s+/g, "");
      if (/^(?:Poco::)?Process::launch$|^QProcess::(?:start|startDetached|execute)$|^(?:boost::)?process::system$/.test(fnText) && args[0]) fireOn(ctx, "command-injection", call, args[0], argM[0] ?? 0, fnText);
      if (/^QNetworkRequest$|^QDesktopServices::openUrl$/.test(fnText) && args[0]) fireOn(ctx, "ssrf", call, args[0], argM[0] ?? 0, fnText);
      if (recv) {
        const root = receiverRoot(recv);
        const cls = root ? declaredClassOf(root, call) : null;
        if (cls) for (const [clsRe, methodRe, id, idx] of METHOD_SINKS) {
          if (clsRe.test(cls) && methodRe.test(api) && args[idx]) fireOn(ctx, id, call, args[idx], argM[idx] ?? 0, `${cls}.${api}`);
        }
      }
    }
    // loading a library the caller names
    if (/^(?:dlopen|LoadLibrary|LoadLibraryEx)$/.test(api) && args[0]) fireOn(ctx, "eval-exec", call, args[0], argM[0] ?? 0, name);
    // libxml2 told to substitute entities / load the DTD: an external entity in the document reads local files or
    // fetches URLs (XXE) -- whatever the document's origin, the parser configuration is the defect
    if (!opts.quiet && ((/^xml(?:Read(?:Memory|File|Doc|Fd|IO)|CtxtRead(?:Memory|File|Doc|Fd|IO)|CtxtUseOptions)$/.test(api)
        && args.some(a => /\bXML_PARSE_(?:NOENT|DTDLOAD)\b/.test(a.text))) || (api === "xmlSubstituteEntitiesDefault" && args[0]?.text === "1"))) {
      emit(ctx, "xxe", call, name, name, `${name}(...) enables entity substitution / DTD loading (the NOENT / DTDLOAD parse options) — an external entity in the document can read local files or reach internal URLs; drop those options (libxml2 ≥ 2.9 leaves them off by default)`);
    }
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
    const resolved = resolveLocalFns(call, ctx.fnAlias.get(name) ?? name, recv, ctx);
    // one function -- or several member functions of one class hierarchy (any override may run: each is walked)
    const targets = resolved.length === 1 || (resolved.length > 1 && resolved.every(f => !!f.cls)) ? resolved : [];
    for (const fn of targets) {
      const target = fn.id;
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
        if (a.type !== "identifier" || !fn.params[i]) continue;
        // a parameter the callee frees: its allocation kind is judged at this call, but whether it may be NULL still travels
        for (const k of frees?.has(String(i)) ? ["unchecked"] : ["alloc", "unchecked"]) {
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
    const facts = !recv && targets.length === 0 ? ctx.crossFileFacts?.get(ctx.fnAlias.get(name) ?? name) : undefined;
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
          trace: crossFileTrace((cppTraceRoot = ctx.root, buildBackwardTraceGeneric(ctx.filePath, call, a.text, name, cppTraceResolver)), name, fact),
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
  const observeWrite = (dest: string, bytes: number) => {
    if (ctx.writeObs && bytes > (ctx.writeObs.get(dest) ?? 0)) ctx.writeObs.set(dest, bytes);
  };
  const checkConstantOverflow = (call: SyntaxNode, api: string, args: SyntaxNode[], env: Env) => {
    void env;
    const dest = rootName(args[0] ?? null);
    if (!dest || dest.includes(".")) return;
    const cap = ctx.capacity.get(dest);
    if (cap === undefined && !ctx.writeObs) return;
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
    if (need !== undefined) observeWrite(dest, need);
    if (need !== undefined && cap !== undefined && need > cap && !opts.quiet) {
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
      if (elem) observeWrite(buf.text, (lastIndex + 1) * elem);
      if (cap === undefined || !elem || (lastIndex + 1) * elem <= cap || opts.quiet) continue;
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
          // `up = nullptr;` / `up = std::make_unique<T>(...)`: up's old object is destroyed
          if (op === "=" && ctx.borrows.has(nm)) releaseBorrows(nm, env);
          setVar(nm, rm, env, op !== "=");
          // a global written here: what it holds when the function returns is what other functions read (see
          // flushGlobals) -- `g = input; g = "ls";` leaves it clean
          if (ctx.globalNames.has(nm) && !ctx.speculative) globalWrites.add(nm);
          if (op === "=") {
            // a new value: the old buffer's size and contents no longer describe it
            ctx.capacity.delete(nm);
            if (!ctx.aliases.has(nm)) ctx.strLen.delete(nm);
            ctx.aliases.delete(nm);
            if (ctx.views.has(nm)) invalidateViews(nm, env);   // the container now holds other storage
            recordAlloc(nm, r, env);
            copyMemory(nm, r, env);
            noteMemoryEffects(nm, r, e, env);
            const rn = r?.type === "identifier" ? r.text : null;
            if (rn && (ctx.capacity.has(rn) || ctx.aliases.has(rn))) alias(nm, rn);
          }
        } else {
          // *pp = data: the variable pp points at now holds that allocation (`*dataPtr = (int *)malloc(...)`)
          if (op === "=" && l?.type === "pointer_expression" && l.text.startsWith("*")) {
            const slot = slotOf(l);
            if (slot) { recordAlloc(slot, r, env); copyMemory(slot, r, env); }
          }
          // s.f = data / arr[2] = data / vec[i] = data: the member or element holds that allocation
          if (op === "=" && l && (l.type === "field_expression" || l.type === "subscript_expression")) {
            const ms = memberSlot(l);
            if (ms) { recordAlloc(ms, r, env); copyMemory(ms, r, env); }
          }
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
        // a lambda runs here: called through its variable (`run(x)`), invoked in place (`[&]{ ... }()`), or handed to
        // the call as a callback (`std::for_each(b, e, [](auto& s) { ... })`, `std::thread t(f)`) -- its parameters
        // then get what the call's other arguments carry (the container behind the iterators)
        // up.reset() / up.reset(other): the object up held is destroyed -- pointers borrowed from it now dangle
        if (recv?.type === "identifier" && name === "reset" && ctx.borrows.has(recv.text)) releaseBorrows(recv.text, env);
        // v.push_back(x) / v.clear() / ...: v may move its storage -- its iterators and data() pointers dangle
        if (recv?.type === "identifier" && INVALIDATING_RE.test(name) && ctx.views.has(recv.text)) invalidateViews(recv.text, env);
        // std::thread(run, x) / std::async(run, x) / std::async(std::launch::async, run, x): run is called with x
        if (!recv && /^(?:std::)?(?:thread|jthread|async)$/.test(name)) {
          const fi = args.findIndex(a => a.type === "identifier" && (ctx.byName.get(a.text) ?? []).some(f => !f.cls));
          if (fi >= 0) seedCallbackFn(args[fi].text, args.slice(fi + 1).map(a => m(a, env)));
        }
        // a container a value is stored into holds it: v.push_back(x) / q.push(x) / s.insert(x) / m.emplace(k, x)
        if (recv && /^(?:push_back|emplace_back|push_front|emplace_front|push|emplace|insert|insert_or_assign|try_emplace)$/.test(name)) {
          const nm = rootName(recv);
          const v = args.reduce((acc, a) => acc | m(a, env), 0);
          if (nm && v) taintBuffer(nm, v, env);
        }
        // std::swap(a, b): each now holds the other's value
        if (!recv && /^(?:std::)?swap$/.test(name.replace(/^::/, "")) && args.length === 2 && args.every(a => a.type === "identifier")) {
          const [a, b] = [args[0].text, args[1].text];
          const ma = env.get(a) ?? 0, mb = env.get(b) ?? 0;
          setVar(a, mb, env, false); setVar(b, ma, env, false);
        }
        // an asynchronous read fills its buffer before the completion handler (a lambda argument) runs
        if (/^async_/.test(name.split("::").pop() ?? "")) {
          const slot0 = OUT_PARAM_SOURCES[baseApi(name)];
          const buf = slot0 !== undefined && slot0 >= 0 ? rootName(unwrapBufferArg(args[slot0])) : null;
          if (buf) taintBuffer(buf, ALL, env);
        }
        const lam = fnNode?.type === "lambda_expression" ? fnNode : fnNode?.type === "identifier" ? ctx.lambdas.get(fnNode.text) : undefined;
        if (lam) walkLambda(lam, args.map(a => m(a, env)), env);
        for (const [i, a] of args.entries()) {
          const cb = a.type === "lambda_expression" ? a : a.type === "identifier" ? ctx.lambdas.get(a.text) : undefined;
          if (!cb) continue;
          const carried = args.reduce((acc, o, j) => (j === i ? acc : acc | m(o, env) | baseVarMask(o, env)), recv ? m(recv, env) : 0);
          walkLambda(cb, [carried], env, true);
        }
        const api = baseApi(name);
        // free releases; a local function that frees its parameter releases that argument; everything else that
        // takes the pointer uses it
        // (the one same-file function the call runs, by identity -- see resolveLocalFns)
        const own = resolveLocalFns(e, ctx.fnAlias.get(name) ?? name, recv, ctx);
        const ownId = own.length === 1 ? own[0].id : undefined;
        const farFacts = own.length === 0 && !recv ? ctx.crossFileFacts?.get(AUX_PREFIX + (ctx.fnAlias.get(name) ?? name)) : undefined;
        const frees = ownId ? ctx.freesParam.get(ownId) : farFacts ? crossFileReleases(farFacts) : undefined;
        const farUses = farFacts ? crossFileUses(farFacts) : [];
        if (/^(?:free|cfree|kfree|g_free)$/.test(api) && args[0]) { const nm = rootName(args[0]); if (nm && args[0].type === "identifier") freeVar(nm, e, "free", env); }
        else for (const [i, a] of args.entries()) {
          const nm = a.type === "identifier" ? a.text : null;
          if (!nm) continue;
          const dIdx = DEREF_ARGS[api];
          const how = frees?.get(String(i));
          // a callee in another file that dereferences the pointer before freeing it: an unchecked allocation is used there
          if (how && env.get(KIND_KEY("unchecked", nm)) && !env.get(KIND_KEY("freed", nm)) && farUses.some(u => u.state === "unchecked" && u.key === String(i))) touchVar(nm, a, env, true);
          if (how) freeVar(nm, e, how, env); else touchVar(nm, a, env, dIdx === -1 || dIdx === i || farUses.some(u => u.state === "unchecked" && u.key === String(i)));
        }
        // a callee in another file that dereferences / reads, through a pointer-to-pointer, a member or an element, a pointer
        // that is unchecked or already freed here
        for (const u of farUses) {
          const km = /^(\d+)(.+)$/.exec(u.key);
          if (!km) continue;
          const a = args[Number(km[1])];
          if (!a) continue;
          const t = km[2] === "*" ? pointeeSlot(a) : slotFor(argSlot(a), km[2]);
          if (!t) continue;
          // a pointer that is already freed is a use-after-free, whatever else is said about its NULL check
          if (u.state === "unchecked" && env.get(KIND_KEY("freed", t))) continue;
          touchVar(t, a, env, u.state === "unchecked");
        }
        // what the callee releases beyond the argument itself: what it points at (`badSink(&data)` freeing `*dataPtr`), a
        // member or element of it (`myStruct.first`, `dataArray[2]`), and file-scope pointers (`badData`)
        if (frees) for (const [key, how] of frees) {
          const km = /^(?:(\d+)|g:(\w+))(.*)$/.exec(key);
          if (!km || (km[1] !== undefined && km[3] === "")) continue;
          const [, idx, gname, suffix] = km;
          let target: string | null = null;
          if (idx !== undefined) {
            const a = args[Number(idx)];
            if (!a) continue;
            target = suffix === "*" ? pointeeSlot(a) : slotFor(argSlot(a), suffix);
          } else target = suffix === "" ? gname : suffix === "*" ? ctx.slots.get(`*${gname}`) ?? `*${gname}` : slotFor(gname, suffix);
          if (target) freeVar(target, e, how, env);
        }
        if (recv?.type === "identifier") touchVar(recv.text, recv, env, fnNode?.text.includes("->") ?? false);
        checkCall(e, env);
        // a local function that fills an out-parameter (`badSource(data)` with `char *&data`, `fill(buf)`): the
        // caller's argument now holds what the function stored there
        const fill = ownId ? ctx.fills.get(ownId) : undefined;
        if (fill) for (const [i, sources] of fill) {
          const nm = rootName(args[i] ?? null);
          if (!nm) continue;
          let v = 0;
          for (const [j, cls] of sources) v |= j < 0 ? cls : m(args[j] ?? null, env) & cls;
          if (v) taintBuffer(nm, v, env);
        }
        // c.push_back(data) / c.insert(c.end(), 1, data): an element of the container is that allocation
        if (recv?.type === "identifier" && ctx.slots.has(`c:${recv.text}`) && /^(?:push_back|push_front|push|emplace_back|emplace_front|insert|emplace)$/.test(api) && args.length > 0) {
          const slot = slotFor(recv.text, "[*]");
          if (slot) copyMemory(slot, args[args.length - 1], env);
        }
        // an out-parameter a function in another file fills with input it read (or copied from another argument)
        if (farFacts) for (const f of farFacts) {
          if (f.id !== "taint-fill") continue;
          const nm = rootName(args[f.index] ?? null);
          if (!nm) continue;
          const j = Number(f.sinkExpr.split("|")[0]);
          const v = j < 0 ? f.sinkClass : m(args[j] ?? null, env) & f.sinkClass;
          if (v) taintBuffer(nm, v, env);
        }
        // what the callee leaves in a pointer the caller passed by reference (`void fill(int *&data)`, `fill(&data)`),
        // and the allocations file-scope pointers hold when it runs
        {
          const msum = ownId ? ctx.memSum.get(ownId) : own.length === 0 && !recv ? crossFileMem(ctx.fnAlias.get(name) ?? name) : undefined;
          // the callee writes N bytes into a buffer (an argument, what it points at, a member, a global) whose capacity is known here
          if (msum) for (const [key, bytes] of msum.writes) {
            const t = keyTarget(key, args);
            if (!t) continue;
            observeWrite(t.slot, bytes);   // while a summary is being built: this function writes it too
            const cap = ctx.capacity.get(t.slot);
            if (!opts.quiet && cap !== undefined && bytes > cap) {
              emit(ctx, "buffer-overflow", e, t.arg?.text ?? t.slot, name, `${name}() writes up to ${bytes} bytes into '${t.slot}', which holds ${cap} — the callee overflows the destination`);
            }
          }
          if (msum) for (const [i, st] of msum.outs) { const slot = st.viaPtr ? pointeeSlot(args[i] ?? null) : argSlot(args[i] ?? null); if (slot) writeState(slot, st, env); }
          if (ownId && !opts.quiet) {
            for (const g of ctx.globalNames) {
              const st = readState(g, env);
              if (memEmpty(st)) continue;
              // a global the callee releases is judged at this call (freeVar); whether it may be NULL still travels
              const seed: MemState = ctx.freesParam.get(ownId)?.has(`g:${g}`) ? { alloc: 0, freed: 0, unchecked: st.unchecked } : st;
              if (memEmpty(seed)) continue;
              const per = ctx.seededGlobals.get(ownId) ?? new Map<string, MemState>();
              per.set(g, seed);
              ctx.seededGlobals.set(ownId, per);
            }
          }
        }
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
        // *(base + i) / *(base - i): a read or write at an attacker-chosen offset from a pointer
        const inner = operatorOf(e) === "*" ? field(e, "argument") : null;
        const sum = inner?.type === "parenthesized_expression" ? named(inner)[0] : null;
        if (sum?.type === "binary_expression" && /^[-+]$/.test(operatorOf(sum)) && !opts.quiet) {
          const off = field(sum, "right");
          if (off && off.type !== "number_literal") fireOn(ctx, "buffer-overflow", e, off, m(off, env), "pointer offset", SinkClass.CONTROL,
            `Attacker-controlled offset '${off.text.slice(0, 40)}' is added to a pointer that is then dereferenced, with no bound check — it reads or writes outside the object`);
        }
        return;
      }
      case "subscript_expression": case "field_expression": {
        walkExpr(field(e, "argument"), env);
        if (e.type === "subscript_expression") for (const c of named(field(e, "indices"))) walkExpr(c, env);
        const base = field(e, "argument");
        if (base?.type === "identifier") touchVar(base.text, e, env, e.type === "subscript_expression" || e.text.includes("->"));
        // tbl[i] on an array of known size with an attacker-chosen, unchecked index
        if (e.type === "subscript_expression" && base?.type === "identifier" && ctx.capacity.has(base.text) && !opts.quiet) {
          const idx = named(field(e, "indices"))[0];
          if (idx && idx.type !== "number_literal" && idx.type !== "string_literal") fireOn(ctx, "buffer-overflow", e, idx, m(idx, env), `${base.text}[...]`, SinkClass.CONTROL,
            `Attacker-controlled index '${idx.text.slice(0, 40)}' is used on '${base.text}' with no bound check — an out-of-range index reads or writes outside the array`);
        }
        return;
      }
      case "binary_expression": {
        walkExpr(field(e, "left"), env); walkExpr(field(e, "right"), env);
        // std::cin >> s / in >> s: the right side is filled from the stream
        const l = field(e, "left");
        if (operatorOf(e) === ">>" && l && /(?:^|::)(?:cin|wcin)$|^(?:in|is|stream|file|ifs|input)$/.test(l.text.split(" >>")[0])) {
          const nm = rootName(field(e, "right")); if (nm) taintBuffer(nm, ALL, env);
          return;
        }
        // a string stream: `ss << x` puts x in it (the stream variable, or the left end of a `ss << a << b` chain);
        // `ss >> y` reads what it holds into y
        let head: SyntaxNode | null = l;
        while (head?.type === "binary_expression" && /^(?:<<|>>)$/.test(operatorOf(head))) head = field(head, "left");
        const stream = head?.type === "identifier" && /stringstream$/.test(declaredClassOf(head.text, e) ?? "") ? head.text : null;
        if (stream && operatorOf(e) === "<<") { const v = m(field(e, "right"), env); if (v) taintBuffer(stream, v, env); }
        // POCO Data: `session << "DELETE ... " + n, now;` builds a statement from the right operand (use(x) binds, so a call is judged by its own sink)
        if (operatorOf(e) === "<<" && !opts.quiet) {
          const left = field(e, "left");
          const lroot = left?.type === "identifier" ? left.text : null;
          const lcls = lroot ? declaredClassOf(lroot, e) : null;
          const right = field(e, "right");
          if (lcls && /^(?:Session|Statement)$/.test(lcls) && right && right.type !== "call_expression") fireOn(ctx, "sql-injection", e, right, m(right, env), `${lcls} <<`);
        }
        if (stream && operatorOf(e) === ">>") { const nm = rootName(field(e, "right")); const v = groupMask(stream, env, ctx); if (nm && v) taintBuffer(nm, v, env); }
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
      // `int *data = *dataPtr;` re-declares the variable it reads: its allocation state carries over
      if (!(d.type === "init_declarator" && slotOf(field(d, "value")) === nm)) resetMemory(nm, env);
      if (CONTAINER_TYPE_RE.test(typeText)) ctx.slots.set(`c:${nm}`, "1");
      else if (UNION_TYPES.has(typeText.replace(/\b(?:const|struct|union|volatile)\b|[\s*&]/g, ""))) ctx.slots.set(`u:${nm}`, "1");
      // `int **pp = &data;`: a write or read through pp is data's
      if (d.type === "init_declarator" && /\*\s*\*/.test(`${typeText}${target?.text ?? ""}`.replace(/\s+/g, ""))) {
        const iv = unwrapValue(field(d, "value"));
        if (iv?.type === "pointer_expression" && iv.text.startsWith("&")) { const t = slotOf(field(iv, "argument") ?? named(iv)[0] ?? null); if (t) ctx.slots.set(`*${nm}`, t); }
      }
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
        const argNames = ps.map(p => {
          const kids = named(p);
          const id = kids[0];
          // a bare name, or one subscripted (`req["X-U"]` reads as a type with an array declarator)
          return id?.type === "type_identifier" && env.has(id.text) && kids.slice(1).every(k => /^abstract_/.test(k.type)) ? id.text : null;
        });
        if (ps.length && argNames.every(Boolean)) {
          const am = argNames.reduce((acc, a) => acc | groupMask(a!, env, ctx), 0);
          env.set(nm, am);
          // QFile f(p) / QLibrary lib(name) / HTTPClientSession s(host) / process::child c(cmd) / SQLite::Statement q(db, sql)
          if (!opts.quiet) {
            const cls = classOfTypeText(typeText);
            for (const [re, id, idx] of CTOR_SINKS) {
              if (re.test(cls) && argNames[idx]) { fireOn(ctx, id, d, ps[idx], groupMask(argNames[idx]!, env, ctx), typeText); break; }
            }
          }
          if (/(?:^|::)(?:i|o)?fstream$/.test(typeText) && !opts.quiet) fireOn(ctx, "path-traversal", d, ps[0], groupMask(argNames[0]!, env, ctx), typeText);
          // `boost::archive::text_iarchive ia(is);` (parsed the same way) over a stream holding request data
          if (INPUT_ARCHIVE_RE.test(typeText.replace(/<.*$/, "")) && (am & ALL) && !opts.quiet) {
            emit(ctx, "insecure-deserialization", d, argNames[0]!, typeText,
              `'${argNames[0]}' holds request data and is read through ${typeText} — deserializing untrusted bytes can construct arbitrary registered types; parse a plain format (JSON with a schema) instead`);
          }
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
      // `struct mg_http_message *hm = (struct mg_http_message *) ev_data;`: an object of a request class holds what the client sent
      if (v && INPUT_CLASSES.has(classOfTypeText(typeText))) env.set(nm, (env.get(nm) ?? 0) | ALL);
      if (v?.type === "lambda_expression") ctx.lambdas.set(nm, v);
      // `int *raw = up.get();` with up a unique_ptr: raw lives only as long as up holds its object
      if (v?.type === "call_expression" && callInfo(v).name === "get" && callInfo(v).recv?.type === "identifier" && isUniquePtr(callInfo(v).recv!.text, d)) {
        const owner = callInfo(v).recv!.text;
        ctx.borrows.set(owner, new Set([...(ctx.borrows.get(owner) ?? []), nm]));
      }
      // `char *&dataRef = data;`: a reference names that variable from now on, whatever it is later assigned
      if (v?.type === "identifier" && target && (target.type === "reference_declarator" || findAllNodes(target, "reference_declarator").length)) {
        ctx.refs.set(nm, ctx.refs.get(v.text) ?? v.text);
      }
      recordAlloc(nm, v, env);
      copyMemory(nm, v, env);
      noteMemoryEffects(nm, v, d, env);
      // `char *data = dataRef;` names what the reference is bound to (its own alias group went stale when that variable was re-pointed)
      const vn0 = v?.type === "identifier" ? v.text : null;
      const vn = vn0 ? ctx.refs.get(vn0) ?? vn0 : null;
      if (vn && (ctx.capacity.has(vn) || ctx.aliases.has(vn) || /\*/.test(target?.text ?? ""))) alias(nm, vn);
      if (v?.type === "argument_list") {
        const cargs = named(v);
        // `std::thread t([&] { ... })` / `std::thread t(run, x)`: the callable runs with the other arguments
        for (const [i, a] of cargs.entries()) {
          const cb = a.type === "lambda_expression" ? a : a.type === "identifier" ? ctx.lambdas.get(a.text) : undefined;
          if (cb) walkLambda(cb, [cargs.reduce((acc, o, j) => (j === i ? acc : acc | m(o, env)), 0)], env, true);
        }
        if (/(?:^|::)j?thread$/.test(typeText) && cargs[0]?.type === "identifier") seedCallbackFn(cargs[0].text, cargs.slice(1).map(a => m(a, env)));
        // `boost::archive::text_iarchive ia(is)` over a stream holding request data: reading objects from it runs
        // the archive's type machinery on attacker-chosen bytes
        if (INPUT_ARCHIVE_RE.test(typeText.replace(/<.*$/, "")) && cargs[0] && !opts.quiet) {
          const sm = m(cargs[0], env);
          if (sm & ALL) emit(ctx, "insecure-deserialization", d, cargs[0].text, typeText,
            `'${cargs[0].text}' holds request data and is read through ${typeText} — deserializing untrusted bytes can construct arbitrary registered types; parse a plain format (JSON with a schema) instead`);
        }
      }
      // std::ifstream f(path) / std::fstream f(path, mode)
      if (v?.type === "argument_list" && /(?:^|::)(?:i|o)?fstream$/.test(typeText) && named(v)[0] && !opts.quiet) {
        fireOn(ctx, "path-traversal", d, named(v)[0], m(named(v)[0], env), typeText);
      }
      // QFile f(path) / QLibrary lib(name) / HTTPClientSession s(host) / SQLite::Statement q(db, sql) / process::child c(cmd): the constructor acts on its argument
      if (v?.type === "argument_list" && !opts.quiet) {
        const cls = classOfTypeText(typeText);
        for (const [re, id, idx] of CTOR_SINKS) {
          const a = named(v)[idx];
          if (re.test(cls) && a) { fireOn(ctx, id, d, a, m(a, env), typeText); break; }
        }
      }
    }
  };

  /** Globals this walk assigned, and the merge of what each holds where the function leaves (each return, the end). */
  const globalWrites = new Set<string>();
  const flushGlobals = (env: Env) => {
    for (const nm of globalWrites) {
      const v = (env.get(nm) ?? 0) & ALL;
      if (v) ctx.globalTaint.set(nm, (ctx.globalTaint.get(nm) ?? 0) | v);
    }
  };

  /** `v.begin()` / `v.cbegin()` / `v.data()`: what the container they come from holds. */
  const baseVarMask = (a: SyntaxNode, env: Env): number => {
    const fn = a.type === "call_expression" ? field(a, "function") : null;
    const base = fn?.type === "field_expression" ? rootName(field(fn, "argument")) : null;
    return base ? groupMask(base, env, ctx) : 0;
  };
  /**
   * Walk a lambda's body where it runs, in a copy of the environment there (captures by reference or by value both
   * see the values the caller holds), its parameters bound to `paramMasks` by position -- or, for a callback, every
   * parameter to `paramMasks[0]`. Not where it is merely written: a lambda that is never run reaches no sink.
   */
  const walkLambda = (lam: SyntaxNode, paramMasks: number[], env: Env, sameForAll = false) => {
    ctx.lambdaStack ??= new Set();
    if (ctx.lambdaStack.has(lam.id) || ctx.lambdaStack.size > 3) return;
    ctx.lambdaStack.add(lam.id);
    try {
      const inner: Env = new Map(env);
      // init captures: `[c = std::string(getenv("X"))]` / `[&r = buf]` bind c to that expression's value
      for (const cap of named(named(lam).find(k => k.type === "lambda_capture_specifier") ?? null)) {
        const l = field(cap, "left") ?? (cap.type === "lambda_capture_initializer" ? named(cap)[0] : null);
        const r = field(cap, "right") ?? (cap.type === "lambda_capture_initializer" ? named(cap)[named(cap).length - 1] : null);
        const nm = l ? rootName(l) ?? l.text.replace(/^&/, "") : null;
        if (nm && r && l !== r) inner.set(nm, m(r, env));
      }
      const decl = field(lam, "declarator");
      const params = named(decl ? field(decl, "parameters") : null).filter(p => /parameter_declaration/.test(p.type));
      params.forEach((p, i) => { const nm = declaredName(field(p, "declarator")); if (nm) inner.set(nm, (sameForAll ? paramMasks[0] : paramMasks[i]) ?? 0); });
      for (const nm of inputParamNames(params, "", lam)) inner.set(nm, ALL);
      walk(field(lam, "body"), inner);
    } finally {
      ctx.lambdaStack.delete(lam.id);
    }
  };

  const walk = (node: SyntaxNode | null, env: Env): boolean => {
    if (!node) return false;
    switch (node.type) {
      case "preproc_if": case "preproc_ifdef": {
        // The arms of #if / #ifdef / #else are alternative compilations, never one after the other: each is walked from the
        // state before the directive and the results are joined (a later arm no longer overwrites an earlier one).
        const ownStmts = (n: SyntaxNode): SyntaxNode[] => {
          const skip = new Set([field(n, "name")?.id, field(n, "condition")?.id, field(n, "alternative")?.id]);
          return named(n).filter(c => !skip.has(c.id) && !/comment$/.test(c.type));
        };
        const branches: Branch[] = [];
        let cur: SyntaxNode | null = node;
        while (cur) {
          const stmts = ownStmts(cur);
          branches.push({ body: (e) => walkStmts(stmts, e) });
          cur = field(cur, "alternative");
        }
        if (!hasFinalElse(node)) branches.push({ body: () => false });   // no #else: the arm may not be compiled
        return walkIfChain(env, branches);
      }
      case "compound_statement": case "translation_unit": case "preproc_else": case "preproc_elif":
      case "declaration_list": case "labeled_statement":
        return walkStmts(named(node), env);
      case "declaration": declare(node, env); return false;
      case "expression_statement": for (const c of named(node)) walkExpr(c, env); return false;
      case "return_statement": {
        const v = named(node)[0] ?? null;
        walkExpr(v, env);
        if (v?.type === "identifier") touchVar(v.text, v, env, false);
        opts.onReturn?.(v, env);
        flushGlobals(env);
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
        if (node.type === "for_statement") checkConstantLoopOverflow(node);
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
  /** Walk a function body; the globals it assigned keep what they hold where it ends. */
  const walkBody = (body: SyntaxNode | null, env: Env): boolean => {
    const t = walk(body, env);
    if (!t) flushGlobals(env);
    return t;
  };
  return { walk: walkBody, checkCall, kindOf: allocKindOf, slotOf, readState, unwrapValue };
}

// ── Functions, summaries and entry points ──────────────────────────────────────────────────────────────────

function collectFns(root: SyntaxNode): LocalFn[] {
  return findAllNodes(root, "function_definition").map(f => {
    let d = field(f, "declarator");
    while (d && d.type !== "function_declarator") d = field(d, "declarator");
    const body = field(f, "body");
    const params = named(field(d, "parameters")).filter(p => /parameter_declaration/.test(p.type))
      .map((p, index) => {
        const name = declaredName(field(p, "declarator")) ?? "";
        return { name, index, out: name ? outKind(field(p, "declarator"), name, body) : undefined, bufLike: BUFFER_PARAM_RE.test(p.text) };
      });
    const name = functionName(f) ?? "";
    const cls = memberClassOf(f, d);
    return {
      name, decl: f, body: field(f, "body"), params, cls, id: cls ? `${cls}::${name}` : name,
      isStatic: named(f).some(c => c.type === "storage_class_specifier" && c.text === "static"),
    };
  }).filter(f => !!f.name);
}

/** `class P { std::string t(...) { ... } }` -> "P"; `std::string P::t(...) { ... }` -> "P"; a free function -> null. */
function memberClassOf(fn: SyntaxNode, declarator: SyntaxNode | null): string | null {
  const nm = declarator ? field(declarator, "declarator") : null;
  if (nm?.type === "qualified_identifier") {
    const scope = field(nm, "scope")?.text.replace(/<.*$/, "").split("::").pop();
    if (scope && /^[A-Z_a-z]\w*$/.test(scope)) return scope;
  }
  for (let p = fn.parent; p; p = p.parent) {
    if (p.type === "class_specifier" || p.type === "struct_specifier") return field(p, "name")?.text ?? null;
    if (p.type === "function_definition") break;
  }
  return null;
}

// function/lambda node -> variable name -> declared class, built by ONE walk of the function (declaredClassOf used to walk the whole function again for every receiver it was asked about)
const declaredClassesCache = new NodeCache<Map<string, string>>();
function declaredClassesIn(fn: SyntaxNode): Map<string, string> {
  const hit = declaredClassesCache.get(fn);
  if (hit) return hit;
  const out = new Map<string, string>();
  for (const d of [...findAllNodes(fn, "parameter_declaration"), ...findAllNodes(fn, "declaration")]) {
    const t = field(d, "type")?.text.replace(/^(?:const|struct|class)\s+/, "").replace(/<.*$/, "").split("::").pop();
    if (!t || !/^[A-Za-z_]\w*$/.test(t)) continue;
    const declarators = d.type === "parameter_declaration" ? [field(d, "declarator")] : named(d).filter(c => c !== field(d, "type"));
    for (const x of declarators) {
      const n = x ? declaredName(x.type === "init_declarator" ? field(x, "declarator") : x) : null;
      if (n && !out.has(n)) out.set(n, t);   // the first declaration wins, as the per-lookup scan did
    }
  }
  declaredClassesCache.set(fn, out);
  return out;
}

/** The declared class of variable `name` where `site` is: a parameter or a local declared `T x` / `T* x` / `T& x`. */
function declaredClassOf(name: string, site: SyntaxNode): string | null {
  for (let cur: SyntaxNode | null = site; cur; cur = cur.parent) {
    if (cur.type !== "function_definition" && cur.type !== "lambda_expression") continue;
    const t = declaredClassesIn(cur).get(name);
    if (t) return t;
    if (cur.type === "function_definition") break;
  }
  return null;
}

/**
 * The same-file function(s) a call runs, by identity: `T::f(...)` T's; `this->m()` / an implicit member call the
 * enclosing class's; `x.m()` / `x->m()` the class x is declared as (a parameter or local); a free call the free
 * function. A receiver of unknown class: only a member name defined once in the file (any of several overrides could
 * run, so none is assumed). Two classes' same-named methods never stand in for each other.
 */
function resolveLocalFns(call: SyntaxNode, name: string, recv: SyntaxNode | null, ctx: EngineCtx): LocalFn[] {
  const cands = ctx.byName.get(name) ?? [];
  if (cands.length === 0) return [];
  const ofClass = (c: string) => cands.filter(f => f.cls === c);
  const fnNode = field(call, "function");
  if (!recv && fnNode?.type === "qualified_identifier") {
    const scope = field(fnNode, "scope")?.text.replace(/<.*$/, "").split("::").pop() ?? "";
    const own = ofClass(scope);
    return own.length ? own : cands.filter(f => !f.cls);
  }
  if (!recv) {
    const free = cands.filter(f => !f.cls);
    if (free.length) return free;
    return ctx.current?.cls ? ofClass(ctx.current.cls) : [];
  }
  const r = recv.type === "pointer_expression" ? field(recv, "argument") : recv;
  const cls = r?.type === "this" ? ctx.current?.cls ?? null : r?.type === "identifier" ? declaredClassOf(r.text, call) : null;
  if (cls) return viaHierarchy(cls, cands, ctx);
  const members = cands.filter(f => !!f.cls);
  return members.length === 1 && definitionCount(ctx.root, name) === 1 ? members : [];
}

/**
 * A member call on a `cls` object: cls's own method, else the nearest base class's (inherited) -- and every override
 * in a class deriving from cls, since a `Base *` may point at any of them (virtual dispatch).
 */
function viaHierarchy(cls: string, cands: LocalFn[], ctx: EngineCtx): LocalFn[] {
  const own = ancestorsOf(cls, ctx).map(c => cands.filter(f => f.cls === c)).find(fs => fs.length) ?? [];
  const overrides = descendantsOf(cls, ctx).flatMap(c => cands.filter(f => f.cls === c));
  return [...new Set([...own, ...overrides])];
}

/** A reference parameter, or a pointer one the body never re-points (`p = ...` would leave the caller's buffer). */
function outKind(declarator: SyntaxNode | null, name: string, body: SyntaxNode | null): "ref" | "ptr" | undefined {
  if (!declarator) return undefined;
  const has = (t: string) => declarator.type === t || findAllNodes(declarator, t).length > 0;
  if (has("reference_declarator")) return "ref";
  if (!has("pointer_declarator") && !has("array_declarator")) return undefined;
  const repointed = body ? findAllNodes(body, "assignment_expression").some(a => field(a, "left")?.type === "identifier" && field(a, "left")!.text === name) : false;
  return repointed ? undefined : "ptr";
}

type Release = "free" | "delete" | "delete[]";
/**
 * freesParam keys name what a function releases: `"0"` its parameter 0 (`free(p)`), `"0*"` what the parameter points at
 * (`int *data = *dataPtr; free(data);`), `"0.f"` a member (`myStruct.structFirst`), `"0[2]"` / `"0[*]"` an element of an
 * array / any element of a container, and `"g:name"` (+ the same suffixes) a file-scope variable it frees.
 */
function accessPath(v: SyntaxNode | null, alias: ReadonlyMap<string, string>): string | null {
  const unwrap = (x: SyntaxNode | null): SyntaxNode | null => {
    let e = x;
    while (e && (e.type === "cast_expression" || e.type === "parenthesized_expression")) e = e.type === "cast_expression" ? field(e, "value") : named(e)[0] ?? null;
    return e;
  };
  const e = unwrap(v);
  if (!e) return null;
  if (e.type === "identifier") return alias.get(e.text) ?? null;
  if (e.type === "pointer_expression" && e.text.startsWith("*")) {
    const o = unwrap(field(e, "argument") ?? named(e)[0] ?? null);
    return o?.type === "identifier" && alias.get(o.text) === "" ? "*" : null;
  }
  if (e.type === "field_expression") {
    const b = unwrap(field(e, "argument")), f = field(e, "field")?.text;
    return b?.type === "identifier" && f && alias.get(b.text) === "" ? `.${f}` : null;
  }
  if (e.type === "subscript_expression") {
    const b = unwrap(field(e, "argument"));
    const idx = (named(field(e, "indices"))[0] ?? field(e, "index"))?.text ?? "";
    return b?.type === "identifier" && alias.get(b.text) === "" && /^\d+$/.test(idx) ? `[${idx}]` : null;
  }
  if (e.type === "call_expression") {
    const ci = callInfo(e);
    return ci.recv?.type === "identifier" && alias.get(ci.recv.text) === "" && /^(?:back|front|at|top)$/.test(ci.name) ? "[*]" : null;
  }
  return null;
}

/** Every name that holds `root` or something reached from it, with how it is reached (see accessPath). */
function aliasPaths(pairs: ReadonlyArray<[string, SyntaxNode | null]>, root: string): Map<string, string> {
  const alias = new Map<string, string>([[root, ""]]);
  for (let pass = 0; pass < 3; pass++) {
    for (const [n, v] of pairs) {
      if (alias.has(n)) continue;
      const path = accessPath(v, alias);
      if (path !== null) alias.set(n, path);
    }
  }
  return alias;
}
/** What the memory analyses read of a function body, found in one traversal and shared: its declarations and plain
 * assignments as (name, value) pairs, its `delete`s and its calls. */
interface BodyShape { pairs: Array<[string, SyntaxNode | null]>; deletes: SyntaxNode[]; calls: SyntaxNode[] }
const SHAPE_TYPES: ReadonlySet<string> = new Set(["init_declarator", "assignment_expression", "delete_expression", "call_expression"]);
const shapeCache = new WeakMap<SyntaxNode, BodyShape>();
function bodyShape(body: SyntaxNode): BodyShape {
  const hit = shapeCache.get(body);
  if (hit) return hit;
  const shape: BodyShape = { pairs: [], deletes: [], calls: [] };
  for (const n of findAllNodes(body, SHAPE_TYPES)) {
    if (n.type === "init_declarator") { const name = declaredName(field(n, "declarator")); if (name) shape.pairs.push([name, field(n, "value")]); }
    else if (n.type === "assignment_expression") { const l = field(n, "left"); if (l?.type === "identifier" && operatorOf(n) === "=") shape.pairs.push([l.text, field(n, "right")]); }
    else if (n.type === "delete_expression") shape.deletes.push(n);
    else shape.calls.push(n);
  }
  shapeCache.set(body, shape);
  return shape;
}
/** The file-scope names a function's text mentions (a superset is fine: each is verified by the alias analysis). */
function mentionedGlobals(fn: LocalFn, globals: ReadonlySet<string>): string[] {
  const text = fn.decl.text;
  return [...globals].filter(g => text.includes(g));
}

function collectFreesParam(fns: ReadonlyMap<string, LocalFn>, globals: ReadonlySet<string>, far?: ReadonlyMap<string, readonly ParamSinkFact[]>): Map<string, Map<string, Release>> {
  const out = new Map<string, Map<string, Release>>();
  const calleeMap = (n: string): Map<string, Release> | undefined => out.get(n) ?? (far?.has(AUX_PREFIX + n) ? crossFileReleases(far.get(AUX_PREFIX + n)) : undefined);
  // one pass over each body: its declarations, assignments, deletes, calls and the file-scope names it mentions
  const shape = new Map<string, BodyShape & { globals: string[] }>();
  for (const [name, f] of fns) {
    if (!f.body) continue;
    shape.set(name, { ...bodyShape(f.body), globals: globals.size ? mentionedGlobals(f, globals) : [] });
  }
  for (let round = 0; round < 4; round++) {
    let changed = false;
    for (const [name, f] of fns) {
      const sh = shape.get(name);
      if (!f.body || !sh) continue;
      const map = out.get(name) ?? new Map<string, Release>();
      const before = map.size;
      const roots: Array<[string, string]> = [...f.params.filter(p => p.name).map(p => [String(p.index), p.name] as [string, string]), ...sh.globals.map(g => [`g:${g}`, g] as [string, string])];
      for (const [rootKey, root] of roots) {
        // every name that holds the root or something reached from it, with how it is reached
        const alias = aliasPaths(sh.pairs, root);
        const byPath = new Map<string, Set<string>>();
        for (const [n, path] of alias) byPath.set(path, (byPath.get(path) ?? new Set()).add(n));
        for (const [path, names] of byPath) {
          const key = `${rootKey}${path}`;
          if (map.has(key)) continue;
          const del = sh.deletes.find(d => named(d).some(c => c.type === "identifier" && names.has(c.text)));
          let how: Release | undefined = del ? (/\[\s*\]/.test(del.text) ? "delete[]" : "delete") : undefined;
          if (!how) for (const c of sh.calls) {
            const ci = callInfo(c);
            if (/^(?:free|cfree|kfree|g_free)$/.test(baseApi(ci.name))) {
              if (ci.args[0]?.type === "identifier" && names.has(ci.args[0].text)) { how = "free"; break; }
              continue;
            }
            const callee = calleeMap(ci.name);
            if (!callee) continue;
            // forwarded as argument k to a function that releases that parameter (or what it points at)
            for (const [k, a] of ci.args.entries()) {
              if (a.type !== "identifier" || !names.has(a.text)) continue;
              const direct = callee.get(String(k));
              if (direct) { how = direct; break; }
              if (path === "") { const via = callee.get(`${k}*`); if (via) { map.set(`${rootKey}*`, via); changed = true; } }
            }
            if (how) break;
          }
          if (how) map.set(key, how);
        }
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

function freshWalkState(ctx: EngineCtx) { ctx.aliases = new Map(); ctx.capacity = new Map(); ctx.strLen = new Map(); ctx.fnAlias = new Map(); ctx.refs = new Map(); ctx.slots = new Map(); ctx.lambdas = new Map(); ctx.borrows = new Map(); ctx.views = new Map(); }

/** `class Bad : public Base, private Mixin { ... }` -> Bad: [Base, Mixin]. */
function collectBases(root: SyntaxNode): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const c of [...findAllNodes(root, "class_specifier"), ...findAllNodes(root, "struct_specifier")]) {
    const name = field(c, "name")?.text;
    const clause = named(c).find(k => k.type === "base_class_clause");
    if (!name || !clause) continue;
    const bases = findAllNodes(clause, "type_identifier").map(t => t.text).concat(findAllNodes(clause, "qualified_identifier").map(q => q.text.split("::").pop()!));
    if (bases.length) out.set(name, [...new Set(bases)]);
  }
  return out;
}
/** A class and every class above it (its bases, theirs, ...). */
function ancestorsOf(cls: string, ctx: EngineCtx, seen = new Set<string>()): string[] {
  if (seen.has(cls)) return [];
  seen.add(cls);
  return [cls, ...(ctx.bases.get(cls) ?? []).flatMap(b => ancestorsOf(b, ctx, seen))];
}
/** Every class of the file deriving (directly or not) from `cls`. */
function descendantsOf(cls: string, ctx: EngineCtx): string[] {
  return [...ctx.bases.keys()].filter(c => c !== cls && ancestorsOf(c, ctx).includes(cls));
}

/** The declaration (parameter or local) of `name` in the function `site` is in, or null. */
function declarationOf(name: string, site: SyntaxNode): SyntaxNode | null {
  for (let cur: SyntaxNode | null = site; cur; cur = cur.parent) {
    if (cur.type !== "function_definition" && cur.type !== "lambda_expression") continue;
    for (const d of [...findAllNodes(cur, "parameter_declaration"), ...findAllNodes(cur, "declaration")]) {
      const ds = d.type === "parameter_declaration" ? [field(d, "declarator")] : named(d).filter(c => c !== field(d, "type"));
      if (ds.some(x => x && declaredName(x.type === "init_declarator" ? field(x, "declarator") : x) === name)) return d;
    }
    return null;
  }
  return null;
}
/** Is `name` a std::unique_ptr where `site` is -- declared as one, or initialised from make_unique? */
function isUniquePtr(name: string, site: SyntaxNode): boolean {
  return /\bunique_ptr\b|\bmake_unique\b/.test(declarationOf(name, site)?.text ?? "");
}
/** Is `name` a container whose growth reallocates its storage (vector, string, deque)? */
function isReallocatingContainer(name: string, site: SyntaxNode): boolean {
  return /\b(?:vector|deque|basic_string|w?string|u16string|u32string)\b/.test(field(declarationOf(name, site), "type")?.text ?? "");
}
/** `(char *)realloc(p, n)` -> p (an identifier), else null. */
function reallocSource(v: SyntaxNode | null): string | null {
  let g = v;
  while (g && (g.type === "cast_expression" || g.type === "parenthesized_expression")) g = g.type === "cast_expression" ? field(g, "value") : named(g)[0] ?? null;
  if (g?.type !== "call_expression" || !/^(?:realloc|reallocarray|_recalloc)$/.test(baseApi(callInfo(g).name))) return null;
  const p = callInfo(g).args[0];
  return p?.type === "identifier" ? p.text : null;
}
const VIEW_METHODS_RE = /^(?:begin|end|cbegin|cend|rbegin|rend|data|c_str)$/;
const INVALIDATING_RE = /^(?:push_back|emplace_back|push_front|emplace_front|insert|emplace|resize|reserve|clear|erase|shrink_to_fit|assign|append|pop_back|swap)$/;
const INPUT_ARCHIVE_RE = /(?:^|::)(?:text|binary|xml|polymorphic_text|polymorphic_binary|polymorphic_xml)_iarchive$|(?:^|::)(?:Binary|PortableBinary|JSON|XML)InputArchive$/;

/** What `fn` returns with parameter `seedIndex` tainted (null: none); `outs` collects what it leaves in each
 * out-parameter other than the seeded one, at every return and at the end of the body. */
function returnMask(fn: LocalFn, ctx: EngineCtx, seedIndex: number | null, outs?: Map<number, number>): number {
  if (!fn.body) return 0;
  let surviving = 0;
  const saved = { findings: ctx.findings, seen: ctx.seen, suppressed: ctx.suppressed, seeded: ctx.seeded, aliases: ctx.aliases, capacity: ctx.capacity, strLen: ctx.strLen, fnAlias: ctx.fnAlias, refs: ctx.refs, current: ctx.current, speculative: ctx.speculative };
  ctx.findings = []; ctx.seen = new Set(); ctx.suppressed = undefined; ctx.seeded = new Map(); ctx.current = fn;
  ctx.speculative = saved.speculative || seedIndex !== null;
  freshWalkState(ctx);
  const env: Env = new Map();
  for (const p of fn.params) env.set(p.name, seedIndex === p.index ? ALL : 0);
  const collectOuts = (en: Env) => {
    if (!outs) return;
    for (const p of fn.params) {
      if (!p.out || p.index === seedIndex) continue;
      const v = groupMask(p.name, en, ctx) & ALL;
      if (v) outs.set(p.index, (outs.get(p.index) ?? 0) | v);
    }
  };
  createWalker(ctx, { quiet: true, onReturn: (e, en) => { surviving |= mask(e, en, ctx); collectOuts(en); } }).walk(fn.body, env);
  collectOuts(env);
  Object.assign(ctx, saved);
  return surviving & ALL;
}

/** Merge one walk's out-parameter masks into `fills` under `source`; true when anything grew. */
function mergeFills(ctx: EngineCtx, fn: string, source: number, outs: ReadonlyMap<number, number>, exclude = 0): boolean {
  let grew = false;
  for (const [i, raw] of outs) {
    const v = raw & ~exclude;
    if (!v) continue;
    const byOut = ctx.fills.get(fn) ?? new Map<number, Map<number, number>>();
    const bySource = byOut.get(i) ?? new Map<number, number>();
    const next = (bySource.get(source) ?? 0) | v;
    if (next === (bySource.get(source) ?? 0)) continue;
    bySource.set(source, next); byOut.set(i, bySource); ctx.fills.set(fn, byOut);
    grew = true;
  }
  return grew;
}

// ── Memory-state facts: what a function in another file does to a pointer, carried as pseudo sink facts ──────────
// id "mem-state": index -1 = the returned pointer, index i = the pointer left in parameter i (sinkExpr "alloc,freed,unchecked");
// "mem-releases": a parameter / global / member is released (sinkExpr `free|key`); "mem-uses": one is touched while it is in a state
// (`unchecked|key`: dereferenced before any NULL check; `freed|key`: read after being freed) -- keys as in freesParam
// before any NULL check. They ride in the same cross-file map as the taint facts (so the batch digest covers them)
// and never match a taint class (sinkClass 0).
function decodeMemFacts(facts: readonly ParamSinkFact[]): MemSummary {
  const sum: MemSummary = { outs: new Map(), writes: new Map() };
  for (const f of facts) {
    if (f.id === "mem-writes") { const [bytes, key] = f.sinkExpr.split("|"); if (key) sum.writes.set(key, Number(bytes) || 0); continue; }
    if (f.id !== "mem-state") continue;
    const [alloc, freed, unchecked, via, cap, len] = f.sinkExpr.split(",");
    const st: MemState = { alloc: Number(alloc) || 0, freed: Number(freed) || 0, unchecked: Number(unchecked) || 0, viaPtr: via === "p", cap: cap ? Number(cap) : undefined, len: len ? Number(len) : undefined };
    if (f.index < 0) sum.ret = st; else sum.outs.set(f.index, st);
  }
  return sum;
}
function crossFileReleases(facts: readonly ParamSinkFact[] | undefined): Map<string, Release> {
  const out = new Map<string, Release>();
  for (const f of facts ?? []) if (f.id === "mem-releases") { const [how, key] = f.sinkExpr.split("|"); if (key) out.set(key, how as Release); }
  return out;
}
/** Auxiliary per-function facts (memory state, taint through returns and out-parameters) are keyed `m:<fn>` so they
 * never compete with the function's taint-sink facts for its capped list; a file-scope variable some function taints
 * is keyed `g:<name>`. */
const AUX_PREFIX = "m:";
/** The taint classes that cross a file boundary at a return, an out-parameter or a global: all of them. What is restricted is
 * WHICH parameters can carry it (see BUFFER_PARAM_RE). */
const CROSS_FILE_TAINT = ALL;
/** A parameter that can hold bytes the caller handed over: `char *`, `uint8_t *`, `void *`, `wchar_t buf[]`, a string. A struct
 * pointer or a scalar cannot: when `init(q, size)` writes `size` into `*q`, that does not make every `q` in every other file
 * attacker data (it did on curl: its connection structs became "tainted" and every size check after them a finding). */
const BUFFER_PARAM_RE = /\b(?:u?char|wchar_t|TCHAR|CHAR|WCHAR|u?int8_t|byte|BYTE|void|string|string_view|String|LPC?[TW]?STR|QString|QByteArray)\b[^()]*(?:[*\[]|\bstring(?:_view)?\b)|\bstd::(?:w?string|string_view)\b/;
const GLOBAL_PREFIX = "g:";
function crossFileUses(facts: readonly ParamSinkFact[] | undefined): Array<{ state: "unchecked" | "freed"; key: string }> {
  const out: Array<{ state: "unchecked" | "freed"; key: string }> = [];
  for (const f of facts ?? []) if (f.id === "mem-uses") { const [state, key] = f.sinkExpr.split("|"); if (key && (state === "unchecked" || state === "freed")) out.push({ state, key }); }
  return out;
}

/** Keep a flag only when every path agrees on it (a function that frees on one path and not another leaves it unknown). */
function agreeState(states: readonly MemState[]): MemState | undefined {
  if (states.length === 0) return undefined;
  const out: MemState = { alloc: states[0].alloc, freed: states[0].freed, unchecked: states[0].unchecked, cap: states[0].cap, len: states[0].len, viaPtr: states[0].viaPtr };
  for (const st of states) {
    for (const k of MEM_KINDS) if (st[k] !== out[k]) out[k] = 0;
    if (st.cap !== out.cap) out.cap = undefined;
    if (st.len !== out.len) out.len = undefined;
  }
  return memEmpty(out) ? undefined : out;
}

/** What `fn` leaves in memory-state terms: the pointer it returns, and what each reference / pointer-to-pointer
 * parameter holds when it returns -- each walked with nothing known about its parameters. */
function summarizeMem(fn: LocalFn, ctx: EngineCtx): MemSummary {
  const saved = { findings: ctx.findings, seen: ctx.seen, suppressed: ctx.suppressed, seeded: ctx.seeded, seededMem: ctx.seededMem, seededGlobals: ctx.seededGlobals, writeObs: ctx.writeObs, aliases: ctx.aliases, capacity: ctx.capacity, strLen: ctx.strLen, fnAlias: ctx.fnAlias, refs: ctx.refs, slots: ctx.slots, current: ctx.current, speculative: ctx.speculative };
  ctx.findings = []; ctx.seen = new Set(); ctx.suppressed = undefined; ctx.seeded = new Map(); ctx.seededMem = new Map(); ctx.seededGlobals = new Map(); ctx.current = fn;
  ctx.speculative = true;
  freshWalkState(ctx);
  const env: Env = new Map();
  for (const p of fn.params) env.set(p.name, 0);
  const rets: MemState[] = [];
  const outs = new Map<number, MemState[]>();
  const collectOuts = (en: Env, w: ReturnType<typeof createWalker>) => {
    for (const p of fn.params) {
      if (!p.out) continue;
      const st = w.readState(p.out === "ref" ? p.name : `*${p.name}`, en);
      outs.set(p.index, [...(outs.get(p.index) ?? []), { ...st, viaPtr: p.out === "ptr" }]);
    }
  };
  const w: ReturnType<typeof createWalker> = createWalker(ctx, {
    quiet: true,
    onReturn: (e, en) => {
      collectOuts(en, w);
      const v = w.unwrapValue(e);
      if (!v || /^(?:NULL|nullptr|null|0)$/.test(v.text)) return;
      const slot = w.slotOf(v);
      if (slot) rets.push(w.readState(slot, en));
      else if (v.type === "new_expression" || v.type === "call_expression") { const k = w.kindOf(v); rets.push({ alloc: k, freed: 0, unchecked: 0 }); }
      else rets.push({ alloc: 0, freed: 0, unchecked: 0 });
    },
  });
  ctx.writeObs = new Map();
  const ended = w.walk(fn.body!, env);
  if (!ended) collectOuts(env, w);
  // bytes written into each buffer the function was handed: a parameter, what it points at, a member / element of it, a global
  const writes = new Map<string, number>();
  const pairs = bodyShape(fn.body!).pairs;
  const roots: Array<[string, string]> = [...fn.params.filter(p => p.name).map(p => [String(p.index), p.name] as [string, string]), ...mentionedGlobals(fn, ctx.globalNames).map(g => [`g:${g}`, g] as [string, string])];
  for (const [rootKey, root] of roots) {
    const alias = aliasPaths(pairs, root);
    for (const [n, bytes] of ctx.writeObs) {
      const path = observedPath(n, alias);
      if (path === null) continue;
      const key = `${rootKey}${path}`;
      if (bytes > (writes.get(key) ?? 0)) writes.set(key, bytes);
    }
  }
  ctx.writeObs = undefined;
  Object.assign(ctx, saved);
  const sum: MemSummary = { ret: agreeState(rets), outs: new Map(), writes };
  for (const [i, list] of outs) { const a = agreeState(list); if (a) sum.outs.set(i, a); }
  return sum;
}

/** How a buffer name seen in a function body is reached from one of its roots: an alias of it, `*pp`, `s.f`, `a[2]`. */
function observedPath(name: string, alias: ReadonlyMap<string, string>): string | null {
  const direct = alias.get(name);
  if (direct !== undefined) return direct;
  const deref = /^\*(\w+)$/.exec(name);
  if (deref) return alias.get(deref[1]) === "" ? "*" : null;
  const member = /^(\w+)(\.\w+|\[\d+\]|\[\*\])$/.exec(name);
  return member && alias.get(member[1]) === "" ? member[2] : null;
}

/** Can the function leave anything behind a summary records? It takes a parameter, returns a pointer or touches a file-scope variable. */
function mayHaveMemSummary(fn: LocalFn, ctx: EngineCtx): boolean {
  if (fn.params.some(p => p.name)) return true;
  const text = fn.decl.text;
  const header = text.slice(0, Math.max(text.indexOf("{"), 0));
  if (header.includes("*")) return true;
  for (const g of ctx.globalNames) if (text.includes(g)) return true;
  return false;
}

/** `exported`: also summarise functions nothing in this file calls -- their summaries are published for the other files of the batch. */
function buildMemSummaries(ctx: EngineCtx, exported: boolean) {
  const todo = new Map<string, LocalFn>();
  // used here: called by name, or referenced some other way (`void (*fp)(char *) = sink; fp(data);`) -- its name occurs again
  const usedHere = (name: string) => { const first = ctx.content.indexOf(name); return first >= 0 && ctx.content.indexOf(name, first + name.length) >= 0; };
  for (const [id, f] of ctx.fns) if (f.body && (exported || usedHere(f.name)) && mayHaveMemSummary(f, ctx)) todo.set(id, f);
  // who calls whom, so a later round re-summarises only the callers of a function whose summary changed
  const callees = new Map<string, Set<string>>();
  for (const [id, f] of todo) callees.set(id, new Set(bodyShape(f.body!).calls.map(c => callInfo(c).name)));
  let dirty: ReadonlySet<string> = new Set(todo.keys());
  for (let round = 0; round < 3 && dirty.size > 0; round++) {
    const changed = new Set<string>();
    for (const id of dirty) {
      const f = todo.get(id)!;
      const sum = summarizeMem(f, ctx);
      const key = (x: MemSummary | undefined) => x ? JSON.stringify([x.ret ?? null, [...x.outs], [...x.writes]]) : "";
      if (key(sum) !== key(ctx.memSum.get(id))) { ctx.memSum.set(id, sum); changed.add(f.name); }
    }
    dirty = new Set([...todo.keys()].filter(id => [...callees.get(id)!].some(n => changed.has(n))));
  }
  for (const [id, sum] of [...ctx.memSum]) if (!sum.ret && sum.outs.size === 0 && sum.writes.size === 0) ctx.memSum.delete(id);
}

function buildSummaries(ctx: EngineCtx) {
  const globalsSig = () => [...ctx.globalTaint].map(([k, v]) => `${k}=${v}`).join(",");
  for (let round = 0; round < FIXED_POINT_CAP; round++) {
    const before = globalsSig();
    let changed = false;
    for (const [name, f] of ctx.fns) {
      const ownOuts = new Map<number, number>();
      const intrinsic = returnMask(f, ctx, null, ownOuts);
      if ((intrinsic | (ctx.intrinsic.get(name) ?? 0)) !== (ctx.intrinsic.get(name) ?? 0)) { ctx.intrinsic.set(name, (ctx.intrinsic.get(name) ?? 0) | intrinsic); changed = true; }
      if (mergeFills(ctx, name, -1, ownOuts)) changed = true;
      const prop = new Map(ctx.propagating.get(name) ?? []);
      let grew = false;
      for (const p of f.params) {
        const outs = new Map<number, number>();
        const r = returnMask(f, ctx, p.index, outs) & ~intrinsic;
        const next = (prop.get(p.index) ?? 0) | r;
        if (r && next !== (prop.get(p.index) ?? 0)) { prop.set(p.index, next); grew = true; }
        // parameter p reaches another out-parameter: beyond what that one gets from the function itself
        for (const [i, v] of outs) if (mergeFills(ctx, name, p.index, new Map([[i, v & ~(ownOuts.get(i) ?? 0)]]))) changed = true;
      }
      if (grew) { ctx.propagating.set(name, prop); changed = true; }
    }
    if (!changed && globalsSig() === before) break;
  }
}

/** Functions registered as libcurl's write / header callback: their first parameter is the response bytes. */
let curlCallbackNames: ReadonlySet<string> = new Set();

function makeCtx(content: string, filePath: string, root: SyntaxNode, suppressed?: SuppressedSink[],
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>, exportSummaries = false): EngineCtx {
  MACROS = collectMacros(root);
  UNION_TYPES = collectUnionTypes(root);
  curlCallbackNames = new Set([...content.matchAll(/CURLOPT_(?:WRITE|HEADER|READ)FUNCTION\s*,\s*&?\s*([A-Za-z_]\w*)/g)].map(mm => mm[1]));
  // every function under its own identity (two classes' `process` are two summaries and two bodies)
  const fns = new Map<string, LocalFn>();
  const byName = new Map<string, LocalFn[]>();
  for (const f of collectFns(root)) {
    if (fns.has(f.id)) continue;
    fns.set(f.id, f);
    byName.set(f.name, [...(byName.get(f.name) ?? []), f]);
  }
  const ctx: EngineCtx = {
    filePath, content, lines: content.split("\n"), root, fns, byName, propagating: new Map(), intrinsic: new Map(), seeded: new Map(),
    suppressed, findings: [], seen: new Set(), crossFileFacts, aliases: new Map(), capacity: new Map(), strLen: new Map(), fnAlias: new Map(), freesParam: collectFreesParam(fns, collectGlobals(root), crossFileFacts), seededMem: new Map(),
    globalNames: collectGlobals(root), globalTaint: new Map(), speculative: false, current: null,
    refs: new Map(), slots: new Map(), memSum: new Map(), seededGlobals: new Map(), fills: new Map(), lambdas: new Map(), borrows: new Map(), views: new Map(), bases: collectBases(root),
  };
  // a file-scope variable another file taints (`extern char *badData;` read here)
  for (const name of ctx.globalNames) {
    let cls = 0;
    for (const f of crossFileFacts?.get(GLOBAL_PREFIX + name) ?? []) if (f.id === "taint-global") cls |= f.sinkClass;
    if (cls) ctx.globalTaint.set(name, cls);
  }
  buildSummaries(ctx);
  buildMemSummaries(ctx, exportSummaries);
  return ctx;
}

/** The last segment of a declared type, without qualifiers, pointers, references and template arguments: `const Poco::Net::HTTPServerRequest &` -> HTTPServerRequest. */
function classOfTypeText(typeText: string): string {
  return typeText.replace(/<[^<>]*(?:<[^<>]*>[^<>]*)*>/g, "").replace(/\b(?:const|struct|class|volatile|typename)\b|[&*\s]/g, "").split("::").pop() ?? "";
}
const STRINGISH_PARAM_RE = /(?:^|[\s:])(?:string|wstring|string_view|QString|QByteArray|QStringView)\b|\bchar\s*\*|\bchar\s*const\s*\*/;
const NUMERIC_PARAM_RE = /\b(?:int|long|short|unsigned|size_t|bool|double|float|u?int\d+_t|qint\d+|quint\d+)\b/;

/**
 * Which parameters of a function / lambda are request data, from their declared types: a request object, a socket, a form or a text widget; the
 * route arguments a framework hands after its request (Drogon: after the `HttpRequestPtr` and the callback); the `url` / `upload_data` of a
 * libmicrohttpd handler; the first parameter of a libcurl write callback; a Qt message slot's text; a route lambda's string parameters (Crow, QHttpServer).
 */
function inputParamNames(params: SyntaxNode[], fnName: string, lam: SyntaxNode | null): string[] {
  const info = params.map(p => ({ name: declaredName(field(p, "declarator")) ?? "", type: field(p, "type")?.text ?? "", full: p.text }));
  const out: string[] = [];
  const hasRequest = info.some(p => /HttpRequestPtr|HttpRequest\b/.test(p.type));
  let seenRequest = false;
  for (const [i, p] of info.entries()) {
    if (!p.name) continue;
    if (INPUT_CLASSES.has(classOfTypeText(p.type))) { out.push(p.name); seenRequest = seenRequest || /HttpRequestPtr|HttpRequest\b/.test(p.type); continue; }
    // Drogon: handler(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb, std::string name): the trailing parameters are path values
    if (hasRequest && seenRequest && STRINGISH_PARAM_RE.test(p.full) && !/function\s*</.test(p.full)) out.push(p.name);
    if (info.some(q => /MHD_Connection/.test(q.type)) && /^(?:url|upload_data|method|version)$/.test(p.name)) out.push(p.name);
    if (i === 0 && curlCallbackNames.has(fnName)) out.push(p.name);
    if (/(?:Text|Binary)?Message(?:Received)?$|^on(?:Text|Binary|Message)/.test(fnName) && /QString|QByteArray/.test(p.type)) out.push(p.name);
  }
  // CROW_ROUTE(app, "/f/<string>")([](const std::string &name) {...}) / server.route("/f/<arg>", [](const QString &name) {...})
  if (lam) {
    const call = lam.parent?.type === "argument_list" ? lam.parent.parent : null;
    const callee = call ? field(call, "function") : null;
    const routeName = callee?.type === "call_expression" ? field(callee, "function")?.text : callee?.text;
    if (routeName && /(?:^|[.:>-])(?:CROW_ROUTE|CROW_BP_ROUTE|route|registerHandler|addRoute)$/.test(routeName.replace(/\s+/g, ""))) {
      for (const p of info) if (p.name && STRINGISH_PARAM_RE.test(p.full) && !NUMERIC_PARAM_RE.test(p.type) && !INPUT_CLASSES.has(classOfTypeText(p.type))) out.push(p.name);
    }
  }
  return out;
}

/** Parameters that are input at a function's entry: main/wmain's argv, WinMain's command line. */
function entryEnv(fn: LocalFn, seedEntry: boolean): Env {
  const env: Env = new Map();
  for (const p of fn.params) env.set(p.name, 0);
  {
    let d = field(fn.decl, "declarator");
    while (d && d.type !== "function_declarator") d = field(d, "declarator");
    for (const nm of inputParamNames(named(field(d, "parameters")).filter(p => /parameter_declaration/.test(p.type)), fn.name, null)) env.set(nm, ALL);
  }
  if (/^(?:main|wmain|_tmain)$/.test(fn.name) && fn.params[1]) env.set(fn.params[1].name, ALL);
  if (/^(?:WinMain|wWinMain)$/.test(fn.name) && fn.params[2]) env.set(fn.params[2].name, ALL);
  if (seedEntry) for (const p of fn.params) if (p.name) env.set(p.name, ALL);
  return env;
}

/** Pointer/string parameters of exported functions nothing in the file calls: library API taking caller data. */
const STRINGY_PARAM_RE = /\bchar\s*\*|\bwchar_t\s*\*|std::(?:w?string|string_view)|\bLPC?[TW]?STR\b|\bconst\s+char\b/;

function runScan(ctx: EngineCtx, withEntryPoints: boolean): AstTaintCppFinding[] {
  const called = new Set(findAllNodes(ctx.root, "call_expression").map(c => callInfo(c).name));
  const globalsSig = () => [...ctx.globalTaint].map(([k, v]) => `${k}=${v}`).sort().join(",");
  // a global that only a seeded walk writes (`set(getenv("X"))` with `void set(std::string v) { g = v; }`) is read by
  // functions walked before it: walk them again once the globals stop growing
  for (let round = 0; round < 3; round++) {
    const before = globalsSig();
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
    if (globalsSig() === before) break;
  }
  ctx.current = null;
  return ctx.findings;
}

function drainSeeded(ctx: EngineCtx) {
  const walked = new Set<string>();
  for (let round = 0; round < FIXED_POINT_CAP; round++) {
    let changed = false;
    for (const name of new Set([...ctx.seeded.keys(), ...ctx.seededMem.keys(), ...ctx.seededGlobals.keys()])) {
      const f = ctx.fns.get(name);
      if (!f?.body) continue;
      const idx = ctx.seeded.get(name) ?? new Map<number, number>();
      const mem = ctx.seededMem.get(name) ?? new Map<number, Map<string, number>>();
      const globals = ctx.seededGlobals.get(name);
      const sig = `${name}:${[...idx].sort((a, b) => a[0] - b[0]).map(([i, v]) => `${i}=${v}`).join(",")}`
        + `|${[...(globals ?? [])].sort().map(([g, st]) => `${g}${st.alloc}${st.freed}${st.unchecked}`).join(",")}`
        + `|${[...mem].sort((a, b) => a[0] - b[0]).map(([i, ks]) => `${i}=${[...ks].map(([k, v]) => `${k}${v}`).join("+")}`).join(",")}`;
      if (walked.has(sig)) continue;
      walked.add(sig);
      changed = true;
      const env: Env = new Map();
      for (const p of f.params) {
        env.set(p.name, idx.get(p.index) ?? 0);
        for (const [k, v] of mem.get(p.index) ?? []) env.set(KIND_KEY(k, p.name), v);
      }
      for (const [g, st] of globals ?? []) for (const k of MEM_KINDS) if (st[k]) env.set(KIND_KEY(k, g), st[k]);
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
    recordEngineFailure(filePath, "analysis-failed");
    lastCppEngineError = `analysis_failed: ${filePath}: ${String((err as Error)?.message ?? err)}`;   // visible via getCppEngineStatus()
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
    const ctx = makeCtx(content, filePath, root, undefined, incoming, true);
    ctx.speculative = true;
    const all = [...ctx.fns.values()];
    for (const [name, cls] of ctx.globalTaint) {
      if (!(cls & ALL)) continue;
      if (cls & CROSS_FILE_TAINT) out.set(GLOBAL_PREFIX + name, [{ index: -2, isRest: false, id: "taint-global", sinkClass: cls & CROSS_FILE_TAINT, sinkExpr: `${name}|${cls & CROSS_FILE_TAINT}`, file: filePath, line: 1, via: [name] }]);
    }
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
      if (!f.body || f.isStatic || /^(?:main|wmain)$/.test(f.name)) continue;
      // what the function does to a pointer (returns an allocation, frees a parameter, dereferences it unchecked)
      const mem: ParamSinkFact[] = [];
      const memFact = (index: number, id: string, sinkExpr: string, sinkClass = 0): ParamSinkFact => ({ index, isRest: false, id, sinkClass, sinkExpr, file: filePath, line: f.decl.startPosition.row + 1, via: [f.name] });
      const sum = ctx.memSum.get(f.id);
      if (sum?.ret) mem.push(memFact(-1, "mem-state", `${sum.ret.alloc},${sum.ret.freed},${sum.ret.unchecked},r,${sum.ret.cap ?? ""},${sum.ret.len ?? ""}`));
      for (const [key, bytes] of sum?.writes ?? []) mem.push(memFact(Number(/^\d+/.exec(key)?.[0] ?? -2), "mem-writes", `${bytes}|${key}`));
      for (const [i, st] of sum?.outs ?? []) mem.push(memFact(i, "mem-state", `${st.alloc},${st.freed},${st.unchecked},${st.viaPtr ? "p" : "r"},${st.cap ?? ""},${st.len ?? ""}`));
      for (const [key, how] of ctx.freesParam.get(f.id) ?? []) mem.push(memFact(Number(/^\d+/.exec(key)?.[0] ?? -2), "mem-releases", `${how}|${key}`));
      const zero = () => { const e: Env = new Map(); for (const p of f.params) e.set(p.name, 0); return e; };
      const baseline = f.params.length > 0 ? new Set(run(f, zero()).map(x => `${x.id}:${x.line}`)) : new Set<string>();
      if (f.params.length > 0) {
        // the parameter itself and everything the body reads out of it (`*p`, `p.f`, `p[2]`), each seeded in the state to
        // test; every name the body holds it under is recorded, so a finding on an alias is attributed to its parameter
        const pairs = bodyShape(f.body).pairs;
        const cands: Array<{ idx: number; path: string; slot: string; names: ReadonlyMap<string, string> }> = [];
        for (const p of f.params) {
          if (!p.name) continue;
          const names = aliasPaths(pairs, p.name);
          for (const path of new Set(names.values())) {
            const slot = path === "" ? p.name : path === "*" ? `*${p.name}` : path === "[*]" ? "" : `${p.name}${path}`;
            if (slot) cands.push({ idx: p.index, path, slot, names });
          }
        }
        // One walk with every candidate seeded: unchecked (a dereference there is a NULL dereference) and, for what a
        // parameter reaches, freed (any touch is a use-after-free) -- the two findings do not depend on each other. A
        // parameter used while freed is already caught at the call (any use of a freed argument), so only what it reaches
        // needs a fact.
        if (cands.length > 0) {
          const env = zero();
          for (const c of cands) {
            env.set(KIND_KEY("unchecked", c.slot), 1);
            if (c.path !== "") env.set(KIND_KEY("freed", c.slot), 1);
          }
          const done = new Set<string>();
          for (const x of run(f, env)) {
            const state = x.id === "null-dereference" ? "unchecked" : x.id === "use-after-free" ? "freed" : null;
            if (!state || baseline.has(`${x.id}:${x.line}`)) continue;
            for (const c of cands) {
              if (state === "freed" && c.path === "") continue;
              if (c.names.get(x.sourceExpr) !== c.path && x.sourceExpr !== c.slot) continue;
              const key = `${state}|${c.idx}${c.path}`;
              if (done.has(key)) continue;
              done.add(key);
              mem.push(memFact(c.idx, "mem-uses", key));
            }
          }
        }
      }
      // what it does to its arguments' taint: the classes its return carries (from input it reads itself, or from a parameter)
      // and what it stores in out-parameters; kept beside the memory facts, under their own key
      const intrinsic = (ctx.intrinsic.get(f.id) ?? 0) & CROSS_FILE_TAINT;
      if (intrinsic) mem.push(memFact(-1, "taint-ret", String(intrinsic), intrinsic));
      for (const [i, cls] of ctx.propagating.get(f.id) ?? []) if (cls & CROSS_FILE_TAINT && f.params[i]?.bufLike) mem.push(memFact(i, "taint-prop", String(cls & CROSS_FILE_TAINT), cls & CROSS_FILE_TAINT));
      for (const [i, bySource] of ctx.fills.get(f.id) ?? []) for (const [j, cls] of bySource) if (cls & CROSS_FILE_TAINT && f.params[i]?.bufLike && (j < 0 || f.params[j]?.bufLike)) mem.push(memFact(i, "taint-fill", `${j}|${cls & CROSS_FILE_TAINT}`, cls & CROSS_FILE_TAINT));
      if (mem.length > 0) { const list = out.get(AUX_PREFIX + f.name) ?? []; mergeSinkFacts(list, mem); out.set(AUX_PREFIX + f.name, list); }
      if (f.params.length === 0) continue;
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
    recordEngineFailure(filePath, "analysis-failed");
  }
  return out;
}
