// ── Incremental scan result reuse ────────────────────────────────────────────
//
// runScan() used to accept `prev_hashes` (path -> previous content hash) and simply DROP any file whose
// hash matched. Two problems with that, both fixed by this module + runScan's use of it:
//
//  1. Dropped, not reused: an unchanged file vanished from ScanOutput.files, so every aggregate computed
//     over `files` (overall risk, AI %, distribution, compliance, trust chain) silently covered only the
//     changed subset. It also vanished from the cross-file import graph, so a changed file importing an
//     unchanged one could no longer resolve the import.
//  2. Hash-equality is not sufficient for reuse: a file's findings are a function of MORE than its own
//     bytes. analyzeFile() also consumes (a) the incoming cross-file taint summaries of files it imports,
//     (b) the cross-file reachable-name set, (c) the callee file's own content (a source->sink trace
//     continues one real hop into it), and (d) the PR-level AI prior bias. An unchanged caller whose
//     CALLEE changed must be re-analyzed even though its own hash is identical -- a hash-only skip would
//     keep reporting (or keep suppressing) a cross-file flow that no longer exists.
//
// So a cached result is keyed by a digest of every input analyzeFile() reads, not just the content hash.
// The caller persists ScanOutput.file_cache and hands it back as ScanInput.prev_results next time.

import crypto from "crypto";
import type { FileAnalysis } from "./scanner";
import type { ParamSinkFact } from "./taint/taintCore";

/**
 * Bump when analyzeFile()'s output semantics change (a detector added/removed/retuned). A stale cache
 * from before that change would otherwise keep serving old findings for unchanged files forever.
 * A deploy can also namespace its own cache via ScanInput.cache_namespace (e.g. the commit SHA) so a
 * forgotten bump here can never silently serve stale results across releases.
 */
// 7: Kotlin taint pass (kotlinTaint.ts), Ruby taint pass + Ruby AST engine (astTaintRuby.ts).
// 8: Kotlin AST engine (astTaintKotlin.ts), Java facts shared with Kotlin.
// 9: Rust AST engine (astTaintRust.ts).
// 10: hostile-input limits (long runs cut, too-deep trees skip the AST engines), LDAP template rule narrowed.
// 11: Python precision/recall from BenchmarkPython (constant folding, keyed dict/ConfigParser slots, substring and
//     URL-allowlist guards, new sinks, trust-boundary, weak hash/random/cookie rules, request-source helpers).
// 12: Go/Rust/PHP/Ruby/C#/Kotlin precision/recall from the 0llino sast-benchmark and vulnerable-app corpora (request
//     wrappers and Android sources, constant folding, literal-key maps, substring/alphabet/prefix/host/HMAC guards,
//     proven-constant vetoes, argument injection that respects validation, new sinks, PHP/Ruby weak-crypto rules).
// 13: NodeGoat / DVC / DVPWA / Juliet: JS log injection, constant-regex ReDoS, HTTP client packages and require()
//     bindings, block comments and HTML samples skipped by the line rules, C# conventional actions, Sinatra route
//     bodies, aiohttp sources, literal DB credentials, Java methods called from another file not seeded as entries.
// 14: constant folding in C#/PHP/Ruby/Kotlin, log injection in every engine (with CR/LF sanitizers), C# System.Web
//     response / cookie / CodeDom / reflection sinks, Java socket and URLConnection input, Rust request helpers and
//     store query helpers, secrets formatted into multi-line log calls.
// 15: C/C++ data-flow and memory-safety engine (astTaintCpp.ts); .cc/.cxx/.hpp/.hh/.h are C/C++ sources.
// 16: Java proof pass (sinks proven independent of every input veto the regex duplicate), Rust log injection and
//     SQL / LDAP / Location built with format!, relative-URL guards (Go / Ruby / Rust), TLS-off switches by name.
// 17: C# proof pass (incl. private helpers) and network sources, int.Parse as validation; PHP relative-URL / resolved
//     IP guards and libxml-accurate XXE; Android content providers, SQLite by position, Log.*; JS DOM sources and
//     sinks; directory listing, substring URL allowlists, WebView file access, credentials compared to literals.
// 18: Go trust boundary / upload names / unchecked index / goroutine races / CSRF / make() sizes and verbose errors;
//     PHP extract / $$ / loose comparisons / upload names; Ruby reflection and file inclusion with allow-list guards;
//     Rust integer overflow, unsafe memory access and allocation sizes; Java ProcessBuilder.command and array inits;
//     C# proof pass seeded from the batch's own call sites (and named arguments read by value); Express rate-limit
//     keys / diagnostics routes / session fixation / shadowed role guards; C/C++ new T[n] sizes and constant-bound
//     loops; Go math/rand token flows and session-cookie lookups; PHP template-engine render; Java DES key generators;
//     Java request wrappers in other files as sources; Android cleartext storage / clipboard; JS recursive merges;
//     PHP session-authenticated CSRF; Kotlin argument + trailing-lambda calls and coroutine values; WebView bridges.
// 19: Java Runtime.exec environment entries that choose what runs; Commons Codec Base64 carries taint; calls through
//     a batch class or interface whose implementations return their argument carry it (cross-file pass-throughs).
// 20: Ruby whole-hash mass assignment, host-connection SSRF sinks, resolved-address guards, log streams and files; Go
//     cipher use (64-bit ciphers, ECB, fixed IVs, unauthenticated modes, XOR), host-gate / suffix / resolved-address
//     guards, numeric argv proofs; Rust uploads, LDAP escapers, extracted-host guards; PHP cipher use and
//     unserialize allowed_classes / HMAC; raw Set-Cookie built on an earlier line; alphabets no longer clear EVAL.
// 21: Go entry points (string parameters of functions nothing in the file calls) and intrinsic return summaries (a
//     helper that reads the request), slog / log-file / stderr log sinks, %q and escaped-newline proofs; Ruby and PHP
//     weak randomness and Ruby cipher use, constructor taint, javascript_tag; Rust key-XOR / RC4 ciphers; secrets in
//     typed constants, `:=` / struct fields, URL userinfo, SMTP / JWT literals and hex keys.
// 22: interprocedural taint and traces: helpers that read the request are sources in every engine (Python, Java, PHP,
//     C#, Go), Go request fields in structs; traces cross function boundaries (callers' arguments, callees' returns)
//     in Go / Python / Java / PHP / C# / Ruby / Kotlin / Rust / C/C++; a builder in another function is no longer merged
//     into a shared sink; method calls on objects use the method's summary (JS `this.req`, PHP, Kotlin, C++ members, Ruby
//     nested classes); Kotlin package-qualified constructors and constant-helper SQL proof; field writes in traces;
//     exploitability from each finding's own trace (reachability "unknown", local attack vector, auth from code as
//     Privileges Required, a reason per score) and entry points for HandleFunc / Kotlin / Rust / Rails / C main.
// 23: AI attribution: backdoor / hallucinated-API / style-drift findings no longer feed the AI score, the explanation
//     credits only signals that fed it, and files under 50 characters are scanned for security problems (AI signals
//     skipped) instead of returning empty. Cached files from 22 carry the old scores and would hide those findings.
// 24: AST taint engine accuracy: namespace imports / `export * as ns` resolve by qualified key (`ns.fn`) instead of a
//     bare name, a same-named local function is no longer replaced by an imported one, tsconfig `paths` aliases
//     resolve, `path.join/resolve` are transformations (the filesystem call is the sink), a prefix test on a normalised
//     path proves containment, nested request destructuring is tainted, and a literal member of an object literal is
//     no longer tainted by its siblings. Python: functions are keyed by symbol (module function / `Class.method`), call
//     arguments bind by Python's rules (keywords, keyword-only, *args/**kwargs), os.path.join / Path() are
//     transformations and the filesystem call is the sink (os.scandir, archive extraction added), a missing `..` /
//     quote / `<` no longer clears a class, canonical containment does, FastAPI Depends / validated scalars are not
//     request input, an ambiguous absolute import stays unresolved, `abort()`/`sys.exit()` end a validation branch.
//     Java: methods are keyed by package.Class.method(ParamTypes) (overloads and same-named methods of different
//     classes are separate, a call is resolved by arity / receiver class / argument types), each method has its own type
//     environment, Path.of / Paths.get / new File are transformations and the filesystem operation is the sink,
//     XXE hardening is judged per factory / parser instance and in order, Class.forName / getMethod / getField /
//     parseExpression alone are not findings (invoke / newInstance / getValue / Field.set are), lambdas and method
//     references see the receiver's taint, cross-file facts are package-qualified and resolved by import.
//     Go: filepath.Join / Clean / Abs / Rel are transformations (the file operation is the sink; os.OpenRoot added), a
//     `..` check no longer clears path traversal while filepath.IsLocal and a checked filepath.Rel do, response
//     writers and framework contexts are recognised by declared type per function (not by the name `w`),
//     MethodByName / FieldByName alone are not findings (Call / Set* are), a call whose receiver is unresolved is
//     reported at lower confidence with the reason, JWT / CSRF evidence is scoped to the function / router that
//     holds it, and cross-package facts are keyed by directory so two packages named alike stay apart.
//     C#: methods are keyed by namespace.Class.Method<arity>(ParamTypes) and a call is resolved by receiver class, arity /
//     named / optional / params binding and argument types; each method has its own type environment; Type.GetType /
//     GetMethod / GetProperty alone are not findings (Invoke / SetValue / CreateInstance are, through a variable too);
//     a StartsWith containment check needs a directory boundary; JWT evidence is the reading method's own; an owner
//     check on the looked-up record counts as BOLA evidence; [Authorize(Roles)] no longer suppresses mass assignment;
//     a virtual / override method is not proven by its own body; local functions and tuples carry taint; cross-file
//     facts are namespace-qualified and resolved by using; one finding per flow (same-line flows named in the detail).
//     PHP: functions / methods are keyed by namespace (a call resolves against its own namespace, then the global one;
//     \system() names the built-in, a namespaced user function of the same name is the user's), named / optional /
//     variadic / unpacked arguments bind by PHP's rules, a '..' check clears a path only under a fixed directory prefix,
//     JWT verification must mention the same token, a record-level abort_unless / Gate::authorize after a lookup counts as
//     BOLA evidence, SplFileObject / DirectoryIterator open their path, proc_open with an argv array runs no shell, files
//     are linked by use / namespace (Composer-style) as well as by include, one finding per sink call.
//     Ruby: a lambda / proc is walked where it is called (.call / .() / [] / yield), never at its definition, a class
//     constant resolves lexically (innermost namespace outward, no suffix match) in calls and cross-file keys, an owner
//     check only counts between the lookup and the first write, one finding per sink call, and a failed parser init is retried.
//     Rust: a closure runs where it is called or consumed, never where it is written; an owner check only counts before the
//     write; one finding per sink node. C/C++: a null check must test the pointer against null (p == other proves nothing),
//     #if / #ifdef / #else arms are joined as alternatives, one finding per sink call; both retry a failed parser init.
//     Kotlin: a stored lambda runs where it is invoked, same-file functions are keyed by class (same-named methods of two
//     classes stay apart), an authorize()/assertOwner() helper counts only when given the record or id and run before the write,
//     one finding per sink node, a failed parser init is retried.
//     Cached results from 23 would keep the old findings.
export const SCAN_CACHE_VERSION = 24;

/** One file's reusable result. `analysis` is the post-analyzeFile, PRE-PR-level-post-pass snapshot. */
export interface CachedFileResult {
  cache_key: string;
  analysis: FileAnalysis;
}

export function sha256Hex(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

/** Structural subset of an engine's ParamShape (JS/TS `ParamShape`, Python `PyParamShape`). */
interface ShapeLike { index: number; isRest?: boolean; mask?: number; name?: string }

export interface CacheKeyInputs {
  namespace: string;
  path: string;
  contentHash: string;
  prPriorBias: number;
  /** JS/TS incoming cross-file entries: local name -> propagating shapes + sink facts + where they came from. */
  jsCrossFile?: Map<string, { shapes: ShapeLike[]; sinks?: readonly ParamSinkFact[]; fromModule: string; resolvedPath?: string }>;
  /** Content hash of a resolved callee path (a trace hops into the callee's body, so its bytes matter). */
  contentHashOf: (path: string) => string | undefined;
  /** JS/TS cross-file reachable names in this file. */
  crossFileReachable?: Set<string>;
  /** Python incoming cross-file shapes: local name -> shapes. */
  pyCrossFile?: Map<string, ShapeLike[]>;
  /** Python incoming parameter -> sink facts: local name -> facts (their location/expression reach the emitted finding). */
  pySinks?: Map<string, { sinks: readonly ParamSinkFact[] }>;
  /** Stored/second-order provenance (see taintCore.ts's StoredProvenanceIO): THIS file's own model keys
   * (from its modelReceivers) paired with their batch-converged mask -- not the whole batch-wide map, so
   * a write to a model this file never touches can't cause a spurious cache miss. */
  storedProvenanceIncoming?: Array<[string, number]>;
  /** Digest of the batch's cross-file service-layer facts for this file's language (Java/C#): any change to
   * a service's summary may change a controller's findings, so it invalidates this file's cached result. */
  serviceFactsDigest?: string;
}

/** Every field of a sink fact that reaches the emitted finding (its location, expression and via-path all
 * appear in the detail/trace), so a callee whose sink MOVED, changed or vanished invalidates the caller even
 * when the callee's own return shapes are identical. */
function canonSinks(sinks: readonly ParamSinkFact[]): unknown[] {
  return sinks
    .map(f => [f.index, f.isRest ? 1 : 0, f.id, f.sinkClass, f.sinkExpr, f.file, f.line, f.via.join(">"),
      (f.steps ?? []).map(s => `${s.file}:${s.line}:${s.kind}:${s.label}`).join(">")])
    .sort((a, b) => { const x = JSON.stringify(a), y = JSON.stringify(b); return x < y ? -1 : x > y ? 1 : 0; });
}

function canonShapes(shapes: ShapeLike[]): unknown[] {
  return [...shapes]
    .sort((a, b) => a.index - b.index)
    .map(s => [s.index, s.isRest ? 1 : 0, s.mask ?? -1, s.name ?? ""]);
}

/**
 * Digest of everything analyzeFile() reads for one file. Deterministic: every collection is sorted, so
 * Map/Set insertion order (which follows filesystem/API ordering) can never cause a spurious miss.
 */
export function computeFileCacheKey(inp: CacheKeyInputs): string {
  const js = inp.jsCrossFile
    ? [...inp.jsCrossFile.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([name, e]) => [
          name, e.fromModule, e.resolvedPath ?? "",
          e.resolvedPath ? (inp.contentHashOf(e.resolvedPath) ?? "") : "",
          canonShapes(e.shapes), canonSinks(e.sinks ?? []),
        ])
    : [];
  const py = inp.pyCrossFile
    ? [...inp.pyCrossFile.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([name, shapes]) => [name, canonShapes(shapes)])
    : [];
  const pySinks = inp.pySinks
    ? [...inp.pySinks.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([name, e]) => [name, canonSinks(e.sinks)])
    : [];
  const reachable = inp.crossFileReachable ? [...inp.crossFileReachable].sort() : [];
  const storedProvenance = inp.storedProvenanceIncoming
    ? [...inp.storedProvenanceIncoming].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    : [];
  return sha256Hex(JSON.stringify([
    SCAN_CACHE_VERSION, inp.namespace, inp.path, inp.contentHash,
    // toFixed: prPriorBias is a float derived from PR metadata; 6 places is far below any effect on a
    // file's AI% but keeps 0.08 vs 0.0800000000001 (float noise) from causing a spurious miss.
    inp.prPriorBias.toFixed(6),
    js, reachable, py, pySinks, storedProvenance, inp.serviceFactsDigest ?? "",
  ]));
}

/**
 * Deep-copies through JSON. FileAnalysis is plain data (no Map/Set/Date -- verified), and going through
 * JSON on BOTH the store and reuse side means an in-memory cache behaves identically to one that was
 * round-tripped through a database, so a test against this can't pass on object identity alone.
 * (Not structuredClone: jest's jsdom environment doesn't provide it.)
 */
export function cloneAnalysis(a: FileAnalysis): FileAnalysis {
  return JSON.parse(JSON.stringify(a)) as FileAnalysis;
}
