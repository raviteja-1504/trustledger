# Universal Taint Model — engine audit and gap report

Phase 1 deliverable of the Universal Taint Model (UTM) work: what the analysis engines do today, what of the UTM
already exists, what is missing, and the migration plan. Written before any architectural change, as the UTM
specification requires. Every claim below points at code or a measured result; where something has not been
measured it says so.

Audited at commit `1b0d415` plus the uncommitted interprocedural work (November 2026).

---

## 1. Architecture today

```
 file ──► parser ──► language engine (astTaint*.ts) ──► data-flow findings ──┐
                       │  sources, sinks, propagation,                      ├─► scanner.ts merge ──► finding
                       │  summaries: code inside each engine                │   (dedupe, veto, CWE,
                       └─► shared core (src/lib/taint/*)                     │    evidence, reachability)
 file ──► line-pattern layer (scanner.ts, 134 detectors) ───────────────────┘
```

| Layer | Where | What it is |
|---|---|---|
| Parsers | `typescript` (JS/TS), `web-tree-sitter` WASM grammars (Python, Go, C#, PHP, Ruby, Kotlin, Rust, C/C++), `java-parser` (Java) | One parser per language |
| Language engines | `astTaint.ts`, `astTaintPython.ts`, `astTaintJava.ts`, `astTaintKotlin.ts`, `astTaintGo.ts`, `astTaintCSharp.ts`, `astTaintPHP.ts`, `astTaintRuby.ts`, `astTaintRust.ts`, `astTaintCpp.ts` — ~26,800 lines | Each engine defines its own sources, sinks, propagation rules and summaries, in code |
| Shared core | `taint/taintCore.ts` (998), `taint/sanitizers.ts` (244), `taint/sinkShape.ts`, `taint/charClass.ts`, `taint/constEval.ts`, `taint/crossFile.ts`, `taint/principal.ts` | The taint lattice, the sanitizer table, sink-shape judgements, the cross-file bridge, the shared trace builder |
| Line-pattern layer | `scanner.ts` (9,104 lines): 41 regex rule arrays, 142 single regexes, 134 `find*` detectors (59 language-specific) | Regex detection for every language, including those with an engine; an engine's proof that a sink is safe vetoes the regex duplicate (`suppressedSinks`) |
| Evidence | `dataFlowEvidence.ts`, `TraceStep` | Canonical source/sink/hops/sanitizers record for every data-flow finding |
| Catalogs | `findingCatalog.ts`, `cweMap.ts` (87 ids), `ruleLanguages.ts` | Rule titles, CWE per rule, which engines can report each rule (compile-time checked) |

## 2. What of the UTM already exists

These are real, shared, and should be the foundation, not replaced:

| UTM concept (spec §) | Exists as | Assessment |
|---|---|---|
| Context-specific sanitisation (§6) | The taint value is a bitmask of **sink classes** (`SinkClass`: SQL, CMD, XSS, SSRF, PATH, REDIRECT, DESERIAL, INCLUDE, LDAP, XPATH, NOSQL, HEADER, EVAL, SSTI, CONTROL) plus **shadow bits** recording what a sanitizer *cleared* (`taintCore.ts`) | Already the right model: HTML escaping clears only XSS, and "never tainted" is distinguishable from "tainted then sanitised". This is the spec's §6 requirement, done. |
| Sanitizer registry (§6, §7 L2) | `taint/sanitizers.ts`: one table per language (9 languages), each entry = the classes it clears, with argument-aware entries (`filter_var` by its filter constant, `strings.ReplaceAll` by what it replaces) | Data-driven already. Missing: C/C++ table, framework-level entries (Django autoescape, React JSX), and validator/allowlist barriers. |
| Rule → class map | `ID_TO_CLASS` / `classOf()` in `taintCore.ts` | Shared by all engines |
| Rule → CWE (§7 L1) | `cweMap.ts` | Shared, 87 rule ids |
| Function summaries (§9) | `ParamSinkFact` (parameter → sink, with the callee's own steps), computed bottom-up by every engine; return propagation (parameter → return) in six engines | The format is shared and composes across files. Summary *kinds* are incomplete (see §4.5). |
| Evidence and traces (§11, §14.11–12) | `TraceStep`, `DataFlowEvidence` (source, sink role, CWE, files crossed, hops, sanitizers on the path); `buildBackwardTraceGeneric` shared by nine engines | Shared; JS/TS has its own trace builder |
| Rule ↔ engine consistency | `ruleLanguages.ts`: the compiler checks each engine's rule list in both directions | A real, enforced model-coverage table |

## 3. Per-engine audit

| Engine | Parser | Sources defined as | Sinks defined as | Sanitizer table | Param→return summaries | Param→sink summaries | Field / global ("sticky") taint | Trace builder | Unit tests |
|---|---|---|---|---|---|---|---|---|---|
| JS/TS | TypeScript compiler | `SOURCE_ROOTS`/`SOURCE_PROPS` + `isTaintSourceExpr` | `matchSink` + name sets (`CMD_SINK_NAMES`, `FS_SINK_NAMES`, `HTTP_SINK_NAMES`, `DB_SINK_METHODS`) | js | yes | yes | yes | **bespoke** | 26 |
| Python | tree-sitter | `FLASK_*`, `DJANGO_*` constants + `isTaintSourceExprPy` | `matchSinkPy` | py | yes | yes | yes | shared | 24 |
| Java | java-parser | `SERVLET_SOURCE_CALLS`, `SPRING_SOURCE_ANNOTATIONS` | `checkCallSink`, `checkNewExpressionSink` (if-chains) | java | yes | yes | yes | shared | 65 |
| Kotlin | tree-sitter | **own copies** of `SERVLET_SOURCE_CALLS`, `SPRING_SOURCE_ANNOTATIONS` | `checkCallSink` | kt | **no** | yes | yes | shared | 31 |
| Go | tree-sitter | `GIN_ECHO_FIBER_SOURCE_METHODS` + `isTaintSourceExprGo` | `matchSinkGo` (if-chain) + `FS_SINKS_GO` | go | yes | yes | yes | shared | 41 |
| C# | tree-sitter | `ASP_SOURCE_ATTRIBUTES`, `RAW_SOURCE_MEMBER_TAILS` | `checkCallSink`, `checkNewExpressionSink` | cs | yes | yes | yes | shared | 59 |
| PHP | tree-sitter | `isTaintSourceExprPHP` | `checkFunctionCallSink`, `checkMemberCallSink`, `checkIncludeExpressionSink`, … | php | yes | yes | yes | shared | 52 |
| Ruby | tree-sitter | `PARAMS_SOURCE`, `COOKIES_SOURCE` (+ `rubyTaint.ts` regex) | `checkCallSink` | rb | **no** | yes | yes | shared | 30 |
| Rust | tree-sitter | inside the walker | `checkCallSink`, `checkMacroSink` | rs | **no** | yes | **no** | shared | 39 |
| C/C++ | tree-sitter | `OUT_PARAM_SOURCES`, `RETURN_SOURCES` | inside the walker | **none** | **no** | yes | **no** | shared | 43 |

Columns from inspection of each engine (imports of the shared modules, declared tables and matcher functions);
unit-test counts are `it(`/`test(` occurrences in each engine's test file.

### Measured interprocedural capability

The only cross-language interprocedural measurement is the advanced suite
(`src/__tests__/benchmarks/interprocedural`, 22 single-file programs, scored on source + every step + sink at the
right lines, each with a safe twin). Current result, from the committed baseline:

| Language | Pass | Partial | Miss | Safe twins clean |
|---|---|---|---|---|
| Go | 5 / 5 | 0 | 0 | 5 / 5 |
| Java | 5 / 5 | 0 | 0 | 5 / 5 |
| JavaScript | 0 / 6 | 2 | 4 | 6 / 6 |
| Python | 0 / 6 | 2 | 4 | 6 / 6 |
| Kotlin, C#, PHP, Ruby, Rust, C/C++ | **not measured** — the suite has no fixtures for them yet | | | |

The other public corpora (OWASP Benchmark Java/Python, sast-benchmark Go/PHP/Ruby/Rust, Juliet C#/C/C++, the
internal cross-file suite, Juice Shop) measure detection per category, not interprocedural trace accuracy.

## 4. Gaps against the specification

Status: **present** (shared and working), **partial** (exists in some engines or in part), **missing**.

### 4.1 Sources (spec §3)

| Item | Status | Evidence / note |
|---|---|---|
| HTTP query/path/body/headers/cookies | present | Every engine, per framework |
| Multipart / file uploads | partial | Go (`header.Filename`), PHP (`$_FILES`), Rails; not uniform |
| WebSocket, GraphQL args, gRPC fields | missing | No engine models them as sources |
| CLI args, stdin, environment | partial | C/C++ (`argv`, `fgets`, `getenv` in `RETURN_SOURCES`), Rust `std::env`; others treat env as trusted |
| Message queues (Kafka/RabbitMQ/PubSub), webhooks | missing | |
| Database / cache results as sources | missing | Deliberately not tainted today; no "stored input" (second-order) model |
| Deserialization outputs | partial | JSON body parsing is a source in web engines; YAML/XML/protobuf outputs are not |
| Browser sources (location, postMessage, storage, DOM) | partial | JS engine: some DOM sources; no postMessage/storage |
| Identity / claims (JWT, session, tenant) | partial | Session attributes carry taint in Java (added with the interprocedural work); JWT claims only in authz checks (`principal.ts`) |
| **Provenance and trust metadata on sources** | **partial** (was: partial) | Step 6: `DataFlowEvidence.source` carries `kind` (the source-model vocabulary), `trust` (`untrusted` / `semi-trusted` / `assumed`) and the matching `model`, also in SARIF (`trustledger/sourceKind`, `trustledger/sourceTrust`). Declared by models for the JVM (including an annotation-bound parameter, found from its declaration); inferred from the input's shape elsewhere. Sources outside the JVM have no declared models yet, so e.g. a DB value still has no trust level of its own |

### 4.2 Sinks (spec §4)

| Item | Status | Note |
|---|---|---|
| SQL, NoSQL, LDAP, XPath, command, eval, SSTI, path, SSRF, redirect, header, log, XSS, deserialization | present | All in `SinkClass`; coverage per language uneven (see `ruleLanguages.ts`) |
| XXE as a data-flow sink | partial | Python, and Java as of this work; JS/C#/PHP rely on the pattern layer |
| Regex construction (ReDoS) | partial | JS, Python, Java, Go, C#, PHP, Ruby, Rust |
| CSS / JS-context output, DOM HTML assignment | partial | JS only |
| Archive extraction (zip-slip), temp files, permission changes | partial | C/C++ temp files, some zip-slip in the pattern layer |
| DNS lookup, proxy config, cloud metadata | missing | |
| Security-sensitive sinks (crypto, token verification, authz, TLS) | partial, **separate analyses** | Weak crypto, JWT none-alg, TLS-off, BOLA/IDOR exist as specialised checks — correctly separate from taint, as the spec requires |

### 4.3 Propagation (spec §5)

| Item | Status | Evidence |
|---|---|---|
| Assignment, concatenation, interpolation, formatting, casts, ternaries | present | All engines |
| Containers (list/map add, index read) | partial | Detection in most engines; **traces** now in Java and Go; JS Map storage misses (JS-05) |
| Object properties / nested fields | partial | Field-sensitive in JS, Python, Java; JS `res.locals` and receiver fields across methods miss (JS-01, JS-06) |
| Constructor-assigned fields | partial | Java yes; JS `this.x = param` lost (JS-02 isolation run) |
| Function args / returns | present | All engines, same-file; cross-file via summaries |
| Global / static state | partial | "Sticky" fields in 8 engines (not Rust, C/C++); module dicts in Python miss (PY-01) |
| Closures / lambdas | partial | Go and Java traces now follow captures; JS deferred callbacks miss (JS-04) |
| Higher-order functions / callbacks / function values | partial | Go function values now followed; Python callback body step missing (PY-06) |
| Virtual dispatch / interfaces | partial | Go interfaces pass (GO-02); Java abstract dispatch passes (JAVA-03); JS `super` misses (JS-06) |
| Async: promises, await, coroutines, tasks | partial | JS await partial (JS-03), Python coroutines/`create_task` miss (PY-05) |
| Event dispatch (emitters, channels) | partial | Go channels pass (GO-01); JS EventEmitter misses (JS-02) |
| Generators / yield | missing | PY-03 |
| Decorators | missing | PY-02 (eval found only by the pattern layer) |
| Cross-boundary (DB write→read, queue, cache, file) | missing | Session store is the first instance (Java) |
| Reflection, dynamic property access, exceptions, implicit flows | missing / out of scope | No engine models these; implicit flows deliberately excluded |

### 4.4 Sanitizers and barriers (spec §6)

| Item | Status | Note |
|---|---|---|
| Context-specific clearing, tracked per value and class | present | The SinkClass + shadow-bit lattice |
| HTML ≠ SQL, URL encoding ≠ SSRF protection | present | `sanitizers.ts`: `encodeURIComponent` clears `URL_SAFE` only, not SSRF |
| Parameterised SQL, argument separation, path canonicalisation, SSRF host vetting, XML hardening | partial | Implemented per engine as sink-shape judgements (`sinkShape.ts`, `resolvedAddressesVettedGo`, `XML_PARSER_HARDENED_RE`), not as declared barriers |
| Allowlist validators / guards | partial | `applyGuards` in the core; per-engine guard recognition |
| C/C++ sanitizer table | present (step 2) | `astTaintCpp.ts` reads the `cpp` table in `sanitizers.ts` |
| **Unknown calls** | **decided (step 7)** | Detection keeps "an opaque call's result is untainted" -- measured: carrying arguments through unknown calls costs far more than it finds (§6, step 7). §14.9's "never assume safe" is what matters where safety is *claimed* -- a suppression, which vetoes the regex layer's finding. An unknown call's result is mask 0, with no shadow bits, so it can never satisfy `wasCleared` (the sanitizer-based suppression); the constant proofs (`provenConstant*` in Java, C#, Kotlin) treat any call they can't resolve as not constant; and the Java and C# proof passes go further, assuming an unmodelled call returns what it is given. So "untainted" from an unknown call means "not reported by the engine" (the regex layer still applies, except for engine-owned rules), not "proven safe". |

### 4.5 Function summaries (spec §9)

| Summary kind | Status |
|---|---|
| Parameter → sink | present (`ParamSinkFact`, all engines, cross-file) |
| Parameter → return | present in all ten engines. (This audit first said Kotlin, Ruby, Rust and C/C++ lacked it -- wrong: each builds per-parameter `returnMask` summaries to a fixed point, `ctx.propagating`, and `interproceduralMatrixLanguages.test.ts` exercises them, e.g. `normalize(getInput())`, with safe twins.) |
| Parameter → parameter (out-params), parameter → object property, property → return | missing as summaries (C/C++ has `OUT_PARAM_SOURCES` for library functions only) |
| Parameter → store / side effect (DB, queue, session) | missing |
| Sanitisation effect of a callee | partial (a callee returning a sanitised value propagates the shadow bits through return summaries) |
| **Library models** (summaries for third-party functions, declared as data) | **partial** — step 5: every engine's propagators (29 sets: call → result, constructor → result, method arguments → result, arguments → receiver, decoders) are data in `models/propagators.ts`; per-function multi-endpoint summaries (`SummaryModel`) are not yet modelled |

### 4.6 Model registry, schema, framework models (spec §7, §10)

| Item | Status |
|---|---|
| Central registry of sources / sinks / propagators | **partial** — `src/lib/taint/models/`: rules, sanitizers (all engines), propagators (all engines), sinks (SSRF, all engines), sources (JVM). Other sink families and non-JVM sources are still engine code |
| Schema validation | present — TypeScript types plus `validateRegistry` (each check mutation-tested) |
| Framework models as data (Express, Flask, Spring, …) | missing — framework knowledge is spread through each engine |
| Versioned models | missing |

### 4.7 Testing and metrics (spec §11)

| Item | Status |
|---|---|
| Positive / negative per engine | present (unit tests; table in §3) |
| Interprocedural with safe twins | present: the advanced suite for JS, Python, Go, Java (22 cases), and `interproceduralMatrixLanguages.test.ts` (12 shapes with safe twins) for Java, PHP, Ruby, C#, Kotlin, Rust, C/C++ — an earlier version of this table missed the latter |
| Cross-file | present (`crossFile/cases.ts`, 6 languages) |
| Sanitizer bypass tests | partial (scattered in engine tests) |
| Corpus benchmarks per category | present (`benchmarks/`, report on `/benchmarks`) |
| Self-scan false-positive floor | present (`fpBenchmarkCorpus`) |
| Per-language, per-CWE precision/recall, trace accuracy | partial — per category per corpus yes; trace accuracy only in the interprocedural suite |
| Model coverage tracked separately from detection | partial — `modelRegistry.test.ts` pins which languages each model family covers (SSRF sinks and propagators: all ten) |

## 5. Duplication and inconsistency found

1. **Java and Kotlin** each define `SERVLET_SOURCE_CALLS` and `SPRING_SOURCE_ANNOTATIONS` — same JVM APIs, two copies. *Resolved in step 3 (`models/sources.ts`).*
2. **Sinks exist twice for languages that have an engine**: the pattern layer's `SSRF_RE` has Java/Kotlin, Go, PHP, Python and C# entries alongside each engine's own SSRF sink. The veto (`suppressedSinks`) hides the duplicate only when the engine *proves* a sink safe; when the engine simply misses a flow, the regex fires on its own (this is by design today, but the two definitions can drift). *Resolved for SSRF in step 4: SSRF is an engine-owned rule (`ENGINE_OWNED_RULES`), its regex findings dropped on files an engine analysed, after measurement. Other rules keep the dual layer.*
3. **Function identity**: Java's `localMethods` is keyed by method name, so two classes' same-named methods collided (fixed in this work for seeding and traces; the map itself is unchanged and other passes still read it).
4. **Trace builders**: JS/TS has a bespoke builder; the nine other engines share `buildBackwardTraceGeneric`. Improvements to the shared one (closure capture, globals, keyed stores — this work) do not reach JS/TS.
5. ~~**Uneven summaries**: parameter→return exists in six engines and not in four~~ — *withdrawn: all ten have it (§4.5); the audit was wrong.*
6. **No C/C++ sanitizer table**, while every other engine reads `sanitizers.ts`. *Resolved in step 2.*
7. **Unknown calls**: the "opaque call is untainted" default is uniform, documented, and the opposite of the spec's rule. *Decided in step 7, with measurements: kept for detection; safety claims never rest on it.*

## 6. Proposed design and migration plan

### 6.1 Principles

- **Build on the shared core, do not replace engines.** The lattice, sanitizer table, summary format and evidence are already universal. Parsing and per-language semantics stay in the engines.
- **TypeScript-typed models, validated at load.** Models are TypeScript data (the compiler is the first schema check) plus a runtime validator for anything loaded from JSON. No new dependency.
- **Declarative first, predicate hook when needed.** Most sinks are "callee pattern + argument positions + rule". Some need context (receiver type, argument shape, a framework context variable); a model entry may name a predicate implemented in the engine, rather than forcing everything into data.
- **Every migration slice keeps results identical.** Before any rule moves, record a golden snapshot of findings for every corpus and test suite; a slice is accepted only if the snapshot is unchanged (or each difference is reviewed and explained).

### 6.2 Model shapes (to be implemented in `src/lib/taint/models/`)

```ts
type Lang = "js" | "py" | "java" | "kt" | "go" | "cs" | "php" | "rb" | "rs" | "cpp";

interface SourceModel {      // where untrusted data enters
  id: string; lang: Lang | Lang[]; framework?: string;
  kind: "http.query" | "http.body" | "http.header" | "http.cookie" | "http.path" | "file.upload"
      | "env" | "cli" | "stdin" | "network" | "queue" | "db.read" | "session" | "deserialized" | …;
  trust: "untrusted" | "semi-trusted";           // provenance, carried into evidence
  match: CallMatch | MemberMatch | AnnotationMatch | ParamTypeMatch;
}
interface SinkModel {        // where it becomes dangerous
  id: string; lang: Lang | Lang[]; framework?: string;
  rule: RuleId; match: CallMatch; args: number[] | "all" | "rest" | { from: number };
  role: string;                                   // "the SQL query text" -> DataFlowEvidence.sink.role
  predicate?: string;                             // named engine hook, for context-dependent sinks
}
interface SanitizerModel {   // what it neutralises (today's sanitizers.ts entries)
  id: string; lang: Lang | Lang[]; match: CallMatch; clears: SinkClassName[] | { predicate: string };
}
interface PropagatorModel {  // library calls that carry taint (arg -> return, arg -> receiver, receiver -> return)
  id: string; lang: Lang | Lang[]; match: CallMatch; from: Endpoint; to: Endpoint;
}
interface SummaryModel {     // library function summaries, the declared counterpart of ParamSinkFact
  id: string; lang: Lang; function: string;
  flows: Array<{ from: Endpoint; to: Endpoint | { sink: RuleId } | { store: string } }>;
}
interface RuleModel {        // a vulnerability rule over the shared vocabulary
  id: RuleId; cwe: string; sinkClass: SinkClassName; sourceKinds: SourceModel["kind"][];
  severity: "critical" | "high" | "medium" | "low"; tests: { positive: string[]; negative: string[] };
}
```

`CallMatch` covers what the engines already match on: an exact callee (`exec.Command`), a receiver-type + method
(`DocumentBuilder.parse`), a tail on a receiver named/typed like something (`*.setAttribute` on a session), a
constructor (`new ObjectInputStream`), with argument positions.

### 6.3 Engine adapter

Each engine keeps its parser and walker and gains a small adapter: given a call / member / annotation node, ask
the registry *is this a source / sink / sanitizer / propagator, and with which arguments?* The registry answers
from the models for that language (plus the frameworks detected in the file). The engine's own checks remain as
named predicates for what the models cannot express.

### 6.4 Migration steps

| Step | Change | Preservation check |
|---|---|---|
| 0 | **Golden snapshot**: findings (id, file, line, source, sink) for every unit-test fixture, every corpus in `benchmarks/`, the cross-file and interprocedural suites, and the self-scan | Committed snapshot; a test compares against it |
| 1 | Registry skeleton: types, runtime validator, loader, taxonomy (`SinkClass` names, rule ids, CWE from `cweMap.ts`) — no engine reads it yet | Unit tests for the validator; snapshot unchanged |
| 2 | Move `sanitizers.ts` behind the registry (already data; same lookup function, same results) and add the C/C++ table | Snapshot unchanged except new C/C++ sanitizer effects, each reviewed |
| 3 | Sources, one language family at a time, starting with the JVM (dedupes Java/Kotlin, §5.1) | Snapshot unchanged |
| 4 | Sinks, one sink family at a time (SSRF clients first: small and duplicated in the pattern layer) | Snapshot unchanged; the matching pattern-layer regex can then be removed for engine languages |
| 5 | Library summaries and propagators as data; parameter→return summaries for Kotlin, Ruby, Rust, C/C++ | Snapshot may only gain findings; each gain reviewed; interprocedural suite extended to those languages |
| 6 | Trust/provenance on sources, carried into `DataFlowEvidence` | Evidence fields only |
| 7 | Decide the unknown-call default (spec §14.9) with measurements on every corpus | A separate decision, with false-positive numbers |

**Progress**

| Step | Status |
|---|---|
| 0 | Done for in-repo programs: `src/__tests__/benchmarks/golden/` — 100 programs (6 hard fixtures, every cross-file case, every interprocedural fixture), 524 findings as `file:line rule <- source`, deterministic across runs (522 since step 4 removed two regex-only false positives, see below). Kotlin, Ruby, Rust and C/C++ have no in-repo benchmark program; they are guarded by their engine unit tests and by the external corpora (`benchmarks/`), whose TSVs are compared per slice. |
| 1 | Done: `src/lib/taint/models/` — `types.ts` (shared vocabulary), `registry.ts` (rules taxonomy from `RULE_SINK_CLASSES` + `cweMap.ts` + `ruleLanguages.ts`; sanitizer models from `sanitizers.ts`, read from the same tables the engines use), `validateRegistry`. Tests: `modelRegistry.test.ts` (consistent today; each validator check mutation-tested). No engine reads the registry yet. |
| 2 | Done: C/C++ sanitizers (atoi/strtol/stoi… — its private `NUMERIC_CONVERSIONS` set) moved into `sanitizers.ts` as the `cpp` table; the C/C++ engine now calls `sanitizerClears("cpp", …)` like every engine. Every language now has sanitizer models in the registry. Behaviour identical (C/C++ engine tests). |
| 3 | Done for the JVM: `models/sources.ts` — Servlet, Spring/JAX-RS and WebFlux sources with `kind` and `trust` (`getRemoteUser`: identity, semi-trusted); Java and Kotlin read their sets from it (`sourceNames`) instead of two copies. Each entry records the languages that used it, so detection is unchanged (sets pinned in tests; golden snapshot unchanged). **Model coverage found:** Java lacks `getParts` and the WebFlux functional API that Kotlin has — enabling them for Java is a separate, reviewed change. |
| 4 | SSRF HTTP-client family done for JS/TS, Python and Go: `models/sinks.ts` (18 models) — Go `net/http`, a `Client`, `net.Dial*`; Python `requests`, `httpx`, `urllib`; JS/TS `fetch`, Node `http`/`https` (only when imported), `axios`, `got`/`needle`/`request`/`superagent`/`node-fetch`/`undici`/`cross-fetch` (also called directly). Each model says which argument is the URL: position, per-method position, keyword (before or after the position), `proxies`, or an engine-side selector (`select`: a JS options object's url/host/path/proxy, and "a method name may come first"). All three engines' matchers read it (`sinkModelFor`); the old in-engine branches and name sets are removed. Evidence: golden snapshot unchanged; Juice Shop (1,138 findings) and NodeGoat (16) identical line for line before and after; argument rules covered by engine-level tests (`sinkModelsEngines.test.ts`, 16 cases).<br>Then Java, C# and Kotlin (37 models in all). New match kinds: a method on any receiver, a constructor (`new Socket`); new selectors: the URL object a call is made on, the whole call chain (`HttpRequest.newBuilder().uri(x)`), an HTTP-client receiver by type or name, `url(...)` inside a client's request lambda, the receiver as the URL (`"…".httpGet()`). Kotlin judges every matching sink independently, so it reads all hits in order (`sinkModelsFor`); sinks carry an evidence label template and `target: "host"` where the value is a host, not a URL. C#'s `CS_SSRF_TAILS` and Kotlin's `REST_TEMPLATE_METHODS`/`URL_READ_METHODS` are removed; Kotlin's client-method set is read from the model. Evidence: golden snapshot unchanged; OWASP Benchmark Java 1.2 identical line for line (5,490 findings, score 86 / category-averaged 87.5, before and after); engine-level tests now 47 cases (Java 7, C# 7, Kotlin 17); every new branch mutation-checked (two survivors judged equivalent: a lambda carries no taint mask, and a host string judged by URL shape gives the same verdict as by taint). Not re-run: Juliet C# and the Kotlin corpora (sources not on this machine). Found on the way: the rule catalog listed XXE for Kotlin because Kotlin reused Java's id list; Kotlin's id type now excludes it.<br>Then PHP, Ruby, Rust and C/C++ (51 models in all -- the earlier counts of 18 and 37 were each one short: the JS set is 11; SSRF now comes from the registry in every engine, pinned by a test). C/C++'s libcurl sink is judged only when its option argument names `CURLOPT_URL` (`whenArg`). New: a whole-callee `pattern` match (Ruby's and Rust's client families); selectors for PHP stream reads (fetch only when the value can start a URL -- also where those reads' path-traversal check now hangs) and curl options (`curl_setopt($ch, OPT, $v)` / `$curl->setopt(OPT, $v)`, judged only for destination options). Ruby still judges the first URL sink that applies, once. Removed: PHP `URL_CAPABLE_READS_PHP`, Ruby `HOST_CONNECT_RE`/`SSRF_CALL_RE`/`URL_OR_PATH_FETCH_RE`, Rust `HTTP_FREE_FNS`/`HTTP_CLIENT_METHODS`. Evidence: golden unchanged; the two in-repo-adjacent multi-language benchmarks (33 PHP/Ruby/Rust files) identical before and after with HEAD's engine files swapped in (25 findings, PHP curl and Ruby `URI.open` SSRF among them; neither has a Rust finding, so Rust rests on its tests); engine-level tests now 73 cases (PHP 10, Ruby 9, Rust 7 added; C/C++ by its existing engine tests, which cover both options); every new branch mutation-checked (one survivor judged equivalent: without Ruby's host filter a host sink's argument is judged a second time, by URL shape, on the same line). The 0llino sast-benchmark (PHP/Ruby/Rust) is not on this machine and was not re-run.<br>Finally the pattern layer: rather than deleting `SSRF_RE` and the named-taint SSRF detectors (they remain the only check on a file no engine parses -- a language without one, a parse over the size cap), SSRF became an **engine-owned rule** (`ENGINE_OWNED_RULES` in `scanner.ts`): its regex findings are dropped on files an engine analysed. Measured first, with the switch as an experiment: Juice Shop lost exactly two findings, both false positives (supertest `request(app)` calls in `test/api/data-export.test.ts`), NodeGoat unchanged; the golden snapshot lost two, also false positives (`interprocedural/GO-02`: the regex's case-insensitive `fetch(` matched the method declaration `func (c *Client) Fetch(target string)` and the interface call `f.Fetch(target)`; the real sink, `http.Get(target)`, is still reported by the engine) -- snapshot updated by removing exactly those two lines, 524 → 522. *(Correction: this row first said the full suite was unchanged. The golden test's failure was hidden by an output filter that only matched `describe › test` names; it was found when the next change was verified.)* Otherwise the suite was unchanged apart from the known Node 18 environment failures; and in every corpus TSV on hand (OWASP Benchmark Java, WebGoat, crAPI, Juice Shop, NodeGoat) every SSRF finding beside those two came from an engine. Pinned by `engineOwnedRules.test.ts` (dropped on an engine file, kept for a language without an engine). **Done.** |
| 5 | Done. Propagators as data: `models/propagators.ts` holds every engine's propagator sets -- 29 sets across all ten engines (call → result, `new` → result, method arguments → result, arguments → receiver, decoders), moved verbatim with their comments; each engine reads them with `propagatorNames(lang, kind)`. Verified identical set by set (all 29 equal to the engine constants they replaced) and by the full suite (4,404 passed; failures only the known environment ones and a load-sensitive timing test). The registry validates them, and a consistency check found no decoder that doesn't also propagate. Parameter → return summaries: already present in Kotlin, Ruby, Rust and C/C++ (the audit was wrong, §4.5) and already exercised by `interproceduralMatrixLanguages.test.ts`; nothing to add. Not done: multi-endpoint per-function library summaries (`SummaryModel`, e.g. "argument 0 → receiver field") -- no engine has a consumer for them yet. |
| 6 | Done. `DataFlowEvidence.source` gains `kind`, `trust` (`untrusted` / `semi-trusted` / `assumed`) and `model`; SARIF carries `trustledger/sourceKind` and `trustledger/sourceTrust`. JVM flows take both from the source model that matched where the flow starts -- including a bare parameter, whose annotated declaration (`@RequestHeader("X-Id") String id`) the scanner finds (`jvmParamBinding`); other languages get `kind` from the recognised input shape and `trust: untrusted`; an engine-assumed parameter is `trust: assumed` and claims no model. Tests: `sourceProvenance.test.ts` (unit, and real scanner output for a Spring header). |
| 7 | **Decided: keep "unknown calls are untainted" for detection, in every engine.** Measured with a temporary switch that made a call no model describes carry its arguments' (and receiver's) taint, in the JS, Python and Java engines -- the three with labelled corpora on this machine -- each corpus scanned both ways with the repository's own scorers:<br>• OWASP Benchmark Java 1.2: TP 1262 → 1335, **FP 39 → 444**, score 86 → **61** (FP rate up in every injection category: SQL 39 → 153, XSS 0 → 112, command 0 → 64, path 0 → 65 -- the benchmark's safe cases route input through helpers that discard it).<br>• OWASP Benchmark Python 0.1: TP 435 → 452, FP 8 → 11, score 95 → 99 -- but 194 new rule hits in total, most in categories the scorer doesn't count for that case; the recovered miss inspected (Test00003, path traversal) goes through a call on a factory-made object of another file (`helpers.ThingFactory.createThing().doSomething(param)`) -- an interprocedural gap, not a library call.<br>• Juice Shop: challenges 15/35 either way; +14 findings, false positives on inspection (SQL and timing checks over `security.hash(...)` output, JSON event streams as XSS, `{ email: … }` filters built from the logged-in user as NoSQL injection).<br>• crAPI (67 real Python files): +9 findings, all log injection on non-request values (`type(data).__name__`, `len(message)`, a seeded user's email, the server's own payment responses); none new and real.<br>• NodeGoat: unchanged.<br>Not measurable here: Go, C#, PHP, Ruby, Rust, Kotlin, C/C++ (labelled corpora not on this machine); their engines share the default, and the measured languages give no reason to expect a different trade. The switch was removed after measuring (it hooked the unknown-call fallbacks: `callMask`'s final return in `astTaint.ts` and `astTaintPython.ts`, the method-argument default beside each, and the generic passthrough at the end of `astTaintJava.ts`'s call chain). Follow-up found: Python lacks Java's cross-file pass-through for calls on objects of a batch class (`passMethods`) -- the cause of the inspected OWASP Python miss. **Done since:** `computePassMethodsPy` summarises every instance method (which arguments reach its return, after `self`); `collectPassMethodsPy` keeps a method name only when every batch definition passes the same argument through, intersecting what survives (a factory may return any of them), skipping builtin method names, and including files restored from the module cache so their definitions still veto; the engine applies it only to calls it can't resolve itself, and the cache key carries it. Result: OWASP Benchmark Python **TP 435 → 452 (no misses left), FP 8 → 6, score 95 → 99** (category-averaged 94.1 → 98.8) -- 22 targeted rule hits added, 2 `eval-exec` false positives gone; crAPI identical (88 findings); golden snapshot unchanged. Everything the "carry every unknown call" switch found, for none of its noise. Tests: `pythonPassMethods.test.ts` (summaries, the every-definition rule, end to end both ways), mutation-checked. |

Propagation-engine work (the remaining JS/Python interprocedural gaps, JS trace builder parity) continues in
parallel; it is analysis capability, not model data, and the interprocedural suite measures it.

## 7. Known limitations of this audit

- Kotlin, C#, PHP, Ruby, Rust and C/C++ are measured by `interproceduralMatrixLanguages.test.ts` (12 shapes with safe twins), not by the advanced 22-case suite; the advanced shapes in §4.3 (closures, events, generators, ...) for those languages come from code inspection. (The first version of this audit overlooked the matrix.)
- The engine table (§3) records whether a mechanism exists, not how complete it is.
- Framework coverage per language was not enumerated entry by entry; step 3 of the migration produces that inventory as a side effect.
