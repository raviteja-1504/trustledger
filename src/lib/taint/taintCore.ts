/**
 * Shared, tree-agnostic taint primitives for every AST taint engine
 * (astTaint*.ts). Deliberately kept out of scanner.ts: this is the one place
 * the engines agree on what a taint value IS, so it must not depend on any
 * parser or on the detector layer.
 *
 * A taint value is a bitmask of SINK CLASSES the value is still dangerous
 * for (not a boolean). Sources start at ALL; a sanitizer clears only the
 * classes it actually neutralizes (htmlspecialchars clears XSS, NOT SQL or
 * command injection); a sink checks only its own class bit. Every combinator
 * that used to be `||` is now a bitwise OR, so the OR-shaped monotonicity the
 * engines' fixed-point summaries rely on is preserved exactly.
 */

export const SinkClass = {
  SQL: 1 << 0,
  CMD: 1 << 1,
  XSS: 1 << 2,
  SSRF: 1 << 3,
  PATH: 1 << 4,
  REDIRECT: 1 << 5,
  DESERIAL: 1 << 6,
  INCLUDE: 1 << 7,
  LDAP: 1 << 8,
  XPATH: 1 << 9,
  NOSQL: 1 << 10,
  HEADER: 1 << 11,
  EVAL: 1 << 12,
  SSTI: 1 << 13,
  // Not an injection class: "this value is attacker-CONTROLLED" (an id the
  // caller chose). Sources carry it and numeric coercion deliberately does
  // NOT clear it -- strconv.Atoi(c.Param("id")) is no longer injectable but
  // is still exactly the resource id an IDOR/BOLA check cares about.
  CONTROL: 1 << 14,
} as const;

export const ALL = (1 << 15) - 1;

/** Classes an unspecified numeric/URL-safe encoder reasonably neutralizes. */
export const URL_SAFE = SinkClass.SSRF | SinkClass.REDIRECT | SinkClass.HEADER | SinkClass.PATH;

const ID_TO_CLASS: Record<string, number> = {
  "sql-injection": SinkClass.SQL,
  "command-injection": SinkClass.CMD,
  "xss": SinkClass.XSS,
  "ssrf": SinkClass.SSRF,
  "path-traversal": SinkClass.PATH,
  "open-redirect": SinkClass.REDIRECT,
  "insecure-deserialization": SinkClass.DESERIAL,
  "file-inclusion": SinkClass.INCLUDE,
  "ldap-injection": SinkClass.LDAP,
  "xpath-injection": SinkClass.XPATH,
  "nosql-injection": SinkClass.NOSQL,
  "header-injection": SinkClass.HEADER,
  "eval-exec": SinkClass.EVAL,
  "ssti": SinkClass.SSTI,
  "idor": SinkClass.CONTROL,
  "bola-missing-ownership-check": SinkClass.CONTROL,
  "argument-injection": SinkClass.CONTROL,
};

/** Sink class for a finding id. Unknown ids (e.g. authorization findings,
 * which are not taint-class based) map to ALL so they never get masked out. */
export function classOf(findingId: string): number {
  return ID_TO_CLASS[findingId] ?? ALL;
}

/**
 * A taint value's LOW 15 bits are the classes it is still dangerous for. Its
 * HIGH bits (shifted by SHADOW) record the classes a sanitizer or guard
 * actually CLEARED on the way to here. The shadow half never affects a sink
 * decision; it exists so an engine can tell "never tainted for this class"
 * from "tainted, then correctly sanitized" -- the second case is what lets
 * scanner.ts drop the regex layer's duplicate finding for a flow the AST
 * engine positively proved safe (see SuppressedSink), without dropping
 * regex findings the engine merely failed to see.
 */
export const SHADOW = 16;

/** Apply a sanitizer/guard: clear `clears` from the taint bits, remember it in the shadow bits. */
export function applyClears(mask: number, clears: number): number {
  return (mask & ~clears) | ((mask & clears & ALL) << SHADOW);
}

// ── Value kinds ─────────────────────────────────────────────────────────────
//
// A taint value's 32 bits are: the class half (bits 0-14, "still dangerous for class c"), the shadow half (bits
// 16-30, "was cleared for class c"), and exactly two unused bits. Bit 15 -- the one between the halves -- carries
// the only VALUE KIND that changes what a sink should conclude: "this value's clearing depends on WHERE it ends
// up, not just that it was cleared". (Bit 31 is the sign bit and is left alone.) It is a kind rather than a class:
// it says nothing about what the value can reach, only how it got cleared, which is what decides whether the
// clearing still holds where the value ends up.
//
// Why some clearing needs a kind. Three different sanitizer FAMILIES clear the same class bits for three
// different reasons, and only one promise survives a change of position:
//   - a full coercion (parseInt, Number, an (int) cast) changes what the value IS -- a number can't carry a SQL
//     quote or a URL scheme no matter where it lands, so its clearing is safe EVERYWHERE.
//   - an encoder (encodeURIComponent, urllib.parse.quote) or an escaper (mysqli_real_escape_string, addslashes)
//     changes the value's TEXT, neutralizing exactly the characters that matter in ONE syntactic position -- a
//     path/query segment for a URL encoder, a quoted string literal for a SQL escaper -- and nothing outside it:
//     `169.254.169.254` has no character a URL encoder touches, so `"http://" + enc(host)` still lets the
//     attacker choose the host; `1; DROP TABLE users--` has no quote a SQL escaper needs to touch, so
//     `"...WHERE id = " + escape(id)` is still injectable in that unquoted position.
//   - a guard (allowlist membership, `applyGuards`) doesn't change the value at all -- it proves the value was
//     one of a fixed set of safe ones, which holds everywhere, so it sets no kind either.
// The class/shadow bits alone can only say "class c was cleared" -- true for all three families, which is not
// enough to tell a position-dependent clearing from a permanent one. See taint/sinkShape.ts for the position
// analyses (one per sink shape: URL, SQL, ...) that consume this bit.
//
// Every engine masks class decisions with `& ALL` (the shadow half already forced that discipline), so the extra
// bit is invisible to them: it can never make a value look tainted and never survives a full coercion below.
export const KIND_POSITION_SENSITIVE = 1 << 15;

/** A numeric/boolean/uuid coercion neutralizes the injection classes an encoder never does (SQL, command). */
export function isCoercionClears(clears: number): boolean {
  return (clears & SinkClass.SQL) !== 0 && (clears & SinkClass.CMD) !== 0;
}

/** The URL-encoder family of sanitizers clears SSRF (and the other URL-context classes) but not every class. */
export function isUrlEncoderClears(clears: number): boolean {
  return (clears & SinkClass.SSRF) !== 0 && !isCoercionClears(clears);
}

/** The SQL-escaper family (mysqli_real_escape_string, addslashes, connection.escape, ...) neutralizes quote-breaking
 * characters -- a real defence inside a quoted string literal, none at all outside one. */
export function isSqlEscapeClears(clears: number): boolean {
  return (clears & SinkClass.SQL) !== 0 && !isCoercionClears(clears);
}

/** Whether `clears` is a POSITION-DEPENDENT clearing (an encoder or escaper) rather than a permanent one (a
 * coercion or, via applyGuards, a guard). One shared kind bit serves every sink-shape family: each position
 * analysis (sinkShape.ts) already filters by its OWN class first (`wasCleared(mask, SinkClass.SSRF)` vs
 * `...SQL`), so a value that is e.g. SQL-escaped-only never confuses the SSRF analysis, which never asks about
 * the SQL class bit at all. */
function isPositionDependentClears(clears: number): boolean {
  return isUrlEncoderClears(clears) || isSqlEscapeClears(clears);
}

/**
 * applyClears plus value-kind bookkeeping; engines call this at a SANITIZER call (guards use applyGuards, which
 * deliberately sets no kind: an allowlist check is safe in every position). A full coercion (parseInt, Number, ...)
 * clears the kind too -- whatever the value was, it is now a number. The kind is only set when something was actually
 * cleared, so an untainted value passed through an encoder/escaper stays plain 0.
 */
export function applySanitizer(mask: number, clears: number): number {
  const out = applyClears(mask, clears);
  if (isCoercionClears(clears)) return out & ~KIND_POSITION_SENSITIVE;
  return isPositionDependentClears(clears) && (mask & clears & ALL) !== 0 ? out | KIND_POSITION_SENSITIVE : out;
}

/** Is the value still dangerous for any class at all? */
export function isTaintedMask(mask: number): boolean {
  return (mask & ALL) !== 0;
}

/** Was `cls` cleared from this value by a sanitizer/guard (and not re-tainted)? */
export function wasCleared(mask: number, cls: number): boolean {
  return ((mask >>> SHADOW) & cls) !== 0 && (mask & cls) === 0;
}

/** A sink whose argument was tainted for its class but positively cleared. */
export interface SuppressedSink { id: string; line: number }

// ── Parameter -> sink summaries (cross-file) ────────────────────────────────
//
// A function's cross-file summary used to carry ONE fact per parameter: which sink classes survive to its
// RETURN value. That misses the other half of what a callee does with its parameters -- passing them to a
// sink and returning nothing (`export function runQuery(sql) { db.execute(sql); }`). A call
// `runQuery(req.query.id)` from another file was invisible: the same-file "seed the callee's params and
// re-walk its body" pass could never reach a body that lives in a different file.
//
// A ParamSinkFact is that missing half: "if the argument bound to parameter `index` carries taint of class
// `sinkClass`, it reaches sink `sinkExpr` at `file:line`, which reports as finding `id`." Facts are
// computed BOTTOM-UP per function (each callee's facts before its callers'), so they compose across any
// number of calls -- including calls into other files' facts -- and flow the same direction as the
// existing return summaries (callee -> caller). That is a deliberate choice over a top-down "seed the
// callee from its callers" re-walk: it keeps the dependency edge one-directional (a callee never depends on
// its callers' content, so incremental reuse and the cross-file fixed point need no new machinery) and the
// finding lands at the CALL SITE, in the file being changed, which is where a PR review can act on it.
export interface ParamSinkFact {
  /** Parameter index the taint enters through; with `isRest`, every argument from this index on. */
  index: number;
  isRest: boolean;
  /** Finding id the sink reports as (e.g. "sql-injection"). */
  id: string;
  /** The single SinkClass bit for `id` -- stored so a consumer never re-derives it from an id table. */
  sinkClass: number;
  /** The sink call as written, e.g. "db.execute". */
  sinkExpr: string;
  /** File and 1-based line of the ORIGINAL sink, kept unchanged across every hop that forwards to it. */
  file: string;
  line: number;
  /** Function names from the summarized function down to the one that contains the sink (attribution only). */
  via: string[];
}

/** Identity of a fact for set-union. `via` is deliberately excluded: two routes to the same sink are the
 * same fact, and a recursive/mutually-recursive forwarder would otherwise grow `via` without bound. */
export function sinkFactKey(f: ParamSinkFact): string {
  return `${f.index}:${f.isRest ? 1 : 0}:${f.id}:${f.sinkExpr}:${f.file}:${f.line}`;
}

/** Bounds a single function's summary. Facts are kept in a deterministic order (sorted by key) so the cap
 * never makes a scan's output depend on Map iteration order or on which round produced a fact. */
export const MAX_SINK_FACTS_PER_FN = 24;

/**
 * Set-union `add` into `into`, first occurrence winning (so the shortest/earliest `via` is kept).
 * Returns whether anything was added. Keeps `into` sorted and capped at MAX_SINK_FACTS_PER_FN.
 */
export function mergeSinkFacts(into: ParamSinkFact[], add: readonly ParamSinkFact[]): boolean {
  if (add.length === 0) return false;
  const before = new Set(into.map(sinkFactKey));
  const have = new Set(before);
  let pushed = false;
  for (const f of add) {
    const k = sinkFactKey(f);
    if (have.has(k)) continue;
    have.add(k);
    into.push(f);
    pushed = true;
  }
  if (!pushed) return false;
  into.sort((a, b) => { const ka = sinkFactKey(a), kb = sinkFactKey(b); return ka < kb ? -1 : ka > kb ? 1 : 0; });
  if (into.length > MAX_SINK_FACTS_PER_FN) into.length = MAX_SINK_FACTS_PER_FN;
  // "Grew" is judged AFTER the cap: a fact the cap immediately dropped is not growth, and reporting it as
  // such would make a fixed point over a capped summary look perpetually unsettled.
  return into.some(f => !before.has(sinkFactKey(f)));
}

export type TaintEnv = Map<string, number>;

// ── Source -> sink trace (explainability layer) ─────────────────────────────
//
// The taint VALUE propagated through every engine's `env` stays a bitmask (above) -- that is a
// deliberate, load-bearing design choice, not an unfinished one: propagation runs on every
// assignment/branch/call in a file, so it has to stay a single integer with O(1) OR/AND/clear, the
// same reasoning that keeps SHADOW's "was this cleared" bit a shadow half of the SAME integer instead
// of a parallel structure. A TraceStep chain is the opposite shape -- built ONCE per actual finding
// (rare, only at emit() time), where the cost of walking back through the AST to explain *why* a
// value was tainted is negligible and the payoff (a reviewer can see the flow instead of re-deriving
// it) is real. The two are complementary layers over the same ID_TO_CLASS/SinkClass model, not two
// competing representations of taint.
export interface TraceStep {
  file: string;
  line: number;
  kind: "source" | "assignment" | "call" | "sanitizer" | "cross-file" | "sink";
  /** Short human label, e.g. "req.query.id" or "crosses into src/db.ts via buildQuery". */
  label: string;
  /** The relevant source snippet at this step (trimmed, not the whole line). */
  snippet: string;
}

// A bare identifier for every engine here: PHP's optional `$` sigil is the only per-language
// variation, so one shared pattern covers all five tree-sitter/CST-based engines below (astTaint.ts's
// own JS/TS implementation is hand-built against real ts.Node references instead -- see its own
// buildTrace docblock for why that one stays bespoke).
const BARE_IDENTIFIER_RE = /^\$?[A-Za-z_][A-Za-z0-9_]*$/;

/** Balanced-paren extraction of a call expression's FIRST top-level argument, from raw text --
 * language-agnostic (every engine here uses C-family call syntax), so this needs no per-language
 * hook. Returns null when `text` isn't call-shaped (no parens, or something other than a
 * dotted/bracketed identifier chain immediately before the first paren) or the call has no
 * arguments. */
function extractFirstCallArg(text: string): string | null {
  const open = text.indexOf("(");
  if (open < 0 || !text.trimEnd().endsWith(")")) return null;
  if (!/^[\w$.]+$/.test(text.slice(0, open).trim())) return null;
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")") {
      depth--;
      if (depth !== 0) continue;
      const inner = text.slice(open + 1, i).trim();
      if (inner.length === 0) return null;
      let d2 = 0;
      for (let j = 0; j < inner.length; j++) {
        const c = inner[j];
        if (c === "(" || c === "[" || c === "{") d2++;
        else if (c === ")" || c === "]" || c === "}") d2--;
        else if (c === "," && d2 === 0) return inner.slice(0, j).trim();
      }
      return inner;
    }
  }
  return null;
}

/** What buildBackwardTraceGeneric needs from a tree-agnostic engine to walk backward through it --
 * see its own docblock for the shared algorithm every resolver plugs into. */
export interface TraceResolver<N> {
  /** The function/method-like node lexically enclosing `node`, or null (module/top-level scope). */
  enclosingScope(node: N): N | null;
  /** Every simple `name = expr`-shaped assignment (declarations included) within `scope` -- a
   * destructuring/compound target is simply invisible to this, which only means the trace stops one
   * hop early there, never wrong. */
  assignmentsIn(scope: N): Array<{ name: string; position: number; rhsText: string; line: number }>;
  /** A stable, comparable source-order position (e.g. startIndex) -- only used to find the LATEST
   * assignment that still precedes a given position, never displayed. */
  position(node: N): number;
  line(node: N): number;
  text(node: N): string;
  /** Cross-file continuation (engines with cross-file support only): when `text` is a call to a
   * cross-file-propagating import, the extra step(s) to append -- the slice STOPS after these (the
   * callee's own sub-slice is a documented one-hop boundary, matching astTaint.ts's identical
   * policy), same as returning null does for a name this resolver doesn't recognize as cross-file. */
  crossFileHop?(text: string): TraceStep[] | null;
}

const MAX_TRACE_HOPS = 6;

/**
 * Bounded backward slice from a sink's tainted argument (given only as TEXT -- every engine here
 * already computes `sourceExpr` this way) back to its origin, presented source-first. Shared by every
 * engine except astTaint.ts's own JS/TS implementation (hand-built against real ts.Node references,
 * see its buildTrace docblock for why) -- five tree-sitter/CST engines would otherwise duplicate this
 * exact walk five times over. Text/position-based rather than fully AST-typed on purpose: it lets one
 * function serve resolvers built from completely different parsers (web-tree-sitter's SyntaxNode for
 * four engines, Chevrotain's CstNode for Java) through one small interface instead of five bespoke
 * walks. See TraceStep's own docblock for why this whole layer runs only at finding time.
 */
export function buildBackwardTraceGeneric<N>(
  filePath: string, sinkNode: N, sourceText: string, sinkText: string, resolver: TraceResolver<N>,
): TraceStep[] {
  const backward: TraceStep[] = [];
  const visited = new Set<string>();
  const scope = resolver.enclosingScope(sinkNode);
  let curText = sourceText.trim();
  let curPos = resolver.position(sinkNode);
  let curLine = resolver.line(sinkNode);

  for (let hop = 0; hop < MAX_TRACE_HOPS; hop++) {
    const crossSteps = resolver.crossFileHop?.(curText);
    if (crossSteps && crossSteps.length > 0) { backward.push(...crossSteps); break; }

    if (BARE_IDENTIFIER_RE.test(curText)) {
      if (visited.has(curText)) break; // a re-assignment cycle -- stop rather than loop
      visited.add(curText);
      const candidates = scope ? resolver.assignmentsIn(scope).filter(a => a.name === curText && a.position < curPos) : [];
      if (candidates.length === 0) {
        backward.push({ file: filePath, line: curLine, kind: "source", label: curText, snippet: curText });
        break;
      }
      const best = candidates.reduce((a, b) => (b.position > a.position ? b : a));
      backward.push({
        file: filePath, line: best.line, kind: "assignment",
        label: `${curText} = ${best.rhsText.slice(0, 80)}`, snippet: best.rhsText.slice(0, 100),
      });
      curText = best.rhsText.trim();
      curPos = best.position;
      curLine = best.line;
      continue;
    }

    const firstArg = extractFirstCallArg(curText);
    if (firstArg !== null) {
      backward.push({ file: filePath, line: curLine, kind: "call", label: curText.slice(0, 80), snippet: curText.slice(0, 100) });
      curText = firstArg;
      continue;
    }

    backward.push({ file: filePath, line: curLine, kind: "source", label: curText.slice(0, 80), snippet: curText.slice(0, 100) });
    break;
  }

  backward.reverse();
  // Adjacent steps that landed on the exact same line with the exact same text are redundant (a
  // source step immediately followed by an assignment step whose RHS IS that same source, e.g.
  // `const id = req.query.id;`) -- collapse rather than show the same snippet twice.
  const deduped = backward.filter((s, i) => i === 0 || s.line !== backward[i - 1].line || s.snippet !== backward[i - 1].snippet);
  deduped.push({ file: filePath, line: resolver.line(sinkNode), kind: "sink", label: sinkText, snippet: resolver.text(sinkNode).slice(0, 100) });
  return deduped;
}

export function cloneEnv(env: TaintEnv): TaintEnv {
  return new Map(env);
}

/** Per-key bitwise OR across environments (may-taint join). */
export function joinEnvs(envs: readonly TaintEnv[]): TaintEnv {
  const out: TaintEnv = new Map();
  for (const e of envs) {
    for (const [k, v] of e) out.set(k, (out.get(k) ?? 0) | v);
  }
  return out;
}

// ── Path sensitivity helpers (shared by every engine's branch handling) ─────

/** Every injection class -- everything except CONTROL ("attacker-controlled"). */
export const INJECTION = ALL & ~SinkClass.CONTROL;

/** Replace `target`'s contents with `src`'s (envs are mutated in place because callers hold references). */
export function assignEnv(target: TaintEnv, src: TaintEnv): void {
  target.clear();
  for (const [k, v] of src) target.set(k, v);
}

export interface Arm { env: TaintEnv; terminated: boolean }

/**
 * Join the environments of the arms that can actually reach the join point.
 * An arm that ends in return/throw (or break/continue where relevant) never
 * gets there, so it must not contribute its taint -- that is what makes
 * `if (!valid(x)) return; sink(x)` come out clean. If EVERY arm terminates,
 * so does the construct, and the returned env is irrelevant (dead code).
 */
export function joinArms(arms: readonly Arm[]): Arm {
  const live = arms.filter(a => !a.terminated);
  if (live.length === 0) return { env: joinEnvs(arms.map(a => a.env)), terminated: true };
  return { env: joinEnvs(live.map(a => a.env)), terminated: false };
}

/**
 * A narrow, recognized validation guard: variable `name` is proven safe for
 * every injection class in the arm where the guarded condition evaluates to
 * `holds`. Bare identifiers only, and deliberately only unambiguous guards
 * (literal-collection membership, strict numeric/type checks, equality with
 * a literal) -- a wrongly recognized guard silently hides a real finding.
 */
export interface Guard { name: string; holds: "true" | "false" }

/** Mark `names` as validated in `env`: clears injection classes, remembers it in the shadow bits (regex-veto data). */
export function applyGuards(env: TaintEnv, names: readonly string[]): void {
  for (const name of names) {
    const m = env.get(name);
    if (m) env.set(name, applyClears(m, INJECTION));
  }
}

/** Names guarded in the arm where the condition evaluates to `side`. */
export function guardedNames(guards: readonly Guard[], side: "true" | "false"): string[] {
  return guards.filter(g => g.holds === side).map(g => g.name);
}

// ── Shared control-flow combinators ─────────────────────────────────────────
// Each engine keeps its own tree API and only tells these combinators how to
// walk a body; the env cloning / may-taint join / terminated-arm dropping is
// identical everywhere so it lives here once.

export interface Branch {
  /** Absent for a plain `else`. Visits the condition's sub-expressions (sink checks) with the env that reaches it. */
  visitCond?: (env: TaintEnv) => void;
  /** Validation guards this condition proves (only meaningful with visitCond). */
  guards?: () => Guard[];
  /** Walk the arm's body on the given (cloned) env; returns true if control cannot continue past it. */
  body: (env: TaintEnv) => boolean;
}

/**
 * if / elif / else chain. Each condition is evaluated with the env that
 * reaches it (all earlier conditions false); each arm walks a clone with its
 * own condition's true-side guards applied; the fallthrough carries the
 * false-side guards forward. Terminated arms drop out of the join.
 */
export function walkIfChain(env: TaintEnv, branches: readonly Branch[]): boolean {
  const arms: Arm[] = [];
  let fall = cloneEnv(env);
  let hasElse = false;
  for (const br of branches) {
    if (br.visitCond) {
      br.visitCond(fall);
      const guards = br.guards?.() ?? [];
      const armEnv = cloneEnv(fall);
      applyGuards(armEnv, guardedNames(guards, "true"));
      arms.push({ env: armEnv, terminated: br.body(armEnv) });
      fall = cloneEnv(fall);
      applyGuards(fall, guardedNames(guards, "false"));
    } else {
      hasElse = true;
      const armEnv = cloneEnv(fall);
      arms.push({ env: armEnv, terminated: br.body(armEnv) });
    }
  }
  if (!hasElse) arms.push({ env: fall, terminated: false });
  const joined = joinArms(arms);
  assignEnv(env, joined.env);
  return joined.terminated;
}

/**
 * Loop: body walked on a clone TWICE (so a value assigned late in iteration
 * N reaches a sink early in N+1; findings dedupe by id+line), then joined
 * with the pre-loop env (the body may run zero times). Always "continues".
 */
export function walkLoop(env: TaintEnv, body: (env: TaintEnv) => boolean): boolean {
  const pre = cloneEnv(env);
  const bodyEnv = cloneEnv(env);
  let term = body(bodyEnv);
  if (!term) term = body(bodyEnv);
  assignEnv(env, joinArms([{ env: pre, terminated: false }, { env: bodyEnv, terminated: term }]).env);
  return false;
}

export interface CatchArm {
  /** Names bound by the handler (e.g. the exception variable) -- start untainted, shadowing outer names. */
  bind: string[];
  body: (env: TaintEnv) => boolean;
}

/**
 * try / catch / finally. A handler can be entered from anywhere inside the
 * try body, so its entry env is the join of the pre-try env and the try-end
 * env. The construct terminates only if the try body and every handler do.
 */
export function walkTry(
  env: TaintEnv, tryBody: (env: TaintEnv) => boolean, catches: readonly CatchArm[],
  finallyBody?: (env: TaintEnv) => boolean,
): boolean {
  const pre = cloneEnv(env);
  const tryEnv = cloneEnv(env);
  const arms: Arm[] = [{ env: tryEnv, terminated: tryBody(tryEnv) }];
  for (const c of catches) {
    const catchEnv = joinEnvs([pre, tryEnv]);
    for (const n of c.bind) catchEnv.set(n, 0);
    arms.push({ env: catchEnv, terminated: c.body(catchEnv) });
  }
  const joined = joinArms(arms);
  assignEnv(env, joined.env);
  let term = joined.terminated;
  if (finallyBody) term = finallyBody(env) || term;
  return term;
}

export interface SwitchClause {
  isDefault: boolean;
  /** Runs on the clause's cloned env before its body (visit the case label, apply literal-subject guard). */
  pre?: (env: TaintEnv) => void;
  body: (env: TaintEnv) => boolean;
}

/**
 * switch: every clause starts from the pre-switch env (fallthrough between
 * clauses is not modeled), joined with the pre-switch env when there is no
 * default. Terminates only if there is a default and every clause does.
 */
export function walkSwitch(env: TaintEnv, clauses: readonly SwitchClause[]): boolean {
  const arms: Arm[] = [];
  let hasDefault = false;
  for (const cl of clauses) {
    const cenv = cloneEnv(env);
    cl.pre?.(cenv);
    if (cl.isDefault) hasDefault = true;
    arms.push({ env: cenv, terminated: cl.body(cenv) });
  }
  if (!hasDefault) arms.push({ env: cloneEnv(env), terminated: false });
  const joined = joinArms(arms);
  assignEnv(env, joined.env);
  return joined.terminated;
}
