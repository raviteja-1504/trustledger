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
