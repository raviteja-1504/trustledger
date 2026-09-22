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
