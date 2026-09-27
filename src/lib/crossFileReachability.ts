// ── Multi-hop cross-file reachability ────────────────────────────────────────
//
// Question: which functions are reachable at runtime because of code in OTHER files? It feeds
// `reachability` on every finding (scoreExploitability): a sink in a helper that no entry point can reach
// is scored "unreachable" (x0.30), one a request handler can reach is "reachable" -- a large swing on the
// same finding, so an under-approximation here silently downgrades real vulnerabilities.
//
// The previous bridge was ONE hop and had three concrete blind spots:
//   1. It asked "is the CALLER reachable?" using the caller file's OWN entry points only. So
//      route -> a.foo -> b.bar stopped at foo: foo is reachable only because route calls it, which the
//      per-file view of `a` cannot know, so b.bar was never marked. Every chain of length >= 2 was lost
//      whenever the middle function isn't itself detected as an entry point (an `export { foo }` list, a
//      `module.exports = {...}`, a default-exported identifier -- callGraph.ts's regex only sees an inline
//      `export function`).
//   2. Re-export chains (`export { x } from "./a"`, `export * from "./a"`) were not followed: a caller
//      importing through a barrel marked the barrel's name, which has no function body, and never the real
//      declaration one file further.
//   3. A function reached from another file did not make ITS OWN local callees reachable. `foo` marked
//      reachable, but the `helper()` foo calls (where the sink is) stayed "unreachable".
//
// This is a worklist over (file, name) nodes instead of a single pass, so all three fall out of one rule:
// once a name in a file is known reachable, follow its outgoing calls -- to local functions (same file) and
// through import bindings (to another file), and through re-exports when a name is looked up in a barrel.
// Every (file, name) is visited at most once, so it terminates on any graph including cycles, with no round
// cap needed (the state space is finite and only ever grows).
//
// Pure and language-agnostic on purpose: scanner.ts builds the per-file inputs (JS/TS today), this owns the
// graph algorithm, so it can be unit-tested on synthetic graphs.

export interface ReachImport {
  /** The name call sites in the importing file use. */
  localName: string;
  /** The name as exported by the source file. Ignored when `namespace`. */
  importedName: string;
  /** `import * as ns` / `const ns = require(...)`: a call `ns.f()` is recorded by its tail name `f`. */
  namespace?: boolean;
  /** Batch path the specifier resolved to; null for an external package / unresolvable specifier. */
  resolvedPath: string | null;
}

export interface ReachReexport {
  /** null = `export * from` (every name passes through unchanged). */
  publicName: string | null;
  /** Name in the source module (null for `export *`). */
  importedName: string | null;
  resolvedPath: string | null;
}

export interface ReachFile {
  path: string;
  /** Call edges as callGraph.ts records them: caller function name -> callee's TAIL name (`a.b.f()` -> `f`). */
  edges: ReadonlyArray<{ caller: string; callee: string }>;
  /** Names reachable inside this file from its OWN entry points (the file's call-graph BFS result). */
  reachable: ReadonlySet<string>;
  imports: readonly ReachImport[];
  reexports: readonly ReachReexport[];
}

/**
 * For each file, the names in it that are reachable because of OTHER files -- including the local
 * functions those names call (blind spot 3), which callGraph.ts's per-file BFS could not know about.
 * Names already reachable from the file's own entry points are not repeated. Only files with a non-empty
 * result appear.
 */
export function computeCrossFileReachable(files: readonly ReachFile[]): Map<string, Set<string>> {
  const byPath = new Map(files.map(f => [f.path, f]));

  // Per-file lookup tables, built once.
  const adjacency = new Map<string, Map<string, Set<string>>>();
  const importsByLocal = new Map<string, Map<string, ReachImport[]>>();
  const namespaceImports = new Map<string, ReachImport[]>();
  for (const f of files) {
    const adj = new Map<string, Set<string>>();
    for (const e of f.edges) {
      const s = adj.get(e.caller) ?? new Set<string>();
      s.add(e.callee);
      adj.set(e.caller, s);
    }
    adjacency.set(f.path, adj);
    const byLocal = new Map<string, ReachImport[]>();
    for (const imp of f.imports) {
      const list = byLocal.get(imp.localName) ?? [];
      list.push(imp);
      byLocal.set(imp.localName, list);
    }
    importsByLocal.set(f.path, byLocal);
    namespaceImports.set(f.path, f.imports.filter(i => i.namespace));
  }

  const result = new Map<string, Set<string>>();
  const visited = new Set<string>();           // `${path}\0${name}` -- the (file, name) nodes already explored
  const stack: Array<[string, string]> = [];

  const mark = (path: string, name: string, ownReachable: boolean) => {
    const file = byPath.get(path);
    if (!file) return;
    // A name reachable from the file's own entry points is already known to callGraph.ts; only what is
    // NEW (reachable solely thanks to another file) is reported, but it is still explored below -- its
    // outgoing cross-file calls are exactly the hops the old one-pass bridge never followed.
    if (!ownReachable && !file.reachable.has(name)) {
      const set = result.get(path) ?? new Set<string>();
      set.add(name);
      result.set(path, set);
    }
    const key = `${path}\0${name}`;
    if (visited.has(key)) return;
    visited.add(key);
    stack.push([path, name]);
    // A name looked up in a barrel: the real declaration is in the module it re-exports from. (Blind spot 2.)
    for (const re of file.reexports) {
      if (!re.resolvedPath) continue;
      if (re.publicName === null) mark(re.resolvedPath, name, false);
      else if (re.publicName === name) mark(re.resolvedPath, re.importedName ?? name, false);
    }
  };

  // Seed: every name reachable from a file's own entry points is a place calls to other files can start.
  for (const f of files) for (const name of f.reachable) mark(f.path, name, true);

  while (stack.length > 0) {
    const [path, name] = stack.pop()!;
    const file = byPath.get(path)!;
    const callees = adjacency.get(path)!.get(name);
    if (!callees) continue;
    for (const callee of callees) {
      const imports = importsByLocal.get(path)!.get(callee);
      if (imports) {
        // A call through an import binding: hop into the file it came from. (Blind spot 1.)
        for (const imp of imports) if (imp.resolvedPath) mark(imp.resolvedPath, imp.namespace ? callee : imp.importedName, false);
      } else {
        // Local callee: reachable in this file too, so the helper that holds the sink counts. (Blind spot 3.)
        mark(path, callee, file.reachable.has(callee));
      }
      // `ns.f()` is recorded as bare `f`, which no import binding is named: try every namespace import.
      if (!imports) for (const imp of namespaceImports.get(path)!) if (imp.resolvedPath) mark(imp.resolvedPath, callee, false);
    }
  }
  return result;
}
