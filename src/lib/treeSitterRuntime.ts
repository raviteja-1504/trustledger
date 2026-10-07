/**
 * Shared web-tree-sitter runtime bootstrap. Parser.init() instantiates a
 * SINGLE emscripten WASM runtime shared by every tree-sitter grammar in
 * this codebase (Python's astTaintPython.ts, Go's astTaintGo.ts, and any
 * future language engine) -- it is not a per-grammar initialization.
 *
 * Every language engine used to call Parser.init() itself, independently,
 * at its own module-load time. That's a real, reproduced race: calling
 * Parser.init() concurrently from two separate, un-awaited callers
 * corrupts whichever grammar's Language.load() resolves second -- it
 * "loads" without throwing, but reports language version 0 ("Incompatible
 * language version 0. Compatibility range 13 through 15"), a
 * nondeterministic ~50% failure depending on promise resolution order, not
 * a real ABI mismatch. Confirmed directly: five repeated runs of two
 * independent, unawaited Parser.init()-then-Language.load() sequences
 * failed one side or the other every single time until both were changed
 * to await this single shared, memoized promise instead.
 *
 * Every language-specific engine module must await ensureTreeSitterInit()
 * before its own Language.load() call, and must never call Parser.init()
 * itself.
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Parser } = require("web-tree-sitter") as typeof import("web-tree-sitter");

// The memo lives on globalThis, not in this module: Next.js compiles instrumentation.ts (which warms every engine
// at cold start) and the route handlers as SEPARATE bundles, each with its own copy of this module, while
// web-tree-sitter itself is one external package shared by the whole process. A module-level memo therefore let
// each bundle call Parser.init() on the same runtime -- the exact concurrent-init race described above. It showed
// up only in production (one module graph locally and under Jest): C#, the largest grammar and the last to
// finish loading, failed every cold start with "Incompatible language version 0".
const shared = globalThis as typeof globalThis & { __trustledgerTreeSitterInit?: Promise<void> };

/**
 * Deepest syntax-tree nesting the taint engines analyse. Their visitors recurse once (or more) per node, so a
 * repository file nested thousands of levels deep (`f(f(f(...)))`, a 20k-term `a + b + ...` chain, nested
 * `if ... end`) overflowed the call stack and failed the WHOLE scan. Real code stays far below this; a deeper
 * file is still scanned by the regex layer, just not by the AST engines.
 */
export const MAX_AST_DEPTH = 1000;

/** True when `root` nests deeper than `limit` -- walked with a cursor, so the check itself never recurses. */
export function treeTooDeep(root: import("web-tree-sitter").Node, limit = MAX_AST_DEPTH): boolean {
  const cursor = root.walk();
  let depth = 0;
  try {
    for (;;) {
      if (cursor.gotoFirstChild()) {
        if (++depth > limit) return true;
        continue;
      }
      while (!cursor.gotoNextSibling()) {
        if (depth === 0 || !cursor.gotoParent()) return false;
        depth--;
      }
    }
  } finally {
    cursor.delete();
  }
}

/** A parsed root, or null (with a log line) when it is too deep for the engines to walk safely. */
export function rootIfShallowEnough<N extends import("web-tree-sitter").Node>(root: N | null | undefined, engine: string, filePath: string): N | null {
  if (!root) return null;
  if (treeTooDeep(root)) {
    console.warn(`[${engine}] ${filePath}: syntax tree nests deeper than ${MAX_AST_DEPTH} levels -- AST analysis skipped (regex rules still run)`);
    return null;
  }
  return root;
}

export function ensureTreeSitterInit(): Promise<void> {
  if (!shared.__trustledgerTreeSitterInit) shared.__trustledgerTreeSitterInit = Parser.init();
  return shared.__trustledgerTreeSitterInit;
}
