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

let initPromise: Promise<void> | null = null;

export function ensureTreeSitterInit(): Promise<void> {
  if (!initPromise) initPromise = Parser.init();
  return initPromise;
}
