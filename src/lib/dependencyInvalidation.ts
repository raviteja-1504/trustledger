/**
 * Dependency-aware delta invalidation.
 *
 * Problem: a delta scan rebuilds only the files that appear in the git diff
 * (`changedPaths`). If file A imports shared helper B, and B changed, A's
 * previously-cached analysis is now stale — but A is not in the diff.
 *
 * This module resolves that by building a reverse import graph from all file
 * contents visible to the current scan, then walking it transitively from every
 * changed path to find which additional files must be invalidated.
 *
 * Supported languages: JavaScript / TypeScript (relative static imports + requires),
 * Python (relative from…import and import statements). Dynamic / computed imports
 * are not tracked — a scan that misses those is never worse than the previous one.
 */

// ── Import parsing ─────────────────────────────────────────────────────────

const JS_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const JS_FAMILY = new Set([...JS_EXTENSIONS, ".vue", ".svelte"]);

function jsFamily(path: string): boolean {
  return JS_FAMILY.has(path.slice(path.lastIndexOf(".")));
}

/** Resolve a bare import specifier relative to the importing file's directory. */
function resolveRelative(importerDir: string, specifier: string, knownPaths: Set<string>): string | null {
  // Strip query strings / fragments that bundlers allow (e.g. `?raw`, `#hash`)
  const clean = specifier.replace(/[?#].*$/, "");
  // Strip a known JS extension so we can try every extension variant
  const base = joinPath(importerDir, clean.replace(/\.[cm]?[jt]sx?$/, ""));
  for (const ext of JS_EXTENSIONS) {
    const candidate = base + ext;
    if (knownPaths.has(candidate)) return candidate;
    // index file: `./utils` → `./utils/index.ts`
    const idx = base + "/index" + ext;
    if (knownPaths.has(idx)) return idx;
  }
  return null;
}

function joinPath(dir: string, rel: string): string {
  const parts = dir ? dir.split("/") : [];
  for (const seg of rel.replace(/\\/g, "/").split("/")) {
    if (seg === "..") parts.pop();
    else if (seg && seg !== ".") parts.push(seg);
  }
  return parts.join("/");
}

/** Returns the set of paths in `knownPaths` that this file's content imports. */
function parsedImports(path: string, content: string, knownPaths: Set<string>): Set<string> {
  const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
  const out = new Set<string>();

  if (jsFamily(path)) {
    // Static imports: `from "./x"`, `import "./x"`, `require("./x")`, `import("./x")`
    const re = /(?:from\s+|require\(\s*|import\(\s*|import\s+)["'](\.{1,2}\/[^"']*?)["']/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content))) {
      const resolved = resolveRelative(dir, m[1], knownPaths);
      if (resolved) out.add(resolved);
    }
  } else if (path.endsWith(".py")) {
    // Relative imports: `from . import x`, `from .. import y`, `from .utils import z`
    const re = /^[ \t]*from\s+(\.+)([\w.]*)?\s+import/gm;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content))) {
      const dots = m[1].length; // number of dots = levels up
      const mod  = (m[2] ?? "").replace(/\./g, "/");
      let base = dir;
      for (let i = 1; i < dots; i++) base = base.includes("/") ? base.slice(0, base.lastIndexOf("/")) : "";
      const stem = mod ? joinPath(base, mod) : base;
      for (const cand of [`${stem}.py`, `${stem}/__init__.py`]) {
        if (knownPaths.has(cand)) { out.add(cand); break; }
      }
    }
  }

  return out;
}

// ── Reverse graph ──────────────────────────────────────────────────────────

/**
 * Builds a reverse import graph: for each file, the set of files that import it.
 *
 * @param allFiles  All files visible to the current scan: a Map from path to content.
 *                  Content may be null/undefined if the file was inherited (content not stored).
 */
function buildReverseGraph(allFiles: Map<string, string | null | undefined>): Map<string, Set<string>> {
  const knownPaths = new Set(allFiles.keys());
  const reverse = new Map<string, Set<string>>();

  for (const [path, content] of allFiles) {
    if (!content) continue;
    for (const imported of parsedImports(path, content, knownPaths)) {
      let importers = reverse.get(imported);
      if (!importers) { importers = new Set(); reverse.set(imported, importers); }
      importers.add(path);
    }
  }

  return reverse;
}

// ── Transitive closure ─────────────────────────────────────────────────────

/**
 * Returns the set of paths that need rescanning: `changedPaths` plus every path
 * that transitively imports a changed path (i.e. whose cached analysis is now stale).
 *
 * @param changedPaths  Paths that appear in the git diff (always rescanned).
 * @param allFiles      All files visible to this scan (path → content, content may be null).
 * @returns             Superset of `changedPaths`; guaranteed not to be empty when changedPaths isn't.
 */
export function expandWithDependents(
  changedPaths: Set<string>,
  allFiles: Map<string, string | null | undefined>,
): Set<string> {
  if (changedPaths.size === 0) return changedPaths;

  const reverse = buildReverseGraph(allFiles);
  const result  = new Set(changedPaths);
  const queue   = [...changedPaths];

  while (queue.length > 0) {
    const changed = queue.shift()!;
    for (const importer of reverse.get(changed) ?? []) {
      if (!result.has(importer)) {
        result.add(importer);
        queue.push(importer);
      }
    }
  }

  return result;
}
