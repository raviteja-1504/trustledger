/**
 * @jest-environment node
 *
 * Every tree-sitter grammar a scanner engine loads at runtime must be listed in next.config.mjs
 * outputFileTracingIncludes, or it isn't deployed and that language's AST scanning silently turns off in
 * production (it happened to C#: ENOENT for tree-sitter-c_sharp.wasm on every cold start).
 */
import fs from "fs";
import path from "path";

const ROOT = path.join(__dirname, "..", "..", "..");

it("ships every .wasm grammar the engines load", () => {
  const libDir = path.join(ROOT, "src", "lib");
  const loaded = new Set<string>();
  for (const f of fs.readdirSync(libDir).filter(f => /^astTaint.*\.ts$/.test(f))) {
    for (const m of fs.readFileSync(path.join(libDir, f), "utf8").matchAll(/"(tree-sitter-[a-z_]+\.wasm)"/g)) loaded.add(m[1]);
  }
  expect(loaded.size).toBeGreaterThanOrEqual(5);   // python, go, c_sharp, php, ruby

  const config = fs.readFileSync(path.join(ROOT, "next.config.mjs"), "utf8");
  const shipped = new Set([...config.matchAll(/tree-sitter-wasms\/out\/(tree-sitter-[a-z_]+\.wasm)/g)].map(m => m[1]));
  expect([...loaded].filter(w => !shipped.has(w))).toEqual([]);
  // the runtime binary every grammar needs
  expect(config).toContain("./node_modules/web-tree-sitter/tree-sitter.wasm");
});
