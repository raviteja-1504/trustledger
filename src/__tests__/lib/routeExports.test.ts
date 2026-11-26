/**
 * @jest-environment node
 *
 * A Next.js route file may export only its HTTP handlers and route config. Anything else (a helper, a constant) fails
 * `next build` with a type error, which jest and `tsc` cannot see because Next generates those route types at build time:
 * a deploy failed on exactly this once (src/app/api/export/signed/route.ts exported three constants). This test is the
 * local stand-in for that check.
 */
import fs from "fs";
import path from "path";

const ROOT = path.join(__dirname, "../../app");
const ALLOWED = new Set([
  "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
  "dynamic", "dynamicParams", "revalidate", "fetchCache", "runtime", "preferredRegion", "maxDuration", "generateStaticParams",
]);

function routeFiles(dir: string, out: string[] = []): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) routeFiles(p, out);
    else if (/^route\.tsx?$/.test(e.name)) out.push(p);
  }
  return out;
}

/** Runtime names a module exports: `export const x`, `export function f`, `export { a, b as c }`, `export default`. Types are erased and fine. */
export function exportedNames(source: string): string[] {
  const names: string[] = [];
  for (const m of source.matchAll(/^export\s+(?:async\s+)?(?:const|let|var|function\*?|class)\s+([A-Za-z_$][\w$]*)/gm)) names.push(m[1]);
  for (const m of source.matchAll(/^export\s*\{([^}]*)\}/gm)) {
    for (const part of m[1].split(",")) {
      const name = part.trim().split(/\s+as\s+/).pop()!.trim();
      if (name && !/^type\s/.test(part.trim())) names.push(name);
    }
  }
  if (/^export\s+default\b/m.test(source)) names.push("default");
  return names;
}

describe("route files export only what Next.js allows", () => {
  const files = routeFiles(ROOT);

  it("finds the route files", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  it("none exports a helper or constant", () => {
    const bad = files.flatMap(f => exportedNames(fs.readFileSync(f, "utf8")).filter(n => !ALLOWED.has(n)).map(n => `${path.relative(ROOT, f).split(path.sep).join("/")}: ${n}`));
    expect(bad).toEqual([]);
  });

  it("the detector itself sees each way of exporting", () => {
    expect(exportedNames('export const FOO = 1;\nexport async function GET() {}\nexport function helper() {}\nexport { a, b as POST }\nexport default x;\nexport type T = 1;'))
      .toEqual(["FOO", "GET", "helper", "a", "POST", "default"]);
    expect(exportedNames("export type { X } from './y'\nconst z = 1;")).toEqual([]);
  });
});
