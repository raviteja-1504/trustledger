/**
 * @jest-environment node
 *
 * False positives found by scanning the Angular repository (243 findings, about 1 real): each shape that was wrongly
 * reported, with the neighbouring real vulnerability that must still be reported.
 */
import { analyzeFile } from "@/lib/scanner";

const ids = (path: string, code: string) => analyzeFile(path, code).indicators.map(i => i.id);

describe("regex.exec(...) is not command execution", () => {
  const body = (decl: string, call: string) => `export function f(req) {\n  const search = req.query.q;\n  ${decl}\n  let m;\n  while ((m = ${call}(search))) { use(m); }\n}\n`;

  it("a regex literal, a declared regex and a regex-named variable", () => {
    expect(ids("src/a.ts", body("const re = /a(b)/g;", "re.exec"))).not.toContain("command-injection");
    expect(ids("src/a.ts", body("const attributeRegex = /\\[([^\\]=]+)\\]/g;", "attributeRegex.exec"))).not.toContain("command-injection");
    expect(ids("src/a.ts", body("const matcher = new RegExp('a(b)', 'g');", "matcher.exec"))).not.toContain("command-injection");
    expect(ids("src/a.ts", body("", "/a(b)/g.exec"))).not.toContain("command-injection");
    expect(ids("src/a.ts", body("", "searchPattern.exec"))).not.toContain("command-injection");
  });

  it("child_process.exec with input is still command injection, however the module is named", () => {
    expect(ids("src/a.ts", `import { exec } from 'child_process';\nexport function f(req) {\n  exec('ls ' + req.query.dir);\n}\n`)).toContain("command-injection");
    expect(ids("src/a.ts", `import cp from 'child_process';\nexport function f(req) {\n  cp.exec('ls ' + req.query.dir);\n}\n`)).toContain("command-injection");
    expect(ids("src/a.ts", `const shell = require('child_process');\nexport function f(req) {\n  shell.exec(req.query.cmd);\n}\n`)).toContain("command-injection");
  });
});

describe("innerHTML = a constant string is not XSS", () => {
  it("clearing and fixed markup are not; input and concatenation still are", () => {
    expect(ids("src/a.ts", `function f(el) {\n  el.innerHTML = '';\n}\n`)).not.toContain("xss");
    expect(ids("src/a.ts", `function f(doc) {\n  doc.body.innerHTML = '<app-root></app-root>';\n}\n`)).not.toContain("xss");
    expect(ids("src/a.ts", "function f(el) {\n  el.innerHTML = `<p>fixed</p>`;\n}\n")).not.toContain("xss");
    expect(ids("src/a.ts", `function f(el, userHtml) {\n  el.innerHTML = userHtml;\n}\n`)).toContain("xss");
    expect(ids("src/a.ts", `function f(el, name) {\n  el.innerHTML = '<b>' + name + '</b>';\n}\n`)).toContain("xss");
    expect(ids("src/a.ts", "function f(el, x) {\n  el.innerHTML += `<i>${x}</i>`;\n}\n")).toContain("xss");
  });
});

describe("a ternary branch and a fetch credentials mode are not hardcoded secrets", () => {
  it("`x === 'use-credentials' ? 'use-credentials' : 'anonymous'`; a real password is still found", () => {
    expect(ids("src/cors.ts", `export const mode = (v: string) => v.toLowerCase() === 'use-credentials' ? 'use-credentials' : 'anonymous';\n`)).not.toContain("hardcoded-secret");
    expect(ids("src/cors.ts", `fetch(u, { credentials: 'same-origin' });\nconst opts = { credentials: 'include' };\n`)).not.toContain("hardcoded-secret");
    expect(ids("src/db.ts", `export const cfg = { password: 'Sup3rS3cretPw99!' };\n`)).toContain("hardcoded-secret");
  });
});

describe("path traversal: a validated path and constant '..' segments are not", () => {
  it("path.resolve(base, req.url) checked with startsWith is guarded; without the check it is not", () => {
    const guarded = `const path = require('path');\nconst fs = require('fs');\nconst localFolder = __dirname;\nfunction handler(req, res) {\n  const file = path.resolve(localFolder, req.url);\n  if (!file.startsWith(localFolder + '/')) {\n    res.end('404');\n    return;\n  }\n  fs.readFile(file, (e, c) => res.end(c));\n}\n`;
    expect(ids("src/server.js", guarded)).not.toContain("path-traversal");
    const unguarded = `const path = require('path');\nconst fs = require('fs');\nfunction handler(req, res) {\n  const file = path.resolve(__dirname, req.url);\n  fs.readFile(file, (e, c) => res.end(c));\n}\n`;
    expect(ids("src/server.js", unguarded)).toContain("path-traversal");
  });

  it("path.join(dir, '..', 'a', 'b.js') is an ordinary relative path; a '..' with a variable name still is flagged", () => {
    expect(ids("src/loader.ts", `import path from 'path';\nexport const p = path.join(options.dir, '..', 'ng-analyze-wasm', 'ng_analyze.js');\n`)).not.toContain("path-traversal");
    expect(ids("src/loader.ts", `import path from 'path';\nexport const p = (base: string, name: string) => path.join(base, '..', name);\n`)).toContain("path-traversal");
  });
});
