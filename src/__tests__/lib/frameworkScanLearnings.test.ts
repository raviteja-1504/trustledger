/**
 * @jest-environment node
 *
 * False positives found by scanning Django, Next.js and axios, each paired with the real case it must NOT stop catching.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

jest.setTimeout(120_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

const idsOf = (path: string, content: string) =>
  runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] })
    .files[0].indicators.filter(i => i.line != null).map(i => i.id);

describe("a method called eval is not the global eval", () => {
  it("does not flag condition.eval(context), model.eval() or def eval(self, ...)", () => {
    const py = `class Op:\n    def eval(self, context):\n        return self.first.eval(context)\n\ndef run(model, condition, context):\n    model.eval()\n    return condition.eval(context)\n`;
    expect(idsOf("t/op.py", py)).not.toContain("eval-exec");
  });
  it("still flags eval(x) and window.eval(x)", () => {
    expect(idsOf("t/a.py", `def f(request):\n    return eval(request.args.get("x"))\n`)).toContain("eval-exec");
    expect(idsOf("t/b.js", `function f(x) {\n  return window.eval(x)\n}\n`)).toContain("eval-exec");
    expect(idsOf("t/c.js", `function f(x) {\n  return eval(x)\n}\n`)).toContain("eval-exec");
  });
});

describe("path traversal needs a request value, not a file name containing one", () => {
  it("does not flag path.join(dir, 'types', 'root-params.d.ts')", () => {
    expect(idsOf("t/p.ts", `import path from 'path'\nexport const f = (distDir: string) => path.join(distDir, 'types', 'root-params.d.ts')\n`)).not.toContain("path-traversal");
  });
  it("still flags path.join(base, req.params.name) and path.join(base, req.query.f)", () => {
    expect(idsOf("t/q.js", `const path = require('path')\napp.get('/f', (req, res) => res.sendFile(path.join(base, req.params.name)))\n`)).toContain("path-traversal");
    expect(idsOf("t/r.js", `const path = require('path')\napp.get('/f', (req, res) => res.sendFile(path.join(base, req.query.f)))\n`)).toContain("path-traversal");
  });
});

describe("secrets", () => {
  it("does not flag a session-key name or a class-name format string", () => {
    expect(idsOf("t/v.py", `INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"\n`)).not.toContain("hardcoded-secret");
    expect(idsOf("t/w.py", `name = "%s.%s.RelatedObjectDoesNotExist" % (a, b)\n`)).not.toContain("hardcoded-secret");
  });
  it("still flags a Vault token and a real password", () => {
    expect(idsOf("t/x.py", `TOKEN = "s.Ab3dEfGh1jKlMnOpQrStUvWx9"\n`)).toContain("hardcoded-secret");
    expect(idsOf("t/x2.py", `TOKEN = "s.AbCdEfGhIjKlMnOpQrStUvWx"\n`)).toContain("hardcoded-secret");   // no digits, still token-shaped
    expect(idsOf("t/y.py", `password ="Xk9$mPq2vL8nR4tZ"\n`)).toContain("hardcoded-secret");
  });
});

describe("a shell command given as a constant on the next line", () => {
  it("does not flag execSync(\n  'npm run build'\n)", () => {
    expect(idsOf("t/e.ts", `import child_process from 'child_process'\nexport const out = child_process\n  .execSync(\n    'wmic process get executablepath'\n  )\n  .toString()\n`)).not.toContain("command-injection");
  });
  it("still flags a variable or an interpolated command on the next line", () => {
    expect(idsOf("t/f.ts", `import child_process from 'child_process'\nexport const run = (cmd: string) => child_process\n  .execSync(\n    cmd\n  )\n`)).toContain("command-injection");
    expect(idsOf("t/g.ts", `import child_process from 'child_process'\nexport const run = (name: string) => child_process\n  .execSync(\n    \`ls \${name}\`\n  )\n`)).toContain("command-injection");
  });
});
