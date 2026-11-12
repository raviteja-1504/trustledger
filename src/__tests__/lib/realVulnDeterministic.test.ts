/**
 * @jest-environment node
 *
 * Deterministic gaps found by RealVuln (labelled vulnerabilities a conventional SAST tool caught and we missed):
 *  - jinja2/Mako/Django/Tornado Template(source) with request input is server-side template injection (37 labelled cases)
 *  - running a shell command is command injection (CWE-78), not code injection; spawn(..., {shell:true}) and a bare exec() count (38 cases)
 *  - a string built from the `random` module is a predictable token (34 cases)
 */
import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);
const ids = (path: string, src: string) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content: src }] }).files[0].indicators.filter(i => i.id !== "ai-model-attribution").map(i => i.id);

describe("server-side template injection through Template(source)", () => {
  const django = (imp: string, call: string) => `from django.http import HttpResponse\n${imp}\n\ndef view(request):\n    fragment = request.GET.get("fragment", "x")\n    body = ${call}.render()\n    return HttpResponse(body)\n`;

  it("jinja2.Template, Mako and Django templates compiled from request input", () => {
    expect(ids("v.py", django("from jinja2 import Template", `Template("Result: " + fragment)`))).toContain("ssti");
    expect(ids("v.py", django("import jinja2", `jinja2.Template(fragment)`))).toContain("ssti");
    expect(ids("v.py", django("from mako.template import Template", `Template(fragment)`))).toContain("ssti");
    expect(ids("v.py", django("from django.template import Template", `Template(fragment)`))).toContain("ssti");
  });

  it("also when imported inside the function, and for a FastAPI query parameter", () => {
    expect(ids("v.py", `from django.http import HttpResponse\n\ndef view(request):\n    from jinja2 import Template\n    fragment = request.GET.get("fragment")\n    return HttpResponse(Template("x" + fragment).render())\n`)).toContain("ssti");
    expect(ids("r.py", `from fastapi import APIRouter\nfrom fastapi.responses import HTMLResponse\nrouter = APIRouter()\n\n@router.get("/j")\nasync def j(fragment: str = "x"):\n    from jinja2 import Template\n    return HTMLResponse(Template("Result: " + fragment).render())\n`)).toContain("ssti");
  });

  it("not a constant template, a context value, or string.Template", () => {
    expect(ids("v.py", django("from jinja2 import Template", `Template("Result: {{ name }}")`))).not.toContain("ssti");
    expect(ids("v.py", `from django.http import HttpResponse\nfrom jinja2 import Template\n\ndef view(request):\n    name = request.GET.get("n")\n    return HttpResponse(Template("Hello {{ name }}").render(name=name))\n`)).not.toContain("ssti");
    expect(ids("v.py", `from django.http import HttpResponse\nfrom string import Template\n\ndef view(request):\n    name = request.GET.get("n")\n    return HttpResponse(Template("Hello $name").substitute(name=name))\n`)).not.toContain("ssti");
  });
});

describe("running a shell command is command injection", () => {
  it("os.system / subprocess shell=True / execSync / child_process.exec with a built command: command-injection (CWE-78), not eval-exec", () => {
    for (const [path, src] of [
      ["a.py", `import os\n\ndef f(name):\n    os.system("convert " + name)\n`],
      ["b.py", `import subprocess\n\ndef f(name):\n    subprocess.call(f"convert {name}", shell=True)\n`],
      ["c.js", "const { execSync } = require(\"child_process\");\nfunction f(name) {\n  execSync(`pandoc ${name} -o out.pdf`);\n}\n"],
      ["d.js", "const cp = require(\"child_process\");\nfunction f(name) {\n  cp.exec(`ls ${name}`);\n}\n"],
    ] as const) {
      const found = ids(path, src);
      expect({ path, found: found.includes("command-injection") }).toEqual({ path, found: true });
      expect(found).not.toContain("eval-exec");
    }
  });

  it("spawn / execFile with `shell: true`, and a bare exec() imported from child_process", () => {
    expect(ids("s.js", "const { spawn } = require(\"child_process\");\nfunction f(cmd) {\n  const child = spawn(cmd, { shell: true });\n}\n")).toContain("command-injection");
    expect(ids("s2.js", "const { exec } = require(\"child_process\");\nfunction f(dir) {\n  exec(`ls ${dir}`, (e, out) => out);\n}\n")).toContain("command-injection");
    expect(ids("s3.js", "const { exec } = require(\"child_process\");\nfunction f(command) {\n  exec(command, (e, out) => out);\n}\n")).toContain("command-injection");
  });

  it("not a spawn without a shell, a regex .exec(), an exec() in a file that does not use child_process, or a constant command", () => {
    expect(ids("n1.js", "const { spawn } = require(\"child_process\");\nfunction f(a) {\n  spawn(\"ls\", [a]);\n}\n")).not.toContain("command-injection");
    expect(ids("n2.js", "function f(s) {\n  return /a(b)/.exec(s);\n}\n")).not.toContain("command-injection");
    expect(ids("n3.js", "function f(db, q) {\n  return exec(q);\n}\n")).not.toContain("command-injection");
    expect(ids("n4.js", "const { exec } = require(\"child_process\");\nexec(\"npm run build\");\n")).not.toContain("command-injection");
    expect(ids("n5.js", "const { spawn } = require(\"child_process\");\nspawn(\"make all\", { shell: true });\n")).not.toContain("command-injection");
  });

  it("eval and new Function stay code injection", () => {
    expect(ids("e.js", "function f(code) {\n  eval(code);\n}\n")).toContain("eval-exec");
    expect(ids("e2.js", "function f(code) {\n  return new Function(\"a\", code);\n}\n")).toContain("eval-exec");
  });
});

describe("a token built from the random module", () => {
  it("random.choice joined into a string, and random.choices over an alphabet", () => {
    expect(ids("t.py", `import random\n\ndef nonce(length=24):\n    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"\n    return "".join(random.choice(alphabet) for _ in range(length))\n`)).toContain("insecure-randomness");
    expect(ids("t2.py", `import random, string\n\ndef make():\n    return "".join(random.choices(string.ascii_letters + string.digits, k=32))\n`)).toContain("insecure-randomness");
    expect(ids("t3.py", `from random import choice\nimport random\n\ndef pw():\n    chars = "abc123"\n    return "".join(random.choice(chars) for _ in range(12))\n`)).toContain("insecure-randomness");
  });

  it("not secrets, SystemRandom, a pick from a list of words, or a file without `import random`", () => {
    expect(ids("u.py", `import secrets\n\ndef nonce():\n    alphabet = "abcdefghijklmnopqrstuvwxyz"\n    return "".join(secrets.choice(alphabet) for _ in range(24))\n`)).not.toContain("insecure-randomness");
    expect(ids("u2.py", `import random\n\ndef nonce():\n    rng = random.SystemRandom()\n    return "".join(random.SystemRandom().choice("abcdefghijkl") for _ in range(24))\n`)).not.toContain("insecure-randomness");
    expect(ids("u3.py", `import random\n\ndef greeting():\n    return random.choice(["hello", "hi", "hey"])\n`)).not.toContain("insecure-randomness");
    expect(ids("u4.py", `def f(random):\n    return "".join(random.choice(alphabet) for _ in range(3))\n`)).not.toContain("insecure-randomness");
  });
});
