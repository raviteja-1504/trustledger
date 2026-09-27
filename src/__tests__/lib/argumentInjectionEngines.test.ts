import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPythonTaintEngine(); }, 30000);

// Argument injection (CWE-88): a tainted argv element passed straight through, with no shell in between --
// shell-quoting is irrelevant here; only a `--` separator or a literal prefix rules out a leading '-'.

const scan = (path: string, content: string) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] });
const argInj = (content: string) =>
  scan("src/route.ts", content).files[0].indicators.filter(i => i.id === "argument-injection");
const route = (body: string) => `import { spawn, execFile } from "child_process";\napp.get("/x", async (req, res) => {\n  const name = req.query.name;\n  ${body}\n});`;

describe("JS/TS argument injection: bare tainted argv element", () => {
  it("spawn(cmd, [tainted]) is flagged", () => {
    const f = argInj(route(`spawn("rsync", ["-a", name, "/dest"]);`));
    expect(f).toHaveLength(1);
    expect(f[0].sourceExpr).toBe("name");
    expect(f[0].severity).toBe("high");
    expect(f[0].detail).toMatch(/argv element/);
  });
  it("execFile(cmd, [tainted]) is flagged", () => {
    expect(argInj(route(`execFile("tar", ["-c", name]);`))).toHaveLength(1);
  });
  it("a recognized encoder does NOT protect it -- it neutralizes URL/path characters, not a leading dash", () => {
    expect(argInj(route(`spawn("rsync", ["-a", encodeURIComponent(name), "/dest"]);`))).toHaveLength(1);
  });
});

describe("JS/TS argument injection: a literal '--' element protects everything after it", () => {
  it("no finding once past the separator", () => {
    expect(argInj(route(`spawn("rsync", ["-a", "--", name, "/dest"]);`))).toHaveLength(0);
  });
  it("an element BEFORE the separator is still checked", () => {
    expect(argInj(route(`spawn("rsync", [name, "--", "/dest"]);`))).toHaveLength(1);
  });
});

describe("JS/TS argument injection: a non-empty literal prefix rules out a leading dash", () => {
  it("the common './' + value defence", () => {
    expect(argInj(route(`spawn("tar", ["-c", "./" + name]);`))).toHaveLength(0);
  });
  it("a literal flag=value prefix", () => {
    expect(argInj(route(`spawn("tar", ["--file=" + name]);`))).toHaveLength(0);
  });
  it("an untainted opaque prefix (unknown, possibly empty) does NOT count", () => {
    expect(argInj(route(`spawn("tar", [prefix + name]);`))).toHaveLength(1);
  });
});

describe("JS/TS argument injection: CONTROL is deliberately sticky, matching BOLA/IDOR's own treatment", () => {
  it("an allowlist guard narrows the value but does not clear CONTROL, so it is still reported -- the same known, accepted tradeoff BOLA already makes (CONTROL tracks PROVENANCE, not current safety; see taintCore.ts)", () => {
    expect(argInj(route(`if (!ALLOWED.includes(name)) return;\n  spawn("rsync", ["-a", name, "/dest"]);`))).toHaveLength(1);
  });
});

describe("JS/TS argument injection: not the same check as command-injection", () => {
  it("exec (shell string, not an argv array) is untouched by this check", () => {
    // exec()'s single string argument goes through the SHELL, so shell-quoting genuinely helps there --
    // that is command-injection's job (checked elsewhere), not argument-injection's.
    expect(argInj(route(`exec("rsync -a " + name + " /dest");`))).toHaveLength(0);
  });
  it("a non-array second argument (options object) is not mistaken for an argv list, and does not disrupt scanning a later, real finding in the same file", () => {
    const f = argInj(route(`spawn("rsync", { shell: name });\n  spawn("tar", ["-c", name]);`));
    expect(f).toHaveLength(1);
    expect(f[0].sinkExpr).toBe("spawn");
  });
});

// ── Python ──
const pyScan = (content: string) =>
  scan("app/views.py", content).files[0].indicators.filter(i => i.id === "argument-injection");
const pyRoute = (body: string) =>
  `import subprocess\nfrom flask import request\n\n@app.route("/x")\ndef view():\n    name = request.args.get("name")\n    ${body}\n`;

describe("Python argument injection: module scoping and the executable element", () => {
  it("an unrelated object's .run(list)/.call(list) method is not mistaken for subprocess.run/call -- the NAME alone is not enough", () => {
    expect(pyScan(pyRoute('task_queue.run(["-a", name])'))).toHaveLength(0);
    expect(pyScan(pyRoute('mock.call(["-a", name])'))).toHaveLength(0);
  });
  it("the executable itself (element 0) is not checked by THIS rule -- a tainted program name is command-injection's own concern", () => {
    expect(pyScan(pyRoute('subprocess.run([name, "-a", "safe"])'))).toHaveLength(0);
  });
});

describe("Python argument injection: bare tainted argv element", () => {
  it("subprocess.run([cmd, tainted]) is flagged", () => {
    const f = pyScan(pyRoute('subprocess.run(["rsync", "-a", name, "/dest"])'));
    expect(f).toHaveLength(1);
    expect(f[0].sourceExpr).toBe("name");
  });
  it("subprocess.Popen is flagged the same way", () => {
    expect(pyScan(pyRoute('subprocess.Popen(["tar", "-c", name])'))).toHaveLength(1);
  });
  it("shell=True with a list changes the semantics -- not this check's target shape", () => {
    expect(pyScan(pyRoute('subprocess.run(["rsync", "-a", name], shell=True)'))).toHaveLength(0);
  });
});

describe("Python argument injection: a literal '--' element protects everything after it", () => {
  it("no finding once past the separator", () => {
    expect(pyScan(pyRoute('subprocess.run(["rsync", "-a", "--", name, "/dest"])'))).toHaveLength(0);
  });
});

describe("Python argument injection: a non-empty literal prefix rules out a leading dash", () => {
  it("f-string prefix protects it", () => {
    expect(pyScan(pyRoute('subprocess.run(["tar", "-c", f"./{name}"])'))).toHaveLength(0);
  });
  it("concatenation prefix protects it", () => {
    expect(pyScan(pyRoute('subprocess.run(["tar", "--file=" + name])'))).toHaveLength(0);
  });
});

describe("Python argument injection: a shell-quoted value is still flagged (shlex.quote doesn't help here)", () => {
  it("shlex.quote applied to the value does not protect it", () => {
    const f = pyScan(pyRoute('subprocess.run(["rsync", "-a", shlex.quote(name), "/dest"])'));
    expect(f).toHaveLength(1);
  });
});

// ── parity: the summary walk (a wrapper in another file) must agree with the main scan ──
type Multi = { path: string; content: string }[];
const scanMulti = (files: Multi) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const countArgInj = (r: ReturnType<typeof scanMulti>, path: string) =>
  r.files.find(f => f.file_path === path)!.indicators.filter(i => i.id === "argument-injection" && i.confidence === 95).length;

describe("parity JS/TS: a wrapper in another file gets the same verdict as the same code in one file", () => {
  it("flags the same shape whether the spawn call is same-file or cross-file", () => {
    const def = `export function wrap(p) {\n  spawn("rsync", ["-a", p, "/dest"]);\n}`;
    const call = `app.get("/x", (req, res) => {\n  wrap(req.query.v);\n});`;
    const same = scanMulti([{ path: "src/one.ts", content: `import { spawn } from "child_process";\n${def}\n${call}` }]);
    const cross = scanMulti([
      { path: "src/lib.ts", content: `import { spawn } from "child_process";\n${def}` },
      { path: "src/route.ts", content: `import { wrap } from "./lib";\n${call}` },
    ]);
    expect(countArgInj(same, "src/one.ts")).toBe(1);
    expect(countArgInj(cross, "src/route.ts")).toBe(1);
  });
});

describe("parity Python: a wrapper in another file gets the same verdict as the same code in one file", () => {
  it("flags the same shape whether the subprocess call is same-file or cross-file", () => {
    const def = "import subprocess\n\ndef wrap(p):\n    subprocess.run([\"rsync\", \"-a\", p, \"/dest\"])\n";
    const call = "@app.route(\"/x\")\ndef view():\n    wrap(request.args.get(\"v\"))\n";
    const same = scanMulti([{ path: "app/one.py", content: `${def}\nfrom flask import request\n${call}` }]);
    const cross = scanMulti([
      { path: "app/lib.py", content: def },
      { path: "app/views.py", content: `from flask import request\nfrom app.lib import wrap\n\n${call}` },
    ]);
    expect(countArgInj(same, "app/one.py")).toBe(1);
    expect(countArgInj(cross, "app/views.py")).toBe(1);
  });
});
