/**
 * @jest-environment node
 *
 * What scanning semgrep's own CLI (cli/src, 182 Python and TypeScript files) taught us. Of the 14 security findings, 12 were not
 * vulnerabilities; these are the shapes behind them, each kept next to the real thing it must not hide.
 */
import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);

const scan = (path: string, content: string) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "abc123", branch: "main", files: [{ path, content }] }).files[0].indicators;
const ids = (path: string, content: string) => scan(path, content).filter(i => i.line != null).map(i => i.id);

describe("yaml.load on a ruamel parser object is not PyYAML's unsafe load", () => {
  const load = (setup: string) => `${setup}\n\ndef read(path):\n    with open(path) as fd:\n        return yaml.load(fd)\n`;

  it("`yaml = YAML()` (ruamel, round-trip) is safe", () => {
    expect(ids("a.py", load("from ruamel.yaml import YAML\nyaml = YAML()"))).not.toContain("insecure-deserialization");
  });
  it("`ruamel.yaml.YAML(typ=\"safe\")` assigned inside the function is safe", () => {
    expect(ids("a.py", `import ruamel.yaml\n\ndef read(path):\n    yaml = ruamel.yaml.YAML(typ="safe")\n    with open(path) as fd:\n        return yaml.load(fd)\n`)).not.toContain("insecure-deserialization");
  });
  it("a loader built by a helper of your own is a variable too", () => {
    expect(ids("a.py", `from app import make_loader\n\ndef read(text):\n    yaml = make_loader(text)\n    return yaml.load(text)\n`)).not.toContain("insecure-deserialization");
  });
  it("`typ=\"unsafe\"` still is a sink", () => {
    expect(ids("a.py", load("from ruamel.yaml import YAML\nyaml = YAML(typ=\"unsafe\")"))).toContain("insecure-deserialization");
  });
  it("PyYAML's module-level load of a request body still is", () => {
    expect(ids("a.py", `import yaml\nfrom flask import request\n\ndef read():\n    return yaml.load(request.data)\n`)).toContain("insecure-deserialization");
  });
  it("PyYAML's load with a safe loader still is not", () => {
    expect(ids("a.py", `import yaml\nfrom flask import request\n\ndef read():\n    return yaml.load(request.data, Loader=yaml.SafeLoader)\n`)).not.toContain("insecure-deserialization");
  });
});

describe("a name mapped to itself is not a credential", () => {
  it("\"secrets\": \"secrets\" and \"token\": \"tokens\" are labels", () => {
    const code = `result_paths = {\n    "sast": "findings",\n    "secrets": "secrets",\n}\nprefix = {"token": "tokens"}\n`;
    expect(ids("a.py", code)).not.toContain("hardcoded-secret");
  });
  it("a real value under the same name is still found", () => {
    expect(ids("a.py", `config = {\n    "secret": "xK9mP2vL8qR4tN7wZ3bY",\n}\n`)).toContain("hardcoded-secret");
  });
});

describe("logging the error about a token is not logging the token", () => {
  it("f\"Invalid token: {e}\" logs the exception", () => {
    expect(ids("a.py", `import logging\nlogger = logging.getLogger()\n\ndef check(t):\n    try:\n        verify(t)\n    except Exception as e:\n        logger.warning(f"Invalid token: {e}")\n`)).not.toContain("pii-in-logs");
  });
  it("logging the token itself still is", () => {
    expect(ids("a.py", `import logging\nlogger = logging.getLogger()\n\ndef check(token):\n    logger.info(f"login token={token}")\n`)).toContain("pii-in-logs");
  });
});

describe("a type name in quotes is not a random key", () => {
  it("generated code naming a type beside a `token` field", () => {
    const code = `export function read(x: any) {\n  return {\n    token: _read_required_field('UploadSubprojectSymbolAnalysisParams', 'token', _read_string, x['token'], x),\n  };\n}\n`;
    expect(ids("gen.ts", code)).not.toContain("high-entropy-secret");
  });
  it("a random key in the same position still is", () => {
    const code = `const config = {\n  token: "q8Zr3Lm9Xv2KdP7sWn4TbY1uHc6Jg0Ae",\n};\n`;
    expect(ids("conf.ts", code).some(i => i === "high-entropy-secret" || i === "hardcoded-secret")).toBe(true);
  });
});
