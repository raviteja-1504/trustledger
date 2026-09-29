import { analyzeDependencyReachability, importNamesFor, isTestPath, reachableFiles } from "@/lib/depReachability";
import { extractAffectedSymbols } from "@/lib/osvClient";

type F = { file_path: string; content: string };
const tier = (pkg: string, eco: string, files: F[], symbols?: string[]) => analyzeDependencyReachability(pkg, eco, files, symbols).tier;

describe("distribution name -> import name", () => {
  it("PyPI distributions whose import name differs", () => {
    expect(importNamesFor("PyYAML", "python")).toEqual(["yaml"]);
    expect(importNamesFor("beautifulsoup4", "python")).toEqual(["bs4"]);
    expect(importNamesFor("Pillow", "python")).toEqual(["PIL"]);
    expect(importNamesFor("python_dateutil", "python")).toEqual(["dateutil"]);
    expect(importNamesFor("requests", "python")).toEqual(["requests"]);
    expect(importNamesFor("Flask-Login", "python")).toContain("flask_login");
  });
  it("Maven groupId, Composer vendor, crate, and no mapping for OS packages", () => {
    expect(importNamesFor("org.apache.logging.log4j:log4j-core", "java")).toEqual(["org.apache.logging.log4j"]);
    expect(importNamesFor("guzzlehttp/guzzle", "php")).toEqual(["guzzlehttp"]);
    expect(importNamesFor("serde-json", "rust")).toEqual(["serde_json"]);
    expect(importNamesFor("openssl", "docker")).toEqual([]);
  });
});

describe("tiers", () => {
  const route = (imp: string, body: string) => ({ file_path: "src/routes/user.ts", content: `${imp}\napp.get("/u", (req, res) => {\n  ${body}\n});\n` });

  it("called: the advisory's vulnerable function is called through the import", () => {
    const r = analyzeDependencyReachability("lodash", "typescript", [route(`import _ from "lodash";`, `_.template(req.query.t);`)], ["lodash.template"]);
    expect(r.tier).toBe("called");
    expect(r.evidence[0]).toMatchObject({ file: "src/routes/user.ts", line: 3, kind: "call" });
    expect(r.summary).toContain("src/routes/user.ts:3");
  });
  it("called: a named import, and a Go package-qualified call", () => {
    expect(tier("lodash", "typescript", [route(`import { template as tpl } from "lodash";`, `tpl(req.query.t);`)], ["template"])).toBe("called");
    const go = { file_path: "cmd/api/main.go", content: `package main\nimport (\n\t"fmt"\n\tyaml "gopkg.in/yaml.v2"\n)\nfunc main() { yaml.Unmarshal(b, &v) }\n` };
    expect(tier("gopkg.in/yaml.v2", "go", [go], ["gopkg.in/yaml.v2.Unmarshal"])).toBe("called");
  });
  it("not-called: imported, but none of the named functions is used", () => {
    const r = analyzeDependencyReachability("lodash", "typescript", [route(`import _ from "lodash";`, `_.merge({}, req.body);`)], ["lodash.template"]);
    expect(r.tier).toBe("not-called");
    expect(r.evidence[0]).toMatchObject({ kind: "import", line: 1 });
  });
  it("a same-named call on something that isn't the package does not count", () => {
    expect(tier("lodash", "typescript", [route(`import _ from "lodash";`, `engine.template(req.query.t);`)], ["lodash.template"])).toBe("not-called");
  });
  it("reachable: imported by a file an entry point imports", () => {
    const files = [
      { file_path: "src/server.ts", content: `import { render } from "./lib/render";\napp.listen(3000);\n` },
      { file_path: "src/lib/render.ts", content: `import _ from "lodash";\nexport const render = (t) => _.merge({}, t);\n` },
    ];
    const r = analyzeDependencyReachability("lodash", "typescript", files);
    expect(r.tier).toBe("reachable");
    expect(r.summary).toContain("src/server.ts");
    expect(r.evidence).toContainEqual(expect.objectContaining({ kind: "entry", file: "src/server.ts" }));
  });
  it("imported: application code imports it, but nothing reaches that file", () => {
    expect(tier("lodash", "typescript", [{ file_path: "src/lib/unused.ts", content: `import _ from "lodash";\nexport const x = _.merge;\n` }])).toBe("imported");
  });
  it("test-only and not-imported", () => {
    expect(tier("lodash", "typescript", [{ file_path: "src/__tests__/a.test.ts", content: `import _ from "lodash";\n` }])).toBe("test-only");
    expect(tier("lodash", "typescript", [{ file_path: "src/a.ts", content: `import x from "lodash-es";\n` }])).toBe("not-imported");
    expect(tier("openssl", "docker", [])).toBe("unknown");
  });
  it("Python: import name mapping, relative-import reachability from a Django view", () => {
    const files = [
      { file_path: "app/views.py", content: `from .loader import load_cfg\ndef v(request):\n    return load_cfg(request.body)\n` },
      { file_path: "app/loader.py", content: `import yaml\ndef load_cfg(b):\n    return yaml.load(b)\n` },
    ];
    const r = analyzeDependencyReachability("PyYAML", "python", files, ["yaml.load"]);
    expect(r.tier).toBe("called");
    expect(r.summary).toContain("app/loader.py:3");
    expect(r.summary).toContain("app/views.py");
    expect(tier("PyYAML", "python", files, ["yaml.full_load"])).toBe("not-called");
  });
  it("Java import of a class from the groupId, C# using, PHP use", () => {
    expect(tier("org.apache.logging.log4j:log4j-core", "java", [{ file_path: "src/main/java/UserController.java",
      content: `import org.apache.logging.log4j.LogManager;\n@RestController public class UserController {}\n` }])).toBe("reachable");
    expect(tier("Newtonsoft.Json", "csharp", [{ file_path: "Services/Codec.cs", content: `using Newtonsoft.Json;\nclass Codec {}\n` }])).toBe("imported");
    expect(tier("guzzlehttp/guzzle", "php", [{ file_path: "src/Client.php", content: `<?php\nuse GuzzleHttp\\Client;\n` }])).toBe("imported");
  });
  it("the ES import clause never swallows an earlier import statement", () => {
    const f = { file_path: "src/a.ts", content: `import a from "x";\nimport { merge } from "lodash";\nmerge();\n` };
    const r = analyzeDependencyReachability("lodash", "typescript", [f], ["lodash.merge"]);
    expect(r.tier).toBe("called");
    expect(r.evidence.find(e => e.kind === "import")?.line).toBe(2);
  });
  it("a Go string literal outside an import declaration is not an import", () => {
    expect(tier("github.com/x/y", "go", [{ file_path: "a.go", content: `package a\nvar s = "github.com/x/y"\n` }])).toBe("not-imported");
  });
});

describe("helpers", () => {
  it("test paths", () => {
    for (const p of ["tests/a.py", "src/__tests__/x.ts", "a.spec.ts", "pkg/x_test.go", "test_views.py", "FooTest.java", "examples/demo.js"]) expect(isTestPath(p)).toBe(true);
    for (const p of ["src/app.ts", "latest/report.py", "contest.go"]) expect(isTestPath(p)).toBe(false);
  });
  it("reachability follows relative imports transitively and records the entry", () => {
    const r = reachableFiles([
      { file_path: "src/index.ts", content: `import "./a";\napp.listen(1);\n` },
      { file_path: "src/a.ts", content: `import { b } from "./b";\n` },
      { file_path: "src/b.ts", content: `export const b = 1;\n` },
      { file_path: "src/orphan.ts", content: `export const o = 1;\n` },
    ]);
    expect(r.get("src/b.ts")).toBe("src/index.ts");
    expect(r.has("src/orphan.ts")).toBe(false);
  });
  it("OSV symbols: Go imports, RustSec functions, affected_functions", () => {
    expect(extractAffectedSymbols({ id: "GO-1", affected: [{ ecosystem_specific: { imports: [{ path: "golang.org/x/net/html", symbols: ["Parse", "Tokenizer.Next"] }] } }] }))
      .toEqual(["golang.org/x/net/html.Parse", "golang.org/x/net/html.Tokenizer.Next"]);
    expect(extractAffectedSymbols({ id: "RUSTSEC-1", affected: [{ ecosystem_specific: { affects: { functions: ["smallvec::SmallVec::insert_many"] } } }] }))
      .toEqual(["smallvec::SmallVec::insert_many"]);
    expect(extractAffectedSymbols({ id: "GHSA-1", affected: [{ ranges: [] }] })).toEqual([]);
  });
});
