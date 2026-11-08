/** @jest-environment node */
/**
 * Python cross-file resolution shapes: a module imported out of a package (`from pkg.sub import mod`, absolute or
 * relative) and called as `mod.fn(...)`, class methods written without `self`, a schema's `.load()` result, and FastAPI's
 * `FileResponse` with a pathlib `/` path.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

type Step = { file: string; line: number; kind: string };
type Hit = { file: string; id: string; line: number; trace: Step[] };
const scan = (files: Array<{ path: string; content: string }>): Hit[] =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files }).files.flatMap(f => f.indicators
    .filter(i => i.sourceExpr && i.line != null)
    .map(i => ({ file: f.file_path, id: i.id, line: i.line!, trace: (i as { trace?: Step[] }).trace ?? [] })));
const of = (hits: Hit[], id: string) => hits.filter(h => h.id === id);
const reaches = (h: Hit | undefined, file: string, line: number) => !!h?.trace.some(t => t.file === file && t.line === line);

const exportModule = { path: "pkg/utilities/export.py", content: `import os\nEXPORTS_DIR = '/tmp/x'\n\n\ndef read_export(owner_id, filename):\n    path = os.path.join(EXPORTS_DIR, str(owner_id), filename)\n    with open(path) as export_file:\n        return export_file.read()\n` };
const caller = (importLine: string, arg = "filename") => ({
  path: "pkg/rest/user.py",
  content: `from flask import request, Response\n${importLine}\n\n\ndef get(self):\n    user = _owner()\n    filename = request.args.get('filename', 'links.csv')\n    content = export.read_export(user.id, ${arg})\n    return Response(content)\n`,
});

describe("a submodule imported from its package", () => {
  it("absolute `from pkg.utilities import export` resolves, and the flow reaches the helper's open()", () => {
    const [h] = of(scan([caller("from pkg.utilities import export"), exportModule]), "path-traversal");
    expect(h).toBeDefined();
    expect(reaches(h, "pkg/utilities/export.py", 7)).toBe(true);
    expect(h.trace.some(t => t.file === "pkg/rest/user.py" && t.line === 7)).toBe(true);   // the request read
  });

  it("relative `from ..utilities import export` resolves the same way", () => {
    expect(of(scan([caller("from ..utilities import export"), exportModule]), "path-traversal")).toHaveLength(1);
  });

  it("a constant argument in that call is clean", () => {
    expect(of(scan([caller("from pkg.utilities import export", "'links.csv'"), exportModule]), "path-traversal")).toHaveLength(0);
  });

  it("an import that is not a module in the batch is left alone", () => {
    expect(of(scan([caller("from other.library import export"), exportModule]), "path-traversal")).toHaveLength(0);
  });
});

describe("class methods written without self", () => {
  const frontend = (decorator: string, params: string) => ({ path: "app/frontend.py", content: `import subprocess\n\n\nclass Frontend():\n    def set_auth(repository):\n        return 1\n\n${decorator}    def test_connection(${params}):\n        return subprocess.check_output('git ls-remote ' + url, shell=True).decode()\n` });
  const views = { path: "app/views.py", content: `from django.http import JsonResponse\nfrom django.views import View\nfrom .frontend import Frontend\n\n\nclass V(View):\n    def post(self, request):\n        url = request.POST.get('url', '')\n        output = Frontend.test_connection(url)\n        return JsonResponse({'ok': output})\n` };

  it("`Frontend.test_connection(url)` binds url to the first parameter", () => {
    const [h] = of(scan([views, frontend("", "url")]), "command-injection");
    expect(h).toBeDefined();
    expect(reaches(h, "app/frontend.py", 9)).toBe(true);
  });

  it("a @staticmethod is the same", () => {
    expect(of(scan([views, frontend("    @staticmethod\n", "url")]), "command-injection")).toHaveLength(1);
  });

  it("a real instance method still skips self: the argument binds to the second parameter", () => {
    const svc = { path: "app/frontend.py", content: `import subprocess\n\n\nclass Frontend():\n    def test_connection(self, url):\n        return subprocess.check_output('git ls-remote ' + url, shell=True).decode()\n` };
    const [h] = of(scan([views, svc]), "command-injection");
    expect(h).toBeDefined();
  });
});

describe("schema .load() output", () => {
  const helper = { path: "app/reach.py", content: `import requests\n\n\ndef is_reachable(url):\n    return requests.get(url, timeout=5).status_code < 500\n` };
  const view = (loadArg: string) => ({ path: "app/shorturl.py", content: `from flask import request\nfrom .reach import is_reachable\n\n\nclass R:\n    def post(self):\n        payload = request.get_json()\n        data = self.schema.load(${loadArg})\n        long_url = data.pop('long_url')\n        return is_reachable(long_url)\n` });

  it("keeps the client's value: load(request payload) -> pop -> a request made from it", () => {
    const [h] = of(scan([view("payload"), helper]), "ssrf");
    expect(h).toBeDefined();
    expect(h.trace.some(t => t.line === 7)).toBe(true);    // the request body
    expect(reaches(h, "app/reach.py", 5)).toBe(true);
  });

  it("a constant load argument is clean", () => {
    expect(of(scan([view("{'long_url': 'https://example.com'}"), helper]), "ssrf")).toHaveLength(0);
  });
});

describe("FastAPI FileResponse", () => {
  const route = (stmt: string) => `from fastapi import FastAPI\nfrom fastapi.responses import FileResponse\nfrom pathlib import Path\nDOCS = Path('/srv/docs')\napp = FastAPI()\n\n\n@app.get("/docs/{name:path}")\nasync def get_doc(name: str):\n${stmt}\n`;
  it("a request-chosen pathlib path is path traversal, traced from the parameter", () => {
    const [h] = of(scan([{ path: "app/main.py", content: route(`    path = DOCS / name\n    if not path.is_file():\n        return None\n    return FileResponse(path)`) }]), "path-traversal");
    expect(h).toBeDefined();
    expect(h.line).toBe(13);
    expect(h.trace.some(t => t.kind === "source" && t.line === 9)).toBe(true);
  });
  it("a fixed file is not", () => {
    expect(of(scan([{ path: "app/main.py", content: route(`    return FileResponse(DOCS / "terms.pdf")`) }]), "path-traversal")).toHaveLength(0);
  });
  it("also through the module-qualified name", () => {
    const src = `from fastapi import FastAPI\nimport fastapi.responses as r\nfrom pathlib import Path\napp = FastAPI()\n\n\n@app.get("/d/{name}")\nasync def get_doc(name: str):\n    return r.FileResponse(Path('/srv') / name)\n`;
    expect(of(scan([{ path: "app/main.py", content: src }]), "path-traversal")).toHaveLength(1);
  });
});
