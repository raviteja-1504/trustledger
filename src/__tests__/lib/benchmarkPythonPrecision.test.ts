/**
 * Python precision and recall from scoring OWASP BenchmarkPython (12 -> 95 on its scorecard). Each rule is tested
 * with the shape that must be reported and the nearest shape that must not:
 *   - weak randomness / weak hashing / cookie flags / trust boundary / XXE via a qualified SAX feature
 *   - new sinks: codecs.open, os.path.exists, pathlib paths (Path / base / name), elementpath.select
 *   - guards: a dangerous substring that must be absent, the quoted-literal eval check, a parsed-URL host allowlist
 *   - value tracking: literal dict / ConfigParser keys, lists built by append/pop, StringIO/ConfigParser carry,
 *     constant-folded if / ternary / match, quote-escaping replace()
 *   - sources: request.query_string; string-valued request fields aren't NoSQL-capable, cookie/header values
 *     can't split a header; request-returning helpers in another file (and the incremental cache follows them)
 *   - the pattern layer's eval()/pickle.loads() hits are vetoed when the argument is a proven constant
 */
import { analyzeFile, runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

jest.setTimeout(60_000);
beforeAll(async () => { await ensureTaintEngines(); });

const ids = (src: string, id: string, path = "app/views.py") => analyzeFile(path, src).indicators.filter(i => i.id === id).map(i => i.line);
// a Flask view: `param` is request data, the body starts on line 4
const view = (body: string) => `from flask import request\ndef v():\n    param = request.args.get("p")\n${body}\n`;

describe("weak randomness, weak hashing, cookie flags", () => {
  it("random.* stored in a session or a security-named variable is flagged; secrets / SystemRandom / plain use are not", () => {
    const store = (gen: string) => `import random, secrets\nfrom helpers.utils import mysession\ndef v(cookie):\n    value = ${gen}\n    mysession[cookie] = value\n`;
    expect(ids(store("str(random.normalvariate())[2:]"), "insecure-randomness")).toEqual([4]);
    expect(ids(store("str(secrets.randbelow(2**32))"), "insecure-randomness")).toEqual([]);
    expect(ids(store("str(random.SystemRandom().random())"), "insecure-randomness")).toEqual([]);
    expect(ids(`import random\ndef v():\n    token = random.getrandbits(64)\n    return token\n`, "insecure-randomness")).toEqual([3]);
    expect(ids(`import random\ndef v(items):\n    pick = random.choice(items)\n    return pick\n`, "insecure-randomness")).toEqual([]);
  });

  it("MD5 / SHA-1 through hashlib are weak; SHA-384 and usedforsecurity=False are not", () => {
    const hash = (call: string) => `import hashlib\ndef digest(data):\n    h = ${call}\n    h.update(data)\n    return h.hexdigest()\n`;
    expect(ids(hash("hashlib.new('md5')"), "weak-crypto")).toEqual([3]);
    expect(ids(hash("hashlib.sha1()"), "weak-crypto")).toEqual([3]);
    expect(ids(hash("hashlib.new('sha384')"), "weak-crypto")).toEqual([]);
    expect(ids(hash("hashlib.md5(usedforsecurity=False)"), "weak-crypto")).toEqual([]);
  });

  it("set_cookie with an explicit secure=False / httponly=False is flagged across lines; True or omitted is not", () => {
    const cookie = (flags: string) => `def v(r, c, value):\n    r.set_cookie(c, value,\n        path='/',\n        ${flags})\n`;
    expect(ids(cookie("secure=False, httponly=True"), "cookie-no-secure")).toEqual([2]);
    expect(ids(cookie("secure=True, httponly=False"), "cookie-no-httponly")).toEqual([2]);
    expect(ids(cookie("secure=True, httponly=True"), "cookie-no-secure")).toEqual([]);
    expect(ids(cookie("max_age=60"), "cookie-no-secure")).toEqual([]);
  });
});

describe("trust boundary and XXE", () => {
  it("request data as a session key or value is a trust-boundary violation; constants are not", () => {
    expect(ids(view(`    import flask\n    flask.session[param] = '1'`), "trust-boundary")).toEqual([5]);
    expect(ids(view(`    import flask\n    flask.session['userid'] = param`), "trust-boundary")).toEqual([5]);
    expect(ids(view(`    import flask\n    flask.session['userid'] = 'x'`), "trust-boundary")).toEqual([]);
  });

  it("a SAX parser with external entities on (qualified feature name) parsing request data is XXE; off is not", () => {
    const sax = (feature: string) => view(`    import xml.dom.minidom, xml.sax.handler\n    parser = xml.sax.make_parser()\n${feature}\n    return xml.dom.minidom.parseString(param, parser)`);
    expect(ids(sax("    parser.setFeature(xml.sax.handler.feature_external_ges, True)"), "xxe")).toEqual([7]);
    expect(ids(sax("    pass"), "xxe")).toEqual([]);
  });
});

describe("new sinks", () => {
  it("codecs.open, os.path.exists and pathlib paths reach the file system", () => {
    expect(ids(view(`    import codecs\n    return codecs.open(f'/d/{param}', 'r', 'utf-8')`), "path-traversal")).toEqual([5]);
    expect(ids(view(`    import os\n    return os.path.exists(f'/d/{param}')`), "path-traversal")).toEqual([5]);
    expect(ids(view(`    import pathlib\n    p = pathlib.Path('/d') / param\n    return p.exists()`), "path-traversal")).toEqual([6]);
    expect(ids(view(`    import pathlib\n    p = pathlib.Path('/d') / 'x.txt'\n    return p.read_text()`), "path-traversal")).toEqual([]);
    // .open() on something that isn't a path
    expect(ids(view(`    conn = make_conn(param)\n    return conn.open()`), "path-traversal")).toEqual([]);
  });

  it("elementpath.select(root, query) runs the query", () => {
    expect(ids(view(`    import elementpath\n    return elementpath.select(root, f"/E[@id='{param}']")`), "xpath-injection")).toEqual([5]);
  });
});

describe("guards", () => {
  it("'..' / quote absence proves safety only for the injection that needs it", () => {
    expect(ids(view(`    if '../' in param:\n        return 'no'\n    return open(param).read()`), "path-traversal")).toEqual([]);
    expect(ids(view(`    if "'" in param:\n        return 'no'\n    return root.xpath(f"/E[@id='{param}']")`), "xpath-injection")).toEqual([]);
    // a quote check says nothing about paths
    expect(ids(view(`    if "'" in param:\n        return 'no'\n    return open(param).read()`), "path-traversal")).toEqual([6]);
  });

  it("the quoted-literal check makes eval() safe; any one of its three parts alone does not", () => {
    const full = `    if not param.startswith("'") or not param.endswith("'") or "'" in param[1:-1]:\n        return 'no'\n    return eval(param)`;
    const partial = `    if not param.startswith("'") or not param.endswith("'"):\n        return 'no'\n    return eval(param)`;
    expect(ids(view(full), "eval-exec")).toEqual([]);
    expect(ids(view(partial), "eval-exec")).toEqual([6]);
  });

  it("a parsed-URL host allowlist makes the redirect safe; parsing alone does not", () => {
    const guarded = `    import flask, urllib.parse\n    url = urllib.parse.urlparse(param)\n    if url.netloc not in ['google.com'] or url.scheme != 'https':\n        return 'no'\n    return flask.redirect(param)`;
    expect(ids(view(guarded), "open-redirect")).toEqual([]);
    expect(ids(view(`    import flask, urllib.parse\n    url = urllib.parse.urlparse(param)\n    return flask.redirect(param)`), "open-redirect")).toEqual([6]);
  });
});

describe("value tracking", () => {
  it("dict / ConfigParser slots under literal keys are read back by key", () => {
    const dict = (k: string) => view(`    m = {}\n    m['keyA'] = 'a'\n    m['keyB'] = param\n    return open(m[${k}]).read()`);
    expect(ids(dict("'keyA'"), "path-traversal")).toEqual([]);
    expect(ids(dict("'keyB'"), "path-traversal")).toEqual([7]);
    expect(ids(view(`    m = {}\n    m['keyA'] = 'a'\n    m['keyB'] = param\n    return open(m.get('keyA')).read()`), "path-traversal")).toEqual([]);
    const conf = (k: string) => view(`    import configparser\n    c = configparser.ConfigParser()\n    c.set('s', 'keyA', 'a')\n    c.set('s', 'keyB', param)\n    return open(c.get('s', ${k})).read()`);
    expect(ids(conf("'keyA'"), "path-traversal")).toEqual([]);
    expect(ids(conf("'keyB'"), "path-traversal")).toEqual([8]);
  });

  it("StringIO.write -> getvalue carries the value", () => {
    expect(ids(view(`    import io\n    s = io.StringIO()\n    s.write(param)\n    return open(s.getvalue()).read()`), "path-traversal")).toEqual([7]);
  });

  it("a list built with append/pop is read by position", () => {
    const list = (i: number) => view(`    lst = []\n    lst.append('safe')\n    lst.append(param)\n    lst.append('moresafe')\n    lst.pop(0)\n    return root.xpath(f"/E[@id='{lst[${i}]}']")`);
    expect(ids(list(1), "xpath-injection")).toEqual([]);
    expect(ids(list(0), "xpath-injection")).toEqual([9]);
  });

  it("constant conditions keep only the arm that runs (if / ternary / match); unknown conditions keep both", () => {
    const branch = (n: number) => view(`    num = ${n}\n    if 7 * 42 - num > 200:\n        bar = 'safe'\n    else:\n        bar = param\n    return open(bar).read()`);
    expect(ids(branch(86), "path-traversal")).toEqual([]);
    expect(ids(branch(106), "path-traversal")).toEqual([9]);
    expect(ids(view(`    num = 106\n    bar = 'safe' if 7 * 18 + num > 200 else param\n    return open(bar).read()`), "path-traversal")).toEqual([]);
    expect(ids(view(`    bar = 'safe' if len(param) > 3 else param\n    return open(bar).read()`), "path-traversal")).toEqual([5]);
    const match = (i: number) => view(`    import pickle\n    guess = "ABC"[${i}]\n    match guess:\n        case 'A':\n            bar = param\n        case 'B':\n            bar = 'bob'\n    return pickle.loads(bar)`);
    expect(ids(match(1), "insecure-deserialization")).toEqual([]);
    expect(ids(match(0), "insecure-deserialization")).toEqual([11]);
    expect(ids(view(`    t = "never"\n    if 'never' not in t:\n        bar = param\n    else:\n        bar = 'x'\n    return open(bar).read()`), "path-traversal")).toEqual([]);
  });

  it("escaping the quote clears SQL/XPath (not other classes); a replacement that keeps the quote does not", () => {
    expect(ids(view(`    q = f"/E[@id='{param.replace("'", "&apos;")}']"\n    return root.xpath(q)`), "xpath-injection")).toEqual([]);
    expect(ids(view(`    q = f"/E[@id='{param.replace("'", "x'")}']"\n    return root.xpath(q)`), "xpath-injection")).toEqual([5]);
    expect(ids(view(`    return open(param.replace("'", "&apos;")).read()`), "path-traversal")).toEqual([4]);
  });
});

describe("sources", () => {
  it("request.query_string is request data", () => {
    expect(ids(`from flask import request\ndef v():\n    qs = request.query_string.decode('utf-8')\n    return open(qs[qs.find('x=') + 2:]).read()\n`, "path-traversal")).toEqual([4]);
    expect(ids(`from flask import request\ndef v():\n    raw = request.query_string\n    return open(raw).read()\n`, "path-traversal")).toEqual([4]);
  });

  it("a single form/query/cookie value can't carry a NoSQL operator; the whole container or a JSON body can", () => {
    const find = (expr: string) => `from flask import request\ndef v(db):\n    return db.users.find_one(${expr})\n`;
    expect(ids(find(`{"name": request.cookies.get("n")}`), "nosql-injection")).toEqual([]);
    expect(ids(find(`{"name": request.args.get("n")}`), "nosql-injection")).toEqual([]);
    expect(ids(find(`request.args.to_dict()`), "nosql-injection")).toEqual([3]);
    expect(ids(find(`request.get_json()`), "nosql-injection")).toEqual([3]);
  });

  it("a cookie/header value can't split a response header; a query value can", () => {
    const hdr = (src: string) => `from flask import request, make_response\ndef v():\n    r = make_response("ok")\n    r.headers["X-A"] = ${src}\n    return r\n`;
    expect(ids(hdr(`request.cookies.get("a")`), "header-injection")).toEqual([]);
    expect(ids(hdr(`request.args.get("a")`), "header-injection")).toEqual([4]);
  });

  it("make_response((body, headers)): only the body is HTML", () => {
    expect(ids(view(`    from flask import make_response\n    return make_response(("ok", {"X-A": param}))`), "xss")).toEqual([]);
    expect(ids(view(`    from flask import make_response\n    return make_response((param, {"X-A": "1"}))`), "xss")).toEqual([5]);
  });
});

describe("the pattern layer defers to a proven constant", () => {
  it("eval() / pickle.loads() of a value proven constant is not reported; of request data, or a value not proven, it is", () => {
    expect(ids(view(`    num = 86\n    if 7 * 42 - num > 200:\n        bar = 'safe'\n    else:\n        bar = param\n    return eval(bar)`), "eval-exec")).toEqual([]);
    expect(ids(view(`    import pickle, base64\n    bar = 'x'\n    return pickle.loads(base64.b64decode(bar))`), "insecure-deserialization")).toEqual([]);
    expect(ids(view(`    return eval(param)`), "eval-exec")).toEqual([4]);
    // an unknown helper's result is not proven constant: the pattern rule still reports it
    expect(ids(view(`    bar = load_config()\n    return eval(bar)`), "eval-exec")).toEqual([5]);
  });
});

describe("request-returning helpers in another file", () => {
  const helper = (safe: boolean) => `class request_wrapper:\n    def __init__(self, request):\n        self.request = request\n    def get_form_parameter(self, name):\n        return ${safe ? '"bar"' : "self.request.form.get(name)"}\n    def get_safe_value(self, name):\n        return "bar"\n`;
  const views = (method: string) => `import helpers.separate_request\nfrom flask import request\ndef v():\n    w = helpers.separate_request.request_wrapper(request)\n    p = w.${method}("x")\n    return open(p).read()\n`;
  const scan = (helperSrc: string, viewSrc: string, prev?: Parameters<typeof runScan>[0]["prev_results"]) => runScan({
    repo: "a/b", pr_number: 1, commit_sha: "0".repeat(40), prev_results: prev,
    files: [{ path: "helpers/separate_request.py", content: helperSrc }, { path: "app/views.py", content: viewSrc }],
  });
  const traversal = (r: ReturnType<typeof runScan>) => r.files.find(f => f.file_path === "app/views.py")!.indicators.filter(i => i.id === "path-traversal").map(i => i.line);

  it("a wrapper method returning self.request.form.get(...) is request data at the call site; one returning a constant is not", () => {
    expect(traversal(scan(helper(false), views("get_form_parameter")))).toEqual([6]);
    expect(traversal(scan(helper(false), views("get_safe_value")))).toEqual([]);
  });

  it("an unchanged caller is re-analysed when the helper stops returning request data", () => {
    const first = scan(helper(false), views("get_form_parameter"));
    expect(traversal(first)).toEqual([6]);
    const second = scan(helper(true), views("get_form_parameter"), first.file_cache);
    expect(traversal(second)).toEqual([]);
  });
});
