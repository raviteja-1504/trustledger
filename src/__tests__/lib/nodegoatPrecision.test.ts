/**
 * @jest-environment node
 *
 * JS/TS coverage found scanning OWASP NodeGoat: log injection (CWE-117), a constant catastrophic regex applied to
 * request input, HTTP client packages as SSRF sinks (CommonJS require() resolved), template auto-escaping switched
 * off, express-session cookies without `secure` -- and the false positives it exposed: commented-out "fix" blocks
 * and tutorial <pre>/<code> samples read by the line rules, two request fields compared as if one were a secret,
 * and a login-name lookup reported as IDOR.
 */
import { analyzeFile } from "@/lib/scanner";
import { hasNestedQuantifier } from "@/lib/taint/regexShape";
import { removesLineBreaks } from "@/lib/taint/charClass";

const route = (body: string) => `function h(req, res) {\n${body}\n  res.send("ok");\n}\nmodule.exports = h;\n`;
const found = (code: string, path = "app/routes/h.js") => analyzeFile(path, code).indicators;
const has = (code: string, id: string, path?: string) => found(code, path).some(i => i.id === id);
const astHas = (code: string, id: string) => found(code).some(i => i.id === id && !!i.sourceExpr);

describe("regex shape", () => {
  it("star height above one is a nested quantifier; bounded or flat repetition is not", () => {
    expect(hasNestedQuantifier("([0-9]+)+\\#")).toBe(true);
    expect(hasNestedQuantifier("(\\w*)*$")).toBe(true);
    expect(hasNestedQuantifier("(a+){2,}")).toBe(true);
    expect(hasNestedQuantifier("((ab)+c)*")).toBe(true);
    expect(hasNestedQuantifier("([0-9])+\\#")).toBe(false);
    expect(hasNestedQuantifier("(\\d+)?x")).toBe(false);
    expect(hasNestedQuantifier("(a+){1,3}")).toBe(false);
    expect(hasNestedQuantifier("[(a+)]+")).toBe(false);
    expect(hasNestedQuantifier("\\(a+\\)+")).toBe(false);
  });

  it("a line-break remover must take CR and LF each on its own", () => {
    expect(removesLineBreaks("[\\r\\n]")).toBe(true);
    expect(removesLineBreaks("(\\r\\n|\\r|\\n)")).toBe(true);
    expect(removesLineBreaks("\\r|\\n")).toBe(true);
    expect(removesLineBreaks("[\\r\\n]+")).toBe(true);
    expect(removesLineBreaks("\\r\\n")).toBe(false);
    expect(removesLineBreaks("\\n")).toBe(false);
    expect(removesLineBreaks("[\\r\\na]")).toBe(false);
  });
});

describe("ReDoS on a constant pattern", () => {
  it("RE.test(input) / input.match(RE) with a nested quantifier", () => {
    expect(astHas(route(`  const { b } = req.body;\n  const re = /([0-9]+)+\\#/;\n  re.test(b);`), "redos")).toBe(true);
    expect(astHas(route(`  const b = req.query.b;\n  b.match(/(\\w+)*$/);`), "redos")).toBe(true);
    expect(astHas(route(`  const b = req.query.b;\n  new RegExp("(a+)+").exec(b);`), "redos")).toBe(true);
  });
  it("a linear pattern, or a constant subject, is not", () => {
    expect(astHas(route(`  const { b } = req.body;\n  const re = /([0-9])+\\#/;\n  re.test(b);`), "redos")).toBe(false);
    expect(astHas(route(`  const re = /([0-9]+)+\\#/;\n  re.test("123#");`), "redos")).toBe(false);
  });
});

describe("log injection", () => {
  it("a request string reaching console / a logger", () => {
    expect(astHas(route(`  const { userName } = req.body;\n  console.log("invalid user: ", userName);`), "log-injection")).toBe(true);
    expect(astHas(route(`  logger.warn(\`login failed for \${req.query.u}\`);`), "log-injection")).toBe(true);
    expect(astHas(route(`  this.logger.info(req.body.name);`), "log-injection")).toBe(true);
  });
  it("CR/LF stripped, JSON-encoded, a whole request object (util.inspect), or not a logger", () => {
    expect(astHas(route(`  const { u } = req.body;\n  console.log("x", u.replace(/(\\r\\n|\\r|\\n)/g, "_"));`), "log-injection")).toBe(false);
    expect(astHas(route(`  const { u } = req.body;\n  console.log("x", u.replace(/[\\r\\n]/g, ""));`), "log-injection")).toBe(false);
    expect(astHas(route(`  logger.info(JSON.stringify(req.body.u));`), "log-injection")).toBe(false);
    expect(astHas(route(`  console.log(req.body);`), "log-injection")).toBe(false);
    expect(astHas(route(`  Math.log(req.query.n);`), "log-injection")).toBe(false);
    // structured context is serialized, its strings quoted
    expect(astHas(route(`  logger.error("lookup failed", { user: req.query.u });`), "log-injection")).toBe(false);
    // JSON.parse gives back the line breaks JSON.stringify escaped
    expect(astHas(route(`  logger.info(JSON.parse(JSON.stringify(req.body.u)));`), "log-injection")).toBe(true);
    // a replace that keeps a bare CR, or isn't global, still lets a line break through
    expect(astHas(route(`  const { u } = req.body;\n  console.log(u.replace(/\\n/g, ""));`), "log-injection")).toBe(true);
    expect(astHas(route(`  const { u } = req.body;\n  console.log(u.replace(/[\\r\\n]/, ""));`), "log-injection")).toBe(true);
  });
});

describe("HTTP client packages", () => {
  it("needle / got / request bound with require() are SSRF sinks", () => {
    expect(astHas(`const needle = require("needle");\n` + route(`  needle.get(req.query.url + req.query.s, () => {});`), "ssrf")).toBe(true);
    expect(astHas(`const needle = require("needle");\n` + route(`  needle("get", req.query.url);`), "ssrf")).toBe(true);
    expect(astHas(`const got = require("got");\n` + route(`  got(req.body.target);`), "ssrf")).toBe(true);
    expect(astHas(`import * as superagent from "superagent";\n` + route(`  superagent.post(req.body.u);`), "ssrf")).toBe(true);
    // the same names, not bound to the package
    expect(astHas(route(`  needle.get(req.query.url);`), "ssrf")).toBe(false);
  });
});

describe("timing attacks", () => {
  it("a stored secret against input is one; two request fields are not", () => {
    expect(astHas(`function h(req, res, user) {\n  if (user.password === req.body.password) res.send("ok");\n}\nmodule.exports = h;\n`, "timing-attack")).toBe(true);
    expect(astHas(route(`  const { password, verify } = req.body;\n  if (password !== verify) return res.send("mismatch");`), "timing-attack")).toBe(false);
  });
});

describe("line rules skip text that never runs", () => {
  const dao = (inner: string) => `function D(col) {\n  this.f = (t, cb) => {\n    /*\n${inner}\n    */\n    return col.find({ userId: 1 }).toArray(cb);\n  };\n}\nmodule.exports = D;\n`;
  it("a commented-out block in JS/TS", () => {
    expect(has(dao(`    return {$where: \`this.stocks > \${parseInt(t)}\`};`), "nosql-injection")).toBe(false);
    expect(has(dao(`    res.cookie("session", sid, { secure: true });`), "cookie-no-httponly")).toBe(false);
    // the same line live is still reported
    expect(has(`function D(col, t) {\n  return col.find({$where: \`this.stocks > '\${t}'\`});\n}\nmodule.exports = D;\n`, "nosql-injection")).toBe(true);
    // a "/*" inside a string doesn't open a comment
    expect(has(`const g = "src/**/*.js";\nfunction D(col, t) {\n  return col.find({$where: \`this.stocks > '\${t}'\`});\n}\nmodule.exports = D;\n`, "nosql-injection")).toBe(true);
  });
  it("<pre>/<code> samples and comments in HTML, unless a <script> inside still runs", () => {
    const page = (inner: string) => `<html><body>\n<p>Avoid this:</p>\n${inner}\n<p>more text here for length</p>\n</body></html>\n`;
    expect(has(page(`<pre>\n  const x = eval(req.body.preTax);\n</pre>`), "eval-exec", "views/a1.html")).toBe(false);
    expect(has(page(`<p>Never call <code>eval()</code> on input.</p>`), "eval-exec", "views/a1.html")).toBe(false);
    expect(has(page(`<!--\n  eval(req.body.x)\n-->`), "eval-exec", "views/a1.html")).toBe(false);
    expect(has(page(`<script>\n  eval(location.hash.slice(1));\n</script>`), "eval-exec", "views/a1.html")).toBe(true);
    expect(has(page(`<pre>\n<script>\n  eval(location.hash.slice(1));\n</script>\n</pre>`), "eval-exec", "views/a1.html")).toBe(true);
  });
});

describe("template and session configuration", () => {
  it("auto-escaping switched off", () => {
    expect(has(`const swig = require("swig");\nswig.setDefaults({\n  autoescape: false\n});\nmodule.exports = swig;\n`, "xss", "server.js")).toBe(true);
    expect(has(`const swig = require("swig");\nswig.setDefaults({\n  autoescape: true\n});\nmodule.exports = swig;\n`, "xss", "server.js")).toBe(false);
    expect(has(`from jinja2 import Environment\nenv = Environment(loader=loader, autoescape=False)\nprint(env)\n`, "xss", "app.py")).toBe(true);
  });
  it("express-session without cookie.secure; httpOnly explicitly off", () => {
    const app = (opts: string) => `const session = require("express-session");\nconst app = require("express")();\napp.use(session({\n  secret: s,\n${opts}\n}));\n`;
    expect(has(app(`  resave: true`), "cookie-no-secure", "server.js")).toBe(true);
    expect(has(app(`  cookie: { secure: false }`), "cookie-no-secure", "server.js")).toBe(true);
    expect(has(app(`  cookie: { secure: true }`), "cookie-no-secure", "server.js")).toBe(false);
    expect(has(app(`  cookie: { secure: process.env.NODE_ENV === "production" }`), "cookie-no-secure", "server.js")).toBe(false);
    expect(has(app(`  cookie: { secure: true, httpOnly: false }`), "cookie-no-httponly", "server.js")).toBe(true);
    // a function that merely shares the name, from elsewhere
    expect(has(`const session = require("./session");\napp.use(session({\n  resave: true\n}));\nmodule.exports = app;\n`, "cookie-no-secure", "server.js")).toBe(false);
  });
});

describe("IDOR heuristic", () => {
  it("a lookup by login name is not an object reference; by id it is", () => {
    const signup = (call: string) => `function h(req, res) {\n  const { userName, userId } = req.body;\n  ${call}\n  res.send("ok");\n}\nmodule.exports = h;\n`;
    expect(has(signup(`userDAO.getUserByUserName(userName, cb);`), "idor")).toBe(false);
    expect(has(signup(`userDAO.findOne(userName, cb);`), "idor")).toBe(false);
    expect(has(signup(`benefitsDAO.updateBenefits(userId, cb);`), "idor")).toBe(true);
  });
});
