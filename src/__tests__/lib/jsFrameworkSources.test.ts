/**
 * @jest-environment node
 *
 * Request sources and sinks of the JavaScript frameworks beyond Express: Koa, Hapi, Nuxt (h3), Meteor, Sails, AdonisJS, Socket.IO.
 * Each vulnerable case is a class (SSRF, open redirect, XSS) the pattern layer cannot see: only tracing the request value finds it.
 * Each is paired with a safe case that must stay quiet.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

jest.setTimeout(120_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

const idsOf = (name: string, content: string) =>
  runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: `t/${name}`, content }] })
    .files[0].indicators.filter(i => i.line != null && i.id !== "ai-model-attribution").map(i => i.id);

describe("vulnerable handlers are traced from the framework's request", () => {
  const cases: Array<[string, string, string, string]> = [
    ["koa ssrf",        "k1.js", "ssrf",          `router.get('/a', async (ctx) => { const r = await fetch(ctx.query.url); ctx.body = await r.text(); });`],
    ["koa body ssrf",   "k2.js", "ssrf",          `router.post('/a', async (ctx) => { const r = await fetch(ctx.request.body.url); ctx.body = 'ok'; });`],
    ["koa redirect",    "k3.js", "open-redirect", `router.get('/a', async (ctx) => { ctx.redirect(ctx.query.next); });`],
    ["koa xss",         "k4.js", "xss",           `router.get('/a', async (ctx) => { ctx.body = '<h1>' + ctx.query.name + '</h1>'; });`],
    ["hapi ssrf",       "h1.js", "ssrf",          `server.route({ method: 'POST', path: '/a', handler: async (request, h) => { const r = await fetch(request.payload.url); return r.text(); } });`],
    ["hapi redirect",   "h2.js", "open-redirect", `server.route({ method: 'GET', path: '/a', handler: (request, h) => h.redirect(request.query.next) });`],
    ["nuxt ssrf",       "n1.js", "ssrf",          `export default defineEventHandler(async (event) => { const q = getQuery(event); const r = await fetch(q.url); return r.text(); });`],
    ["nuxt redirect",   "n2.js", "open-redirect", `export default defineEventHandler(async (event) => { const q = getQuery(event); return sendRedirect(event, q.next); });`],
    ["nuxt body ssrf",  "n3.js", "ssrf",          `export default defineEventHandler(async (event) => { const b = await readBody(event); return await fetch(b.url); });`],
    ["meteor ssrf",     "m1.js", "ssrf",          `Meteor.methods({ get(url) { return HTTP.get(url); } });`],
    ["meteor sql",      "m2.js", "sql-injection", `Meteor.methods({ find(name) { return db.query("SELECT * FROM t WHERE n = '" + name + "'"); } });`],
    ["sails redirect",  "s1.js", "open-redirect", `module.exports = { run: async function (req, res) { return res.redirect(req.param('next')); } };`],
    ["sails sql",       "s2.js", "sql-injection", `module.exports = { run: async function (req, res) { const r = await sails.sendNativeQuery("SELECT * FROM t WHERE n = '" + req.param('name') + "'"); return res.json(r); } };`],
    ["adonis redirect", "a1.ts", "open-redirect", `export default class A { async run({ request, response }) { return response.redirect(request.input('next')); } }`],
    ["adonis sql",      "a2.ts", "sql-injection", `export default class A { async run({ request }) { return Database.rawQuery("SELECT * FROM t WHERE n = '" + request.input('name') + "'"); } }`],
    ["socket.io ssrf",  "w1.js", "ssrf",          `io.on('connection', (socket) => { socket.on('q', async (data) => { await fetch(data.url); }); });`],
    ["socket.io sql",   "w2.js", "sql-injection", `io.on('connection', (socket) => { socket.on('q', (data, ack) => { db.query("SELECT * FROM t WHERE n = '" + data.name + "'"); ack(); }); });`],
  ];
  it.each(cases)("%s", (_n, file, rule, code) => {
    expect(idsOf(file, code)).toContain(rule);
  });
});

describe("safe handlers stay quiet", () => {
  const safe: Array<[string, string, string]> = [
    ["koa fetches a fixed URL",              "ok1.js", `router.get('/a', async (ctx) => { const r = await fetch('https://api.example.com/x'); ctx.body = await r.text(); });`],
    ["koa redirects to a fixed path",        "ok2.js", `router.get('/a', async (ctx) => { ctx.redirect('/home'); });`],
    ["koa body is the response, not input",  "ok3.js", `router.get('/a', async (ctx) => { ctx.body = '<h1>Welcome</h1>'; });`],
    ["hapi fetches a fixed URL",             "ok4.js", `server.route({ method: 'POST', path: '/a', handler: async (request, h) => { const r = await fetch('https://api.example.com/x'); return r.text(); } });`],
    ["nuxt redirects to a fixed path",       "ok5.js", `export default defineEventHandler(async (event) => { return sendRedirect(event, '/login'); });`],
    ["meteor method ignores its argument",   "ok6.js", `Meteor.methods({ get(url) { return HTTP.get('https://api.example.com/x'); } });`],
    ["socket connect handler is not client data", "ok7.js", `io.on('connection', (socket) => { socket.on('connect', async (info) => { await fetch(info.url); }); });`],
    ["socket event fetches a fixed URL",     "ok8.js", `io.on('connection', (socket) => { socket.on('q', async (data) => { await fetch('https://api.example.com/x'); }); });`],
    ["a method named like a source on another object", "ok9.js", `function f(cache) { return fetch(cache.param('k')); }`],
  ];
  it.each(safe)("%s", (_n, file, code) => {
    const ids = idsOf(file, code);
    for (const rule of ["ssrf", "open-redirect", "xss", "sql-injection"]) expect(ids).not.toContain(rule);
  });
  it("joined string literals are a constant command", () => {
    expect(idsOf("c1.js", `const { exec } = require('child_process');\nexec('ls ' + 'src');\n`)).not.toContain("command-injection");
  });
  it("a joined command with a variable is still flagged", () => {
    expect(idsOf("c2.js", `const { exec } = require('child_process');\nfunction f(d) { exec('ls ' + d); }\n`)).toContain("command-injection");
  });
});
