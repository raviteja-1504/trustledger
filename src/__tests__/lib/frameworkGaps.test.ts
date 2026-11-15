/**
 * @jest-environment node
 *
 * The frameworks the coverage report (frameworkCoverageReport.test.ts) found without a vulnerable AND a safe case:
 * Next.js, Express, Fastify, NestJS, Sequelize, Mongoose, Knex, EJS, Handlebars, Pug, axios, FastAPI, aiohttp, httpx,
 * Servlet, Struts, Micronaut, MyBatis, Nancy, CodeIgniter, CakePHP, Hanami, Poem, OpenSSL. Each vulnerable case ("rule") must
 * be reported; each "!rule" case is the safe counterpart that must stay quiet.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";
jest.setTimeout(300_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);
const ids = (file: string, content: string) =>
  runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: `t/${file}`, content }] })
    .files[0].indicators.filter(i => i.line != null && i.id !== "ai-model-attribution").map(i => i.id);

const EX = (body: string) => `const express = require('express');\nconst app = express();\n${body}\n`;
const FAST = (body: string) => `const fastify = require('fastify')();\n${body}\n`;
const PYF = (body: string) => `from fastapi import FastAPI\nimport sqlite3\napp = FastAPI()\n${body}\n`;
const AIO = (body: string) => `from aiohttp import web\nimport sqlite3\n${body}\n`;
const RB = (body: string) => `class DocsController < ApplicationController\n${body}\nend\n`;

const cases: Array<[string, string, string, string]> = [
  // ---- Next.js
  ["next api route sql", "pages/api/a.js", "sql-injection", `import db from '../../lib/db';\nexport default function handler(req, res) { db.query("SELECT * FROM u WHERE id = " + req.query.id); res.status(200).end(); }\n`],
  ["next api route bound query", "pages/api/b.js", "!sql-injection", `import db from '../../lib/db';\nexport default function handler(req, res) { db.query("SELECT * FROM u WHERE id = $1", [req.query.id]); res.status(200).end(); }\n`],
  ["next app router ssrf", "app/api/c/route.js", "ssrf", `export async function GET(request) { const u = new URL(request.url).searchParams.get('u'); const r = await fetch(u); return Response.json(await r.json()); }\n`],
  ["next app router constant fetch", "app/api/d/route.js", "!ssrf", `export async function GET(request) { const r = await fetch('https://api.example.com/x'); return Response.json(await r.json()); }\n`],
  // ---- Express
  ["express reflected xss", "e1.js", "xss", EX(`app.get('/a', (req, res) => { res.send('<h1>' + req.query.name + '</h1>'); });`)],
  ["express escaped output", "e2.js", "!xss", EX(`const escape = require('escape-html');\napp.get('/a', (req, res) => { res.send('<h1>' + escape(req.query.name) + '</h1>'); });`)],
  ["express constant redirect", "e3.js", "!open-redirect", EX(`app.get('/a', (req, res) => { res.redirect('/home'); });`)],
  ["express open redirect", "e4.js", "open-redirect", EX(`app.get('/a', (req, res) => { res.redirect(req.query.next); });`)],
  // ---- Fastify
  ["fastify sql", "f1.js", "sql-injection", FAST(`fastify.get('/a', async (request, reply) => { return db.query("SELECT * FROM u WHERE n = '" + request.query.n + "'"); });`)],
  ["fastify bound query", "f2.js", "!sql-injection", FAST(`fastify.get('/a', async (request, reply) => { return db.query("SELECT * FROM u WHERE n = $1", [request.query.n]); });`)],
  ["fastify ssrf", "f3.js", "ssrf", FAST(`fastify.get('/a', async (request, reply) => { const r = await fetch(request.query.u); return r.text(); });`)],
  // ---- NestJS
  ["nest controller sql", "n1.ts", "sql-injection", `import { Controller, Get, Query } from '@nestjs/common';\n@Controller('x') export class C { constructor(private db: any) {}\n  @Get() find(@Query('n') n: string) { return this.db.query("SELECT * FROM u WHERE n = '" + n + "'"); } }\n`],
  ["nest controller bound query", "n2.ts", "!sql-injection", `import { Controller, Get, Query } from '@nestjs/common';\n@Controller('x') export class C { constructor(private db: any) {}\n  @Get() find(@Query('n') n: string) { return this.db.query("SELECT * FROM u WHERE n = $1", [n]); } }\n`],
  // ---- Sequelize
  ["sequelize raw query", "s1.js", "sql-injection", EX(`app.get('/a', async (req, res) => { const r = await sequelize.query("SELECT * FROM users WHERE name = '" + req.query.name + "'"); res.json(r); });`)],
  ["sequelize replacements", "s2.js", "!sql-injection", EX(`app.get('/a', async (req, res) => { const r = await sequelize.query("SELECT * FROM users WHERE name = ?", { replacements: [req.query.name] }); res.json(r); });`)],
  // ---- Mongoose
  ["mongoose where operator", "m1.js", "nosql-injection", EX(`app.get('/a', async (req, res) => { res.json(await User.find({ $where: req.query.q })); });`)],
  ["mongoose body as filter", "m2.js", "nosql-injection", EX(`app.post('/a', async (req, res) => { res.json(await User.findOne(req.body)); });`)],
  ["mongoose string cast filter", "m3.js", "!nosql-injection", EX(`app.get('/a', async (req, res) => { res.json(await User.findOne({ name: String(req.query.name) })); });`)],
  // ---- Knex
  ["knex raw concat", "k1.js", "sql-injection", EX(`app.get('/a', async (req, res) => { res.json(await knex.raw("SELECT * FROM u WHERE id = " + req.params.id)); });`)],
  ["knex raw bindings", "k2.js", "!sql-injection", EX(`app.get('/a', async (req, res) => { res.json(await knex.raw("SELECT * FROM u WHERE id = ?", [req.params.id])); });`)],
  // ---- template engines
  ["ejs render request template", "t1.js", "ssti", EX(`const ejs = require('ejs');\napp.post('/a', (req, res) => { res.send(ejs.render(req.body.tpl, {})); });`)],
  ["ejs constant template", "t2.js", "!ssti", EX(`const ejs = require('ejs');\napp.post('/a', (req, res) => { res.send(ejs.render('<p><%= n %></p>', { n: req.body.n })); });`)],
  ["handlebars compile request template", "t3.js", "ssti", EX(`const Handlebars = require('handlebars');\napp.post('/a', (req, res) => { res.send(Handlebars.compile(req.body.tpl)({})); });`)],
  ["handlebars constant template", "t4.js", "!ssti", EX(`const Handlebars = require('handlebars');\napp.post('/a', (req, res) => { res.send(Handlebars.compile('<p>{{n}}</p>')({ n: req.body.n })); });`)],
  ["pug render request template", "t5.js", "ssti", EX(`const pug = require('pug');\napp.post('/a', (req, res) => { res.send(pug.render(req.body.tpl)); });`)],
  ["pug constant template", "t6.js", "!ssti", EX(`const pug = require('pug');\napp.post('/a', (req, res) => { res.send(pug.render('p= n', { n: req.body.n })); });`)],
  // ---- axios
  ["axios request url", "x1.js", "ssrf", EX(`const axios = require('axios');\napp.get('/a', async (req, res) => { const r = await axios.get(req.query.u); res.json(r.data); });`)],
  ["axios constant url", "x2.js", "!ssrf", EX(`const axios = require('axios');\napp.get('/a', async (req, res) => { const r = await axios.get('https://api.example.com/x', { params: { q: req.query.q } }); res.json(r.data); });`)],
  // ---- FastAPI / aiohttp / httpx
  ["fastapi query sql", "a1.py", "sql-injection", PYF(`@app.get("/a")\ndef a(n: str):\n    return sqlite3.connect("d.db").execute("SELECT * FROM u WHERE n = '" + n + "'").fetchall()`)],
  ["fastapi bound query", "a2.py", "!sql-injection", PYF(`@app.get("/a")\ndef a(n: str):\n    return sqlite3.connect("d.db").execute("SELECT * FROM u WHERE n = ?", (n,)).fetchall()`)],
  ["aiohttp query sql", "a3.py", "sql-injection", AIO(`async def h(request):\n    n = request.query.get("n")\n    return web.json_response(sqlite3.connect("d.db").execute("SELECT * FROM u WHERE n = '" + n + "'").fetchall())`)],
  ["aiohttp bound query", "a4.py", "!sql-injection", AIO(`async def h(request):\n    n = request.query.get("n")\n    return web.json_response(sqlite3.connect("d.db").execute("SELECT * FROM u WHERE n = ?", (n,)).fetchall())`)],
  ["httpx request url", "a5.py", "ssrf", `import httpx\nfrom flask import request\ndef a():\n    return httpx.get(request.args["u"]).text\n`],
  ["httpx constant url", "a6.py", "!ssrf", `import httpx\nfrom flask import request\ndef a():\n    return httpx.get("https://api.example.com/x", params={"q": request.args["q"]}).text\n`],
  // ---- Java: Servlet / Struts / Micronaut / MyBatis
  ["servlet statement concat", "A1.java", "sql-injection", `import javax.servlet.http.*;\nimport java.sql.*;\npublic class A1 extends HttpServlet { protected void doGet(HttpServletRequest r, HttpServletResponse s) throws Exception {\n  Connection c = DriverManager.getConnection("jdbc:h2:mem:");\n  c.createStatement().executeQuery("SELECT * FROM u WHERE n = '" + r.getParameter("n") + "'"); } }\n`],
  ["servlet prepared statement", "A2.java", "!sql-injection", `import javax.servlet.http.*;\nimport java.sql.*;\npublic class A2 extends HttpServlet { protected void doGet(HttpServletRequest r, HttpServletResponse s) throws Exception {\n  Connection c = DriverManager.getConnection("jdbc:h2:mem:");\n  PreparedStatement p = c.prepareStatement("SELECT * FROM u WHERE n = ?"); p.setString(1, r.getParameter("n")); p.executeQuery(); } }\n`],
  ["struts action command", "A3.java", "command-injection", `import com.opensymphony.xwork2.ActionSupport;\nimport org.apache.struts2.ServletActionContext;\npublic class A3 extends ActionSupport { public String execute() throws Exception {\n  Runtime.getRuntime().exec(ServletActionContext.getRequest().getParameter("c")); return SUCCESS; } }\n`],
  ["struts action constant command", "A4.java", "!command-injection", `import com.opensymphony.xwork2.ActionSupport;\nimport org.apache.struts2.ServletActionContext;\npublic class A4 extends ActionSupport { public String execute() throws Exception {\n  Runtime.getRuntime().exec("uptime"); return SUCCESS; } }\n`],
  ["micronaut query sql", "A5.java", "sql-injection", `import io.micronaut.http.annotation.*;\nimport java.sql.*;\n@Controller("/x") public class A5 { private final Connection c; A5(Connection c) { this.c = c; }\n  @Get("/a") public Object a(@QueryValue String n) throws Exception { return c.createStatement().executeQuery("SELECT * FROM u WHERE n = '" + n + "'"); } }\n`],
  ["micronaut prepared statement", "A6.java", "!sql-injection", `import io.micronaut.http.annotation.*;\nimport java.sql.*;\n@Controller("/x") public class A6 { private final Connection c; A6(Connection c) { this.c = c; }\n  @Get("/a") public Object a(@QueryValue String n) throws Exception { PreparedStatement p = c.prepareStatement("SELECT * FROM u WHERE n = ?"); p.setString(1, n); return p.executeQuery(); } }\n`],
  ["mybatis dollar interpolation", "A7.java", "sql-injection", `import org.apache.ibatis.annotations.*;\nimport org.springframework.web.bind.annotation.*;\npublic interface A7Mapper { @Select("SELECT * FROM u WHERE n = '\${n}'") Object find(@Param("n") String n); }\n`],
  ["mybatis hash binding", "A8.java", "!sql-injection", `import org.apache.ibatis.annotations.*;\npublic interface A8Mapper { @Select("SELECT * FROM u WHERE n = #{n}") Object find(@Param("n") String n); }\n`],
  // ---- C#: Nancy
  ["nancy query sql", "N1.cs", "sql-injection", `using Nancy;\nusing System.Data.SqlClient;\npublic class N1 : NancyModule { public N1(SqlConnection c) { Get("/a", args => { var cmd = new SqlCommand("SELECT * FROM u WHERE n = '" + this.Request.Query["n"] + "'", c); return cmd.ExecuteReader(); }); } }\n`],
  ["nancy parameterised sql", "N2.cs", "!sql-injection", `using Nancy;\nusing System.Data.SqlClient;\npublic class N2 : NancyModule { public N2(SqlConnection c) { Get("/a", args => { var cmd = new SqlCommand("SELECT * FROM u WHERE n = @n", c); cmd.Parameters.AddWithValue("@n", (string)this.Request.Query["n"]); return cmd.ExecuteReader(); }); } }\n`],
  // ---- PHP: CodeIgniter / CakePHP
  ["codeigniter input into query", "C1.php", "sql-injection", `<?php\nclass C1 extends CI_Controller { public function a() { $q = $this->db->query("SELECT * FROM u WHERE id = " . $this->input->get('id')); echo json_encode($q->result()); } }\n`],
  ["codeigniter bound query", "C2.php", "!sql-injection", `<?php\nclass C2 extends CI_Controller { public function a() { $q = $this->db->query("SELECT * FROM u WHERE id = ?", [$this->input->get('id')]); echo json_encode($q->result()); } }\n`],
  ["cakephp request into execute", "C3.php", "sql-injection", `<?php\nuse Cake\\Controller\\Controller;\nuse Cake\\Datasource\\ConnectionManager;\nclass C3 extends Controller { public function a() { $connection = ConnectionManager::get('default'); $r = $connection->execute("SELECT * FROM u WHERE id = " . $this->request->getQuery('id')); $this->set('r', $r->fetchAll()); } }\n`],
  ["cakephp bound execute", "C4.php", "!sql-injection", `<?php\nuse Cake\\Controller\\Controller;\nuse Cake\\Datasource\\ConnectionManager;\nclass C4 extends Controller { public function a() { $connection = ConnectionManager::get('default'); $r = $connection->execute("SELECT * FROM u WHERE id = :id", ['id' => $this->request->getQuery('id')]); $this->set('r', $r->fetchAll()); } }\n`],
  // ---- Ruby: Hanami
  ["hanami params into where string", "H1.rb", "sql-injection", `require 'hanami'\nmodule Web::Controllers::Docs\n  class Index\n    include Web::Action\n    def call(params)\n      DB.fetch("SELECT * FROM docs WHERE n = '#{params[:n]}'").all\n    end\n  end\nend\n`],
  ["hanami bound query", "H2.rb", "!sql-injection", `require 'hanami'\nmodule Web::Controllers::Docs\n  class Index\n    include Web::Action\n    def call(params)\n      DB[:docs].where(n: params[:n]).all\n    end\n  end\nend\n`],
  // ---- Rust: Poem
  ["poem query path traversal", "p1.rs", "path-traversal", `use poem::{handler, web::Query};\n#[handler]\nfn a(Query(q): Query<std::collections::HashMap<String, String>>) -> String { std::fs::read_to_string(&q["f"]).unwrap() }\n`],
  ["poem constant path", "p2.rs", "!path-traversal", `use poem::{handler, web::Query};\n#[handler]\nfn a(Query(_q): Query<std::collections::HashMap<String, String>>) -> String { std::fs::read_to_string("/etc/app.conf").unwrap() }\n`],
  // ---- C: OpenSSL
  ["openssl read into small buffer", "o1.c", "buffer-overflow", `#include <openssl/ssl.h>\n#include <string.h>\nvoid f(SSL *ssl){ char in[256]; char b[8]; SSL_read(ssl, in, 255); strcpy(b, in); }\n`],
  ["openssl bounded copy", "o2.c", "!buffer-overflow", `#include <openssl/ssl.h>\n#include <string.h>\nvoid f(SSL *ssl){ char in[256]; char b[8]; SSL_read(ssl, in, 255); strncpy(b, in, sizeof b - 1); b[7] = 0; }\n`],
];

it.each(cases)("%s", (_name, file, want, code) => {
  const neg = want.startsWith("!");
  const rule = neg ? want.slice(1) : want;
  const got = ids(file, code);
  if (neg) expect(got).not.toContain(rule); else expect(got).toContain(rule);
});
