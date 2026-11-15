/**
 * @jest-environment node
 *
 * CWE coverage across the framework models: each vulnerable case ("rule") must be reported, each "!rule" case is the safe
 * counterpart that must stay quiet. Rows follow the CWE matrix: SQLi / command / XSS / SSRF / path / deserialization / XXE /
 * code injection are covered per language by the *FrameworkSources suites; this file pins the cells those suites do not:
 * CWE-352 CSRF protection switched off (Spring 6 lambdas, Kotlin DSL, Rails, ASP.NET Core, Laravel, Symfony, Flask-WTF),
 * CWE-306 / CWE-798 authentication (anyRequest().permitAll(), a request password compared with a literal), CWE-190 an
 * attacker-chosen allocation size (Java, Kotlin, C#, Go, Rust), plus the C/C++ and Rust memory-safety rows.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";
jest.setTimeout(300_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);
const ids = (path: string, content: string) =>
  runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] })
    .files[0].indicators.filter(i => i.line != null && i.id !== "ai-model-attribution").map(i => i.id);
const RS = (body: string) => `use actix_web::{get, web, HttpResponse};\n#[get("/a")]\nasync fn a(q: web::Query<std::collections::HashMap<String,String>>) -> HttpResponse {\n${body}\n HttpResponse::Ok().finish() }\n`;
const SERV = (body: string) => `import javax.servlet.http.*;\nclass A extends HttpServlet { protected void doGet(HttpServletRequest r, HttpServletResponse s) throws Exception {\n${body}\n} }\n`;
const KT = (body: string) => `import org.springframework.web.bind.annotation.*\n@RestController class A { @GetMapping("/a") fun a(@RequestParam n: Int): Any {\n${body}\n return "" } }\n`;
const CS = (body: string) => `using Microsoft.AspNetCore.Mvc;\nusing System.Collections.Generic;\npublic class C : Controller { [HttpGet] public IActionResult A(int n) {\n${body}\n return Ok(); } }\n`;
const GO = (body: string) => `package main\nimport ("net/http";"strconv")\nfunc h(w http.ResponseWriter, r *http.Request) {\nn, _ := strconv.Atoi(r.URL.Query().Get("n"))\n${body}\n}\n`;
const cases: Array<[string, string, string, string]> = [
 ["c strcpy argv", "t/a.c", "buffer-overflow", `#include <string.h>\nint main(int argc, char **argv){ char b[8]; strcpy(b, argv[1]); return 0; }\n`],
 ["c malloc mul atoi", "t/a.c", "integer-overflow", `#include <stdlib.h>\nint main(int argc, char **argv){ int n = atoi(argv[1]); int *p = malloc(n * sizeof(int)); return p == 0; }\n`],
 ["c oob idx atoi", "t/a.c", "buffer-overflow", `#include <stdlib.h>\nint main(int argc, char **argv){ char b[8]; int i = atoi(argv[1]); b[i] = 1; return 0; }\n`],
 ["c uaf", "t/a.c", "use-after-free", `#include <stdlib.h>\nvoid f(){ char *p = malloc(8); free(p); p[0] = 1; }\n`],
 ["rust unsafe add", "t/a.rs", "buffer-overflow", RS(`let i: usize = q["i"].parse().unwrap(); let mut a = [0u8; 8]; unsafe { *a.as_mut_ptr().add(i) = 1; }`)],
 ["rust get_unchecked_mut", "t/a.rs", "buffer-overflow", RS(`let i: usize = q["i"].parse().unwrap(); let mut a = [0u8; 8]; unsafe { *a.get_unchecked_mut(i) = 1; }`)],
 ["rust set_len", "t/a.rs", "buffer-overflow", RS(`let n: usize = q["n"].parse().unwrap(); let mut v: Vec<u8> = Vec::with_capacity(8); unsafe { v.set_len(n); }`)],
 ["rust copy_nonoverlapping", "t/a.rs", "buffer-overflow", RS(`let n: usize = q["n"].parse().unwrap(); let src = [0u8; 64]; let mut a = [0u8; 8]; unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), a.as_mut_ptr(), n); }`)],
 ["rust as truncation", "t/a.rs", "arithmetic-overflow|integer-overflow", RS(`let n: u64 = q["n"].parse().unwrap(); let m = n as u8; let _ = m;`)],
 ["rust mul", "t/a.rs", "arithmetic-overflow|integer-overflow", RS(`let n: usize = q["n"].parse().unwrap(); let v = vec![0u8; n * 4]; let _ = v;`)],
 ["go make", "t/a.go", "integer-overflow", GO(`b := make([]byte, n); _ = b`)],
 ["go make mul", "t/a.go", "integer-overflow", GO(`b := make([]byte, n*4); _ = b`)],
 ["java byte[n]", "t/A.java", "integer-overflow", SERV(`int n = Integer.parseInt(r.getParameter("n")); byte[] b = new byte[n];`)],
 ["java byte[n*4]", "t/A.java", "integer-overflow", SERV(`int n = Integer.parseInt(r.getParameter("n")); byte[] b = new byte[n * 4];`)],
 ["java allocate", "t/A.java", "integer-overflow", SERV(`int n = Integer.parseInt(r.getParameter("n")); java.nio.ByteBuffer.allocate(n);`)],
 ["java ArrayList cap", "t/A.java", "integer-overflow", SERV(`int n = Integer.parseInt(r.getParameter("n")); new java.util.ArrayList<String>(n);`)],
 ["java StringBuilder cap", "t/A.java", "integer-overflow", SERV(`int n = Integer.parseInt(r.getParameter("n")); new StringBuilder(n);`)],
 ["java capped safe", "t/A.java", "!integer-overflow", SERV(`int n = Integer.parseInt(r.getParameter("n")); if (n < 0 || n > 4096) return; byte[] b = new byte[n];`)],
 ["java Math.min safe", "t/A.java", "!integer-overflow", SERV(`int n = Math.min(Integer.parseInt(r.getParameter("n")), 4096); byte[] b = new byte[n];`)],
 ["java const safe", "t/A.java", "!integer-overflow", `class A { void m() { byte[] b = new byte[1024]; } }\n`],
 ["kotlin ByteArray", "t/A.kt", "integer-overflow", KT(`val b = ByteArray(n)`)],
 ["kotlin ByteArray n*4", "t/A.kt", "integer-overflow", KT(`val b = ByteArray(n * 4)`)],
 ["kotlin ArrayList(n)", "t/A.kt", "integer-overflow", KT(`val l = ArrayList<String>(n)`)],
 ["kotlin capped safe", "t/A.kt", "!integer-overflow", KT(`if (n !in 0..4096) return ""\nval b = ByteArray(n)`)],
 ["kotlin coerceAtMost safe", "t/A.kt", "!integer-overflow", KT(`val b = ByteArray(n.coerceAtMost(4096))`)],
 ["cs new byte[n]", "t/a.cs", "integer-overflow", CS(`var b = new byte[n];`)],
 ["cs n*4", "t/a.cs", "integer-overflow", CS(`var b = new byte[n * 4];`)],
 ["cs List cap", "t/a.cs", "integer-overflow", CS(`var l = new List<int>(n);`)],
 ["cs Array.CreateInstance", "t/a.cs", "integer-overflow", CS(`var l = new int[n, n];`)],
 ["cs capped safe", "t/a.cs", "!integer-overflow", CS(`if (n < 0 || n > 4096) return BadRequest();\nvar b = new byte[n];`)],
 ["cs Math.Min safe", "t/a.cs", "!integer-overflow", CS(`var b = new byte[Math.Min(n, 4096)];`)],
 ["cs const safe", "t/a.cs", "!integer-overflow", CS(`var b = new byte[1024];`)],
 ["csrf spring lambda", "t/A.java", "csrf-protection-disabled", `import org.springframework.security.config.annotation.web.builders.HttpSecurity;\nclass A { void c(HttpSecurity http) throws Exception { http.csrf(c -> c.disable()); } }\n`],
 ["csrf spring methodref", "t/A.java", "csrf-protection-disabled", `import org.springframework.security.config.annotation.web.builders.HttpSecurity;\nimport org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;\nclass A { void c(HttpSecurity http) throws Exception { http.csrf(AbstractHttpConfigurer::disable); } }\n`],
 ["csrf kotlin dsl", "t/A.kt", "csrf-protection-disabled", `import org.springframework.security.config.annotation.web.builders.HttpSecurity\nfun c(http: HttpSecurity) { http.csrf { it.disable() } }\n`],
 ["csrf kotlin dsl2", "t/A.kt", "csrf-protection-disabled", `import org.springframework.security.config.web.servlet.invoke\nfun c(http: HttpSecurity) { http { csrf { disable() } } }\n`],
 ["csrf rails skip", "t/a.rb", "csrf-protection-disabled", `class C < ApplicationController\n  skip_before_action :verify_authenticity_token\n  def a; end\nend\n`],
 ["csrf rails skip_forgery", "t/a.rb", "csrf-protection-disabled", `class C < ApplicationController\n  skip_forgery_protection\nend\n`],
 ["csrf rails allow false", "t/a.rb", "csrf-protection-disabled", `Rails.application.configure do\n  config.action_controller.allow_forgery_protection = false\nend\n`],
 ["csrf cs ignore", "t/a.cs", "csrf-protection-disabled", `using Microsoft.AspNetCore.Mvc;\n[IgnoreAntiforgeryToken]\npublic class C : Controller { [HttpPost] public IActionResult A(string x) { return Ok(); } }\n`],
 ["csrf laravel except", "t/a.php", "csrf-protection-disabled", `<?php\nclass VerifyCsrfToken extends Middleware { protected $except = ['*']; }\n`],
 ["csrf symfony false", "t/a.php", "csrf-protection-disabled", `<?php\n$resolver->setDefaults(['csrf_protection' => false]);\n`],
 ["csrf flask exempt", "t/a.py", "csrf-protection-disabled", `from flask_wtf.csrf import CSRFProtect\ncsrf = CSRFProtect(app)\n@csrf.exempt\n@app.route('/x', methods=['POST'])\ndef x():\n    return 'ok'\n`],
 ["csrf flask wtf false", "t/a.py", "csrf-protection-disabled", `app.config['WTF_CSRF_ENABLED'] = False\n`],
 ["csrf express safe", "t/a.js", "!csrf-protection-disabled", `const csrf = require('csurf');\napp.use(csrf({ cookie: true }));\n`],
 ["csrf spring safe", "t/A.java", "!csrf-protection-disabled", `import org.springframework.security.config.annotation.web.builders.HttpSecurity;\nclass A { void c(HttpSecurity http) throws Exception { http.csrf(c -> c.csrfTokenRepository(null)); } }\n`],
 ["csrf rails safe", "t/a.rb", "!csrf-protection-disabled", `class C < ApplicationController\n  protect_from_forgery with: :exception\nend\n`],
 ["authn permitAll any", "t/A.java", "authentication-disabled", `import org.springframework.security.config.annotation.web.builders.HttpSecurity;\nclass A { void c(HttpSecurity http) throws Exception { http.authorizeHttpRequests(a -> a.anyRequest().permitAll()); } }\n`],
 ["authn permitAll old", "t/A.java", "authentication-disabled", `import org.springframework.security.config.annotation.web.builders.HttpSecurity;\nclass A { void c(HttpSecurity http) throws Exception { http.authorizeRequests().anyRequest().permitAll(); } }\n`],
 ["authn permitAll login safe", "t/A.java", "!authentication-disabled", `import org.springframework.security.config.annotation.web.builders.HttpSecurity;\nclass A { void c(HttpSecurity http) throws Exception { http.authorizeHttpRequests(a -> a.requestMatchers("/login").permitAll().anyRequest().authenticated()); } }\n`],
 ["authn kotlin permitAll", "t/A.kt", "authentication-disabled", `import org.springframework.security.config.annotation.web.builders.HttpSecurity\nfun c(http: HttpSecurity) { http.authorizeHttpRequests { it.anyRequest().permitAll() } }\n`],
 ["authn pw compare py", "t/a.py", "hardcoded-secret|hardcoded-credential-check", `from flask import request\ndef login():\n    if request.form['password'] == 'admin123':\n        return 'ok'\n`],
 ["authn pw compare js", "t/a.js", "hardcoded-secret|hardcoded-credential-check", `app.post('/login', (req, res) => { if (req.body.password === 'admin123') { res.send('ok'); } });\n`],
 ["authn pw compare java", "t/A.java", "hardcoded-secret|hardcoded-credential-check", `import javax.servlet.http.*;\nclass A extends HttpServlet { protected void doPost(HttpServletRequest r, HttpServletResponse s) { if (r.getParameter("password").equals("admin123")) { } } }\n`],
 ["authn pw compare php", "t/a.php", "hardcoded-secret|hardcoded-credential-check", `<?php\nif ($_POST['password'] == 'admin123') { echo 'ok'; }\n`],
 ["authn pw compare go", "t/a.go", "hardcoded-secret|hardcoded-credential-check", `package main\nimport "net/http"\nfunc h(w http.ResponseWriter, r *http.Request) { if r.FormValue("password") == "admin123" { w.Write([]byte("ok")) } }\n`],
 ["authn pw compare cs", "t/a.cs", "hardcoded-secret|hardcoded-credential-check", `using Microsoft.AspNetCore.Mvc;\npublic class C : Controller { [HttpPost] public IActionResult L(string password) { if (password == "admin123") return Ok(); return Unauthorized(); } }\n`],
 ["authn pw compare rb", "t/a.rb", "hardcoded-secret|hardcoded-credential-check", `class C < ApplicationController\n  def login\n    render plain: 'ok' if params[:password] == 'admin123'\n  end\nend\n`],
 ["authn pw env safe", "t/a.py", "!hardcoded-credential-check", `import os\nfrom flask import request\ndef login():\n    if request.form['password'] == os.environ['ADMIN_PW']:\n        return 'ok'\n`],

 // ---- CWE-611 XXE
 ["xxe php simplexml", "t/a.php", "xxe", `<?php\n$x = simplexml_load_string($_POST['d'], 'SimpleXMLElement', LIBXML_NOENT);\n`],
 ["xxe php DOMDocument", "t/a.php", "xxe", `<?php\n$d = new DOMDocument();\n$d->loadXML($_POST['d'], LIBXML_NOENT | LIBXML_DTDLOAD);\n`],
 ["xxe cs XmlDocument", "t/a.cs", "xxe", `using System.Xml;\nclass C { void M(string s){ var d = new XmlDocument(); d.LoadXml(s); } }\n`],
 ["xxe cs DtdProcessing.Parse", "t/a.cs", "xxe", `using System.Xml;\nclass C { void M(string s){ var st = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse }; XmlReader.Create(new System.IO.StringReader(s), st); } }\n`],
 ["xxe cs XDocument safe", "t/a.cs", "!xxe", `using System.Xml.Linq;\nclass C { void M(string s){ var d = XDocument.Parse(s); } }\n`],
 ["xxe py lxml resolve_entities", "t/a.py", "xxe", `from lxml import etree\nfrom flask import request\ndef f():\n    p = etree.XMLParser(resolve_entities=True)\n    return etree.fromstring(request.data, p)\n`],
 ["xxe java DocumentBuilder", "t/A.java", "xxe", `import javax.xml.parsers.*;\nclass A { void m(java.io.InputStream in) throws Exception { DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); f.newDocumentBuilder().parse(in); } }\n`],
 // ---- CWE-94 code injection
 ["cwe94 js new Function", "t/a.js", "eval-exec", `app.get('/x', (req, res) => { const f = new Function(req.query.c); res.send(String(f())); });\n`],
 ["cwe94 js vm", "t/a.js", "eval-exec", `const vm = require('vm');\napp.get('/x', (req, res) => { vm.runInNewContext(req.query.c); });\n`],
 ["cwe94 py exec", "t/a.py", "eval-exec", `from flask import request\ndef f():\n    exec(request.args['c'])\n`],
 ["cwe94 php assert", "t/a.php", "eval-exec", `<?php\nassert($_GET['c']);\n`],
 ["cwe94 php preg_replace /e", "t/a.php", "eval-exec", `<?php\npreg_replace('/a/e', $_GET['c'], 'a');\n`],
 ["cwe94 ruby instance_eval", "t/a.rb", "eval-exec", `class C < ApplicationController\n  def a\n    instance_eval(params[:c])\n  end\nend\n`],
 // ---- CWE-352 CSRF (state change on cookie / session auth)
 ["csrf php session state change", "t/a.php", "csrf", `<?php\nsession_start();\nfunction del() { global $db; if ($_SESSION['u']) { $db->query("DELETE FROM a WHERE id=1"); } }\n`],
 ["csrf go cookie state change", "t/a.go", "csrf", `package main\nimport "net/http"\nfunc h(w http.ResponseWriter, r *http.Request) { c, _ := r.Cookie("sid"); if c != nil { db.Exec("UPDATE a SET b=1") } }\n`],
 ["csrf django csrf_exempt", "t/a.py", "csrf-protection-disabled", `from django.views.decorators.csrf import csrf_exempt\n@csrf_exempt\ndef t(request):\n    request.user.delete()\n    return None\n`],
 ["csrf spring classic disable", "t/A.java", "csrf-protection-disabled", `import org.springframework.security.config.annotation.web.builders.HttpSecurity;\nclass A { void c(HttpSecurity http) throws Exception { http.csrf().disable(); } }\n`],
 ["csrf rails null_session", "t/a.rb", "csrf-protection-disabled", `class C < ApplicationController\n  protect_from_forgery with: :null_session\nend\n`],
 // ---- CWE-862 / CWE-639 authorization
 ["authz express delete by id", "t/a.js", "bola-missing-ownership-check|idor", `const express = require('express');\nconst app = express();\napp.delete('/users/:id', async (req, res) => { await User.findByIdAndDelete(req.params.id); res.send('ok'); });\n`],
 ["authz spring findById", "t/A.java", "bola-missing-ownership-check|idor", `import org.springframework.web.bind.annotation.*;\n@RestController class A { @DeleteMapping("/doc/{id}") public void d(@PathVariable Long id) { repo.deleteById(id); } }\n`],
 ["authn jwt decode without verify", "t/a.js", "jwt-none-alg", `const jwt = require('jsonwebtoken');\napp.get('/x', (req, res) => { const p = jwt.decode(req.headers.authorization); res.json(p); });\n`],
 // ---- CWE-120 / CWE-416 / CWE-787 (C / C++ / Rust unsafe)
 ["cwe416 cpp delete then use", "t/a.cpp", "use-after-free", `void f(){ int *p = new int(1); delete p; *p = 2; }\n`],
 ["cwe787 loop off by one", "t/a.c", "buffer-overflow", `void f(){ char b[8]; for (int i = 0; i <= 8; i++) b[i] = 0; }\n`],
 ["cwe120 strcpy const buffer safe", "t/a.c", "!buffer-overflow", `#include <string.h>\nvoid f(){ char b[16]; strcpy(b, "hello"); }\n`],
 ["rust copy_nonoverlapping len", "t/a.rs", "buffer-overflow", RS(`let n: usize = q["n"].parse().unwrap(); let src = [0u8; 64]; let mut a = [0u8; 8]; unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), a.as_mut_ptr(), n); }`)],
 // ---- pins for the guards and secondary patterns
 ["authn kotlin authorize(anyRequest, permitAll)", "t/A.kt", "authentication-disabled", `import org.springframework.security.config.web.servlet.invoke\nfun c(http: HttpSecurity) { http { authorize(anyRequest, permitAll) } }\n`],
 ["authn secret read from env vs literal safe", "t/a.js", "!hardcoded-credential-check", `const ok = process.env.APP_SECRET === "abcd1234efgh";\n`],
 ["authn placeholder literal safe", "t/a.js", "!hardcoded-credential-check", `if (password === "changeme-placeholder") { warn("set a real password"); }\n`],
 ["kotlin if n > cap return safe", "t/A.kt", "!integer-overflow", KT(`if (n > 4096) return ""\nval b = ByteArray(n)`)],
 ["kotlin if n < cap safe", "t/A.kt", "!integer-overflow", KT(`if (n < 4096) { val b = ByteArray(n) }`)],
 ["kotlin if-expression bound safe", "t/A.kt", "!integer-overflow", KT(`val b = if (n in 0..4096) ByteArray(n) else ByteArray(0)`)],
 ["kotlin uncapped inside wrong branch", "t/A.kt", "integer-overflow", KT(`if (n > 4096) { val b = ByteArray(n) }`)],
 ["cs Array.CreateInstance", "t/a.cs", "integer-overflow", CS(`var a = Array.CreateInstance(typeof(int), n);`)],
 ["cs ArrayPool Rent", "t/a.cs", "integer-overflow", CS(`var a = System.Buffers.ArrayPool<byte>.Shared.Rent(n);`)],
 ["cs PadLeft", "t/a.cs", "integer-overflow", CS(`var a = "x".PadLeft(n);`)],
 ["cs string ctor count", "t/a.cs", "integer-overflow", CS(`var a = new string('x', n);`)],
 ["cs Math.Min capped safe", "t/a.cs", "!integer-overflow", CS(`var a = ArrayPool<byte>.Shared.Rent(Math.Min(n, 4096));`)],
 ["java uncapped inside wrong branch", "t/A.java", "integer-overflow", SERV(`int n = Integer.parseInt(r.getParameter("n")); if (n > 4096) { byte[] b = new byte[n]; }`)],
 ["java tainted string into StringBuilder safe", "t/A.java", "!integer-overflow", SERV(`String s = r.getParameter("n"); StringBuilder sb = new StringBuilder(s);`)],
 ["java tainted bytes into ByteArrayOutputStream safe", "t/A.java", "!integer-overflow", SERV(`byte[] d = r.getParameter("n").getBytes(); java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream(d.length);`)],
 ["cs tainted bytes into MemoryStream safe", "t/a.cs", "!integer-overflow", `using Microsoft.AspNetCore.Mvc;\nusing System.IO;\npublic class C : Controller { [HttpPost] public IActionResult A([FromBody] string state) { var m = new MemoryStream(System.Convert.FromBase64String(state)); return Ok(); } }\n`],
 ["kotlin if-expression value bounded", "t/A.kt", "!integer-overflow", KT(`val m = if (n < 4096) n else 0
val b = ByteArray(m)`)],
 ["kotlin if-expression value unbounded branch", "t/A.kt", "integer-overflow", KT(`val m = if (n > 4096) n else 0
val b = ByteArray(m)`)],
 ["kotlin minOf capped safe", "t/A.kt", "!integer-overflow", KT(`val b = ByteArray(minOf(n, 4096))`)],
 ["kotlin kotlin.math.min capped safe", "t/A.kt", "!integer-overflow", KT(`val b = ByteArray(kotlin.math.min(n, 4096))`)],
 ["kotlin minOf two request values", "t/A.kt", "integer-overflow", KT(`val b = ByteArray(minOf(n, n * 2))`)],
];

it.each(cases)("%s", (_name, path, want, code) => {
  const neg = want.startsWith("!");
  const any = (neg ? want.slice(1) : want).split("|");
  const got = ids(path, code);
  if (neg) expect(got.filter(g => any.includes(g))).toEqual([]);
  else expect(got.some(g => any.includes(g))).toBe(true);
});
