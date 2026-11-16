/**
 * @jest-environment node
 *
 * Gaps found by scanning public vulnerable-by-design projects (vulnpy, DSVPWA, SAST-Benchmark-Suite, simplest-sast-vulnerable,
 * vulnerable-node-api, Goatlin, VulnerableCodes, JavaVulnerableLab, RailsGoat). Each vulnerable case must report the named
 * rule; each "!rule" case is the safe counterpart that must stay quiet. A case name says which project it came from.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";
jest.setTimeout(300_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);
const ids = (path: string, content: string) =>
  runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] })
    .files[0].indicators.filter(i => i.line != null && i.id !== "ai-model-attribution").map(i => i.id);

// [name, path, rule ("!rule" = must NOT report), content]
const cases: Array<[string, string, string, string]> = [
  // ── Python: a helper that returns a request value directly (vulnpy) ───────────────────────────────────────
  ["py helper returns request.GET.get directly", "t/a.py", "xss", `from django.http import HttpResponse
def _get(request):
    return request.GET.get("q", "")
def view(request):
    ui = _get(request)
    return HttpResponse("<p>" + ui + "</p>")
`],
  ["py helper returns GET or POST in if/else", "t/a.py", "xss", `from django.http import HttpResponse
def _get(request):
    if request.method == "GET":
        return request.GET.get("q", "")
    return request.POST.get("q", "")
def view(request):
    ui = _get(request)
    return HttpResponse("<p>" + ui + "</p>")
`],
  ["py helper returns a constant stays quiet", "t/a.py", "!xss", `from django.http import HttpResponse
def _get(request):
    return "fixed"
def view(request):
    ui = _get(request)
    return HttpResponse("<p>" + ui + "</p>")
`],
  ["py helper result escaped stays quiet", "t/a.py", "!xss", `import html
from django.http import HttpResponse
def _get(request):
    return request.GET.get("q", "")
def view(request):
    ui = html.escape(_get(request))
    return HttpResponse("<p>" + ui + "</p>")
`],
  ["flask view registered with add_url_rule returns request input", "t/a.py", "xss", `from flask import Blueprint, request
bp = Blueprint("v", __name__)
def make(name):
    def _view():
        ui = request.args.get("q", "")
        t = "<p>hi</p>"
        t += "<p>XSS: " + ui + "</p>"
        return t
    bp.add_url_rule("/x", "x", _view, methods=["GET"])
    return _view
`],
  ["flask view_func= registration returns request input", "t/a.py", "xss", `from flask import Flask, request
app = Flask(__name__)
def page():
    return "<p>" + request.args.get("q", "") + "</p>"
app.add_url_rule("/p", view_func=page)
`],
  ["flask helper that is never registered stays quiet", "t/a.py", "!xss", `from flask import request
def page():
    return "<p>" + request.args.get("q", "") + "</p>"
`],
  // ── Python: stdlib http.server handlers (DSVPWA) ─────────────────────────────────────────────────────────
  ["py http.server: query param into shell", "t/a.py", "command-injection", `import subprocess
import urllib.parse as urlparse
from http.server import BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        params = urlparse.parse_qs(urlparse.urlparse(self.path).query)
        domain = params.get('domain', ['x'])[0]
        subprocess.check_output(' '.join(['host', domain]), shell=True)
`],
  ["py http.server: query param written back unescaped", "t/a.py", "xss", `import urllib.parse as urlparse
from http.server import BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        params = urlparse.parse_qs(urlparse.urlparse(self.path).query)
        msg = params.get('msg', [''])[0]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(("<p>" + msg + "</p>").encode())
`],
  ["py http.server: query param into open()", "t/a.py", "path-traversal", `import urllib.parse as urlparse
from http.server import BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        params = urlparse.parse_qs(urlparse.urlparse(self.path).query)
        p = params.get('path', ['x'])[0]
        with open(p, 'rb') as f:
            self.wfile.write(f.read())
`],
  ["py http.server: request header into shell", "t/a.py", "command-injection", `import subprocess
from http.server import BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get('Host')
        subprocess.call('ping ' + host, shell=True)
`],
  ["py http.server: request body into pickle", "t/a.py", "insecure-deserialization", `import pickle
from http.server import BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers['Content-Length'])
        obj = pickle.loads(self.rfile.read(n))
`],
  ["py self.path on a class that is not an http.server handler stays quiet", "t/a.py", "!path-traversal", `class Job:
    def __init__(self, path):
        self.path = path
    def run(self):
        with open(self.path, 'rb') as f:
            return f.read()
`],
  ["py self.path in an http.server handler reaches open()", "t/a.py", "path-traversal", `from http.server import SimpleHTTPRequestHandler
class H(SimpleHTTPRequestHandler):
    def do_GET(self):
        with open(self.path.lstrip('/'), 'rb') as f:
            self.wfile.write(f.read())
`],
  ["py http.server: escaped output stays quiet", "t/a.py", "!xss", `import html
import urllib.parse as urlparse
from http.server import BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        params = urlparse.parse_qs(urlparse.urlparse(self.path).query)
        msg = params.get('msg', [''])[0]
        self.wfile.write(html.escape(msg).encode())
`],
  ["py http.server: validated domain stays quiet", "t/a.py", "!command-injection", `import re, subprocess
import urllib.parse as urlparse
from http.server import BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        params = urlparse.parse_qs(urlparse.urlparse(self.path).query)
        domain = params.get('domain', [''])[0]
        if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', domain):
            return
        subprocess.check_output(['host', domain], shell=False)
`],
  // ── Python: unsafe parser configuration is a finding without any taint (simplest-sast-vulnerable) ──────────
  ["py lxml resolve_entities=True", "t/a.py", "xxe", `import lxml.etree
def parse(s):
    p = lxml.etree.XMLParser(resolve_entities=True)
    return lxml.etree.fromstring(s, parser=p)
`],
  ["py sax external-general-entities on", "t/a.py", "xxe", `from xml.sax import make_parser
def parse(s, h):
    p = make_parser()
    p.setFeature("http://xml.org/sax/features/external-general-entities", True)
    p.setContentHandler(h)
    p.parseString(s)
`],
  ["py lxml resolve_entities=False stays quiet", "t/a.py", "!xxe", `import lxml.etree
def parse(s):
    p = lxml.etree.XMLParser(resolve_entities=False)
    return lxml.etree.fromstring(s, parser=p)
`],
  ["py sax external-general-entities off stays quiet", "t/a.py", "!xxe", `from xml.sax import make_parser
def parse(s, h):
    p = make_parser()
    p.setFeature("http://xml.org/sax/features/external-general-entities", False)
    p.setContentHandler(h)
    p.parseString(s)
`],
  ["py yaml.load with yaml.Loader", "t/a.py", "insecure-deserialization", `import yaml
def f(data):
    return yaml.load(data['yaml_data'], Loader=yaml.Loader)
`],
  ["py yaml.load with UnsafeLoader", "t/a.py", "insecure-deserialization", `import yaml
def f(s):
    return yaml.load(s, Loader=yaml.UnsafeLoader)
`],
  ["py yaml.load with SafeLoader stays quiet", "t/a.py", "!insecure-deserialization", `import yaml
def f(s):
    return yaml.load(s, Loader=yaml.SafeLoader)
`],
  ["py yaml.safe_load stays quiet", "t/a.py", "!insecure-deserialization", `import yaml
def f(s):
    return yaml.safe_load(s)
`],
  // ── Java: servlet/JSP forwards and deserialization (JavaVulnerableLab) ───────────────────────────────────
  ["java base64 state into ObjectInputStream", "t/A.java", "insecure-deserialization", `import javax.servlet.http.*;
import java.io.*;
import javax.xml.bind.DatatypeConverter;
public class A extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String state = request.getParameter("state");
    byte[] data = DatatypeConverter.parseBase64Binary(state);
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object o = ois.readObject();
  }
}
`],
  ["java request body into ObjectInputStream", "t/A.java", "insecure-deserialization", `import javax.servlet.http.*;
import java.io.*;
public class A extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
    Object o = ois.readObject();
  }
}
`],
  ["java getRequestDispatcher(param).forward", "t/A.java", "open-redirect|path-traversal|unvalidated-forward", `import javax.servlet.http.*;
public class A extends HttpServlet {
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String location = request.getParameter("location");
    getServletContext().getRequestDispatcher(location).forward(request, response);
  }
}
`],
  ["java forward to a constant stays quiet", "t/A.java", "!open-redirect|path-traversal|unvalidated-forward", `import javax.servlet.http.*;
public class A extends HttpServlet {
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    request.getRequestDispatcher("/home.jsp").forward(request, response);
  }
}
`],
  ["java upload keeps the client file name", "t/A.java", "insecure-file-upload", `import javax.servlet.http.*;
import java.io.File;
import java.util.List;
import org.apache.commons.fileupload.*;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
public class A extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
    List<FileItem> items = upload.parseRequest(request);
    for (FileItem item : items) {
      String fileName = new File(item.getName()).getName();
      File stored = new File("/var/www/uploads", fileName);
      item.write(stored);
    }
  }
}
`],
  ["java upload with a generated name stays quiet", "t/A.java", "!insecure-file-upload", `import javax.servlet.http.*;
import java.io.File;
import java.util.List;
import java.util.UUID;
import org.apache.commons.fileupload.*;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
public class A extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
    List<FileItem> items = upload.parseRequest(request);
    for (FileItem item : items) {
      String original = new File(item.getName()).getName();
      File stored = new File("/var/www/uploads", UUID.randomUUID().toString() + ".bin");
      item.write(stored);
    }
  }
}
`],
  // ── Express (vulnerable-node-api) ───────────────────────────────────────────────────────────────────────
  ["js md5(password) from the md5 package", "t/a.js", "weak-crypto", `const md5 = require('md5');
exports.login = (username, password) => { const hashed = md5(password); return hashed; };
`],
  ["js sha256 of a password stays quiet", "t/a.js", "!weak-crypto", `const crypto = require('crypto');
exports.login = (password) => crypto.createHash('sha256').update(password).digest('hex');
`],
  ["js whole req.body logged", "t/a.js", "pii-in-logs", `const express = require('express');
const app = express();
app.use((req, res, next) => { console.log('[REQUEST]', req.method, req.path, JSON.stringify(req.body)); next(); });
`],
  ["js one named req.body field logged is not the whole body", "t/a.js", "!pii-in-logs", `const express = require('express');
const app = express();
app.use((req, res, next) => { console.log('[REQUEST]', req.method, req.body.page); next(); });
`],
  ["express admin routes with no middleware beside protected ones", "t/routes.js", "api-endpoint-missing-auth", `const router = require('express').Router();
const controller = require('./controller');
router.post('/login', controller.login);
router.get('/users', controller.verifyToken, controller.getAllUsers);
router.get('/users/:id', controller.verifyToken, controller.getUser);
router.put('/users/:id', controller.verifyToken, controller.updateUser);
router.get('/products', controller.searchProducts);
router.post('/ping', controller.ping);
router.get('/file', controller.getFile);
router.get('/admin/dashboard', controller.adminDashboard);
module.exports = router;
`],
  ["express admin routes behind the same middleware stay quiet", "t/routes.js", "!api-endpoint-missing-auth", `const router = require('express').Router();
const controller = require('./controller');
router.post('/login', controller.login);
router.get('/users', controller.verifyToken, controller.getAllUsers);
router.get('/users/:id', controller.verifyToken, controller.getUser);
router.get('/admin/dashboard', controller.verifyToken, controller.adminDashboard);
module.exports = router;
`],
  // ── Rails (RailsGoat) ───────────────────────────────────────────────────────────────────────────────────
  ["rails protect_from_forgery commented out", "t/application_controller.rb", "csrf-protection-disabled", `class ApplicationController < ActionController::Base
  before_action :authenticated
  #protect_from_forgery with: :exception
end
`],
  ["rails protect_from_forgery live stays quiet", "t/application_controller.rb", "!csrf-protection-disabled", `class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end
`],
  ["rails a commented-out line while a live one exists stays quiet", "t/application_controller.rb", "!csrf-protection-disabled", `class ApplicationController < ActionController::Base
  # protect_from_forgery with: :null_session
  protect_from_forgery with: :exception
end
`],
  ["erb raw of a cookie", "t/layout.html.erb", "xss", `<style>
  body { font-size:<%= raw cookies[:font] %> !important;}
</style>
`],
  ["erb html_safe of a request parameter", "t/show.html.erb", "xss", `<h1>Hello <%= params[:name].html_safe %></h1>
`],
  ["erb html_safe of a user name", "t/header.html.erb", "xss", `<span class="text-dark"><%= current_user.first_name.html_safe %></span>
`],
  ["erb raw of a post body", "t/show.html.erb", "xss", `<div><%= raw @post.body %></div>
`],
  ["erb plain interpolation stays quiet", "t/header.html.erb", "!xss", `<span class="text-dark"><%= current_user.first_name %></span>
<div><%= @post.body %></div>
<style>body { font-size: <%= cookies[:font] %>; }</style>
`],
  ["erb raw wrapped in sanitize stays quiet", "t/show.html.erb", "!xss", `<div><%= raw sanitize(@post.body) %></div>
`],
  // ── Android (Goatlin) ───────────────────────────────────────────────────────────────────────────────────
  ["android exported provider with no permission", "app/src/main/AndroidManifest.xml", "android-exported-component", `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <application android:allowBackup="false">
        <provider
            android:name=".NotesProvider"
            android:authorities="com.x.notes"
            android:exported="true" />
    </application>
</manifest>
`],
  ["android exported provider guarded by a permission stays quiet", "app/src/main/AndroidManifest.xml", "!android-exported-component", `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <application android:allowBackup="false">
        <provider android:name=".NotesProvider" android:authorities="com.x.notes" android:exported="true" android:permission="com.x.READ_NOTES" />
    </application>
</manifest>
`],
  ["android exported launcher activity stays quiet", "app/src/main/AndroidManifest.xml", "!android-exported-component", `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <application android:allowBackup="false">
        <activity android:name=".HomeActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
`],
  ["android allowBackup=true", "app/src/main/AndroidManifest.xml", "android-backup-enabled", `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <application
        android:allowBackup="true"
        android:label="x">
    </application>
</manifest>
`],
  ["android allowBackup=false stays quiet", "app/src/main/AndroidManifest.xml", "!android-backup-enabled", `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <application android:allowBackup="false" android:label="x"></application>
</manifest>
`],
  ["android usesCleartextTraffic=true", "app/src/main/AndroidManifest.xml", "android-cleartext-traffic", `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <application android:allowBackup="false" android:usesCleartextTraffic="true"></application>
</manifest>
`],
  ["kotlin retrofit base url over http", "app/src/main/java/com/x/Client.kt", "android-cleartext-traffic", `class Client {
    fun build(hostname: String, port: Int) {
        val baseUrl: String = "http://\${hostname}:\${port}"
    }
}
`],
  ["kotlin retrofit base url over https stays quiet", "app/src/main/java/com/x/Client.kt", "!android-cleartext-traffic", `class Client {
    fun build(hostname: String) {
        val baseUrl: String = "https://\${hostname}"
    }
}
`],
  ["kotlin emulator loopback base url stays quiet", "app/src/main/java/com/x/Client.kt", "!android-cleartext-traffic", `class Client {
    val baseUrl: String = "http://10.0.2.2:8080"
}
`],
  // ── Groovy / Perl (VulnerableCodes) ─────────────────────────────────────────────────────────────────────
  ["groovy GString run as a command", "t/App.groovy", "command-injection", `class App {
    static void main(String[] args) {
        Spark.get("/exec", { req, res ->
            String command = req.queryParams("cmd")
            def process = "cmd /c \${command}".execute()
            return process.text
        })
    }
}
`],
  ["groovy command as a list stays quiet", "t/App.groovy", "!command-injection", `class App {
    static void main(String[] args) {
        def process = ["ls", "-l"].execute()
        println process.text
        def p2 = "ls -l".execute()
    }
}
`],
  ["groovy literal Sql.newInstance password", "t/App.groovy", "hardcoded-secret", `import groovy.sql.Sql
class App {
    static void main(String[] args) {
        Sql sql = Sql.newInstance("jdbc:mysql://localhost:3306/test", "root", "supersecretpassword", "com.mysql.cj.jdbc.Driver")
    }
}
`],
  ["groovy Sql.newInstance from the environment stays quiet", "t/App.groovy", "!hardcoded-secret", `import groovy.sql.Sql
class App {
    static void main(String[] args) {
        Sql sql = Sql.newInstance("jdbc:mysql://localhost:3306/test", System.getenv("DB_USER"), System.getenv("DB_PASS"), "com.mysql.cj.jdbc.Driver")
    }
}
`],
  ["groovy spark route returns the parameter inside html", "t/App.groovy", "xss", `class App {
    static void main(String[] args) {
        Spark.get("/greet", { req, res ->
            String name = req.queryParams("name")
            return "<h1>Hello, \${name}</h1>"
        })
    }
}
`],
  ["groovy spark route returning a constant stays quiet", "t/App.groovy", "!xss", `class App {
    static void main(String[] args) {
        Spark.get("/greet", { req, res ->
            String name = "world"
            return "<h1>Hello, \${name}</h1>"
        })
    }
}
`],
  ["perl cgi param printed inside html", "t/app.pl", "xss", `use CGI qw(:standard);
print header;
if (param('name')) {
    my $name = param('name');
    print "<h1>Hello, $name</h1>";
}
`],
  ["perl cgi param escaped stays quiet", "t/app.pl", "!xss", `use CGI qw(:standard escapeHTML);
print header;
if (param('name')) {
    my $name = param('name');
    print "<h1>Hello, " . escapeHTML($name) . "</h1>";
}
`],
  // ── JSP scriptlets (JavaVulnerableLab) ──────────────────────────────────────────────────────────────────
  ["jsp request bytes into ObjectInputStream", "t/preferences.jsp", "insecure-deserialization", `<%@ page import="java.io.*, javax.xml.bind.DatatypeConverter" %>
<%
    String state = request.getParameter("state");
    byte[] data = DatatypeConverter.parseBase64Binary(state.trim());
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object obj = ois.readObject();
%>
`],
  ["jsp ObjectInputStream over a local file stays quiet", "t/cache.jsp", "!insecure-deserialization", `<%@ page import="java.io.*" %>
<%
    ObjectInputStream ois = new ObjectInputStream(new FileInputStream(application.getRealPath("/WEB-INF/cache.bin")));
    Object obj = ois.readObject();
%>
`],
  ["jsp deserialization behind an ObjectInputFilter stays quiet", "t/preferences.jsp", "!insecure-deserialization", `<%@ page import="java.io.*" %>
<%
    byte[] data = request.getParameter("state").getBytes();
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    ois.setObjectInputFilter(java.io.ObjectInputFilter.Config.createFilter("com.x.Prefs;!*"));
    Object obj = ois.readObject();
%>
`],
  // ── documentation that quotes vulnerable code is not vulnerable code (vulnerable-node-api, RailsGoat) ──────
  ["readme quoting eval and mass assignment stays quiet", "README.md", "!eval-exec|mass-assignment|xss|redos|sql-injection|command-injection", `# Vulnerable API

| # | Description | File |
|---|-------------|------|
| 8 | Mass assignment via \`Object.assign(user, req.body)\` | controller.js |
| 10 | \`eval()\` called on user input | controller.js |
| 17 | \`new RegExp(req.query.search)\` | controller.js |

\`\`\`js
const result = eval(req.query.expression);
document.write(location.hash);
db.query("SELECT * FROM users WHERE id = " + req.params.id);
\`\`\`
`],
  ["a real key pasted into a readme is still reported", "README.md", "hardcoded-secret", `# Setup

Export the key before running:

    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REALKEY
    aws_key = "AKIAIOSFODNN7REALKEY"
`],
];

describe("one issue, one finding", () => {
  it("a Python XXE flow into a parser that is also configured unsafely is reported once, on the flow", () => {
    const got = ids("t/a.py", `from flask import request
from xml.sax import make_parser
def parse(h):
    p = make_parser()
    p.setFeature("http://xml.org/sax/features/external-general-entities", True)
    p.setContentHandler(h)
    p.parseString(request.data)
`).filter(i => i === "xxe");
    expect(got).toHaveLength(1);
  });
  it("an unsafely configured parser with no request data is still reported (config fact)", () => {
    const got = ids("t/a.py", `from xml.sax import make_parser
def parse(h, s):
    p = make_parser()
    p.setFeature("http://xml.org/sax/features/external-general-entities", True)
    p.setContentHandler(h)
    p.parseString(s)
`).filter(i => i === "xxe");
    expect(got).toHaveLength(1);
  });
});

describe("benchmark gaps", () => {
  it.each(cases)("%s", (_name, path, rule, content) => {
    const got = ids(path, content);
    if (rule.startsWith("!")) {
      for (const r of rule.slice(1).split("|")) expect(got).not.toContain(r);
    } else {
      expect(rule.split("|").some(r => got.includes(r))).toBe(true);
    }
  });
});
