import { scanAstTaint } from "@/lib/astTaint";
import { analyzeFile } from "@/lib/scanner";
import { scanAstTaintPython, warmPythonTaintEngine } from "@/lib/astTaintPython";
import { scanAstTaintJava, parseJavaSource } from "@/lib/astTaintJava";
import { scanAstTaintCSharp, parseCSharpSourceSync, warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { scanAstTaintGo, warmGoTaintEngine } from "@/lib/astTaintGo";
import { scanAstTaintPHP, parsePhpSourceSync, warmPhpTaintEngine } from "@/lib/astTaintPHP";

beforeAll(async () => {
  await warmPythonTaintEngine(); await warmCSharpTaintEngine(); await warmGoTaintEngine(); await warmPhpTaintEngine();
}, 60000);

// Sink/argument precision: a sink is reported only when taint reaches the argument that can actually be
// exploited -- the URL of a request (not its body), the path of a file write (not its contents), the program
// or shell string of a command (not an argv array passed without a shell), the location of a redirect (not
// its status code).

const ids = (body: string) =>
  scanAstTaint(`const cp = require("child_process");\nconst fs = require("fs");\nconst axios = require("axios");\napp.post("/x", (req, res) => {\n${body}\n});\n`, "x.js").map(f => f.id);

describe("JS: only the exploitable argument of a sink is checked", () => {
  it("HTTP clients: the URL, not the request body or config", () => {
    expect(ids(`fetch("https://api.example.com/items", { method: "POST", body: req.body.data });`)).not.toContain("ssrf");
    expect(ids(`axios.post("https://api.example.com/items", req.body.data);`)).not.toContain("ssrf");
    expect(ids(`axios.post("https://api.example.com/items", { q: req.query.q }, { timeout: 5 });`)).not.toContain("ssrf");
    expect(ids(`fetch(req.query.url);`)).toContain("ssrf");
    expect(ids(`axios.post(req.body.url, { a: 1 });`)).toContain("ssrf");
    expect(ids(`axios({ method: "get", url: req.query.url });`)).toContain("ssrf");
    expect(ids(`axios({ method: "post", url: "https://api.example.com", data: req.body });`)).not.toContain("ssrf");
    // ...but a proxy also decides where the request goes
    expect(ids(`axios.get("https://api.example.com/items", { proxy: { host: req.query.h, port: 80 } });`)).toContain("ssrf");
  });

  it("file APIs: the path, not the data written", () => {
    expect(ids(`fs.writeFileSync("/var/app/out.txt", req.body.text);`)).not.toContain("path-traversal");
    expect(ids(`fs.writeFile("/var/app/out.txt", req.body.text, () => {});`)).not.toContain("path-traversal");
    expect(ids(`fs.writeFileSync("/var/app/" + req.body.name, "x");`)).toContain("path-traversal");
    expect(ids(`fs.readFile(req.query.p, "utf8", () => {});`)).toContain("path-traversal");
  });

  it("commands: the program / shell string, not an argv array run without a shell", () => {
    expect(ids(`cp.execFile("convert", ["--", req.body.file, "out.png"]);`)).not.toContain("command-injection");
    expect(ids(`cp.spawn("git", ["log", "--", req.query.ref]);`)).not.toContain("command-injection");
    expect(ids(`cp.spawn("sh", ["-c", req.query.cmd], { shell: true });`)).toContain("command-injection");
    expect(ids(`cp.spawn(req.query.bin, ["--version"]);`)).toContain("command-injection");
    expect(ids(`cp.exec("ls " + req.query.dir);`)).toContain("command-injection");
    expect(ids(`cp.exec("ls", { cwd: req.query.dir });`)).not.toContain("command-injection");
  });

  it("redirects: the location, not the status code", () => {
    expect(ids(`res.redirect(req.query.code, "/home");`)).not.toContain("open-redirect");
    expect(ids(`res.redirect(301, req.query.next);`)).toContain("open-redirect");
    expect(ids(`res.redirect(req.query.next);`)).toContain("open-redirect");
  });

  it("responses: the body written, not extra arguments", () => {
    expect(ids(`res.end("done", req.query.enc);`)).not.toContain("xss");
    expect(ids(`res.send(req.query.name);`)).toContain("xss");
  });
});

const pyIds = (body: string) =>
  scanAstTaintPython(`import os, subprocess, requests, shutil, urllib.request\nfrom flask import request, redirect, render_template_string\n@app.route("/x")\ndef v():\n    x = request.args.get("x")\n${body.split("\n").map(l => "    " + l).join("\n")}\n`, "v.py").map(f => f.id);

const javaIds = (body: string) => {
  const src = `@RestController public class C {\n  @GetMapping("/x") public void a(@RequestParam String x) throws Exception {\n    ${body}\n  }\n}\n`;
  return scanAstTaintJava(src, "C.java", parseJavaSource(src)!).map(f => f.id);
};

describe("Java: only the exploitable argument of a sink is checked", () => {
  it("SQL: the query text, not bound parameters on the statement", () => {
    expect(javaIds(`PreparedStatement ps = conn.prepareStatement("SELECT * FROM u WHERE id = ?"); ps.setString(1, x); ps.executeQuery();`)).not.toContain("sql-injection");
    expect(javaIds(`jdbcTemplate.query("SELECT * FROM u WHERE id = ?", mapper, x);`)).not.toContain("sql-injection");
    // execute(sql, columnNames): the second argument names generated-key columns, it is not SQL text
    expect(javaIds(`stmt.execute("DELETE FROM t WHERE a = 1", new String[] { x });`)).not.toContain("sql-injection");
    expect(javaIds(`stmt.executeQuery("SELECT * FROM u WHERE id = " + x);`)).toContain("sql-injection");
    expect(javaIds(`jdbcTemplate.query("SELECT * FROM u WHERE id = " + x, mapper);`)).toContain("sql-injection");
  });

  it("HTTP clients: the URL, not the request body", () => {
    expect(javaIds(`restTemplate.postForObject("https://api.example.com/items", x, String.class);`)).not.toContain("ssrf");
    expect(javaIds(`restTemplate.getForObject(x, String.class);`)).toContain("ssrf");
  });

  it("files: the path, not the bytes written or open options", () => {
    expect(javaIds(`Files.write(Paths.get("/var/app/out.txt"), x.getBytes());`)).not.toContain("path-traversal");
    expect(javaIds(`Files.writeString(Paths.get("/var/app/out.txt"), x);`)).not.toContain("path-traversal");
    expect(javaIds(`new RandomAccessFile("/var/app/out.txt", x);`)).not.toContain("path-traversal");
    expect(javaIds(`Files.readString(Paths.get("/var/app/" + x));`)).toContain("path-traversal");
    expect(javaIds(`new FileInputStream(x);`)).toContain("path-traversal");
  });

  it("commands: the program or shell string, not argv elements run without a shell", () => {
    expect(javaIds(`new ProcessBuilder("git", "log", "--", x).start();`)).toEqual([]);
    expect(javaIds(`new ProcessBuilder("git", "log", x).start();`)).toEqual(["argument-injection"]);
    expect(javaIds(`new ProcessBuilder("sh", "-c", x).start();`)).toContain("command-injection");
    expect(javaIds(`new ProcessBuilder(x, "--version").start();`)).toContain("command-injection");
    expect(javaIds(`Runtime.getRuntime().exec("uptime", null, new File(x));`)).not.toContain("command-injection");
    expect(javaIds(`Runtime.getRuntime().exec("ls " + x);`)).toContain("command-injection");
  });
});

const csIds = (body: string) => {
  const src = `[ApiController] public class C : ControllerBase {\n  [HttpGet] public async Task<IActionResult> A([FromQuery] string x) {\n    ${body}\n    return Ok();\n  }\n}\n`;
  return scanAstTaintCSharp(src, "C.cs", parseCSharpSourceSync(src, "C.cs")!).map(f => f.id);
};

describe("C#: only the exploitable argument of a sink is checked", () => {
  it("EF raw SQL: the SQL text, not the parameters array", () => {
    expect(csIds(`db.Users.FromSqlRaw("SELECT * FROM u WHERE id = {0}", x).ToList();`)).not.toContain("sql-injection");
    expect(csIds(`db.Database.ExecuteSqlRaw("DELETE FROM u WHERE id = {0}", x);`)).not.toContain("sql-injection");
    expect(csIds(`db.Users.FromSqlRaw("SELECT * FROM u WHERE id = " + x).ToList();`)).toContain("sql-injection");
  });

  it("HTTP clients: the URL, not the content", () => {
    expect(csIds(`await client.PostAsync("https://api.example.com/items", new StringContent(x));`)).not.toContain("ssrf");
    expect(csIds(`new WebClient().UploadString("https://api.example.com/items", x);`)).not.toContain("ssrf");
    expect(csIds(`await client.GetStringAsync(x);`)).toContain("ssrf");
  });

  it("files: the path(s), not the contents or content type", () => {
    expect(csIds(`System.IO.File.WriteAllText("/var/app/out.txt", x);`)).not.toContain("path-traversal");
    expect(csIds(`return PhysicalFile("/var/app/report.pdf", x);`)).not.toContain("path-traversal");
    expect(csIds(`System.IO.File.ReadAllText("/var/app/" + x);`)).toContain("path-traversal");
    expect(csIds(`System.IO.File.Copy("/var/app/a.txt", x);`)).toContain("path-traversal");
  });

  it("processes: the program (or a shell's command), arguments are argument injection", () => {
    expect(csIds(`Process.Start("git", "log " + x);`)).toEqual(["argument-injection"]);
    expect(csIds(`Process.Start("cmd.exe", "/c dir " + x);`)).toContain("command-injection");
    expect(csIds(`Process.Start(x);`)).toContain("command-injection");
    expect(csIds(`var psi = new ProcessStartInfo("git", "log " + x);`)).toEqual(["argument-injection"]);
    expect(csIds(`var psi = new ProcessStartInfo(x);`)).toContain("command-injection");
  });
});

const goIds = (body: string) =>
  scanAstTaintGo(`package main\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tx := r.URL.Query().Get("x")\n\t${body}\n}\n`, "h.go").map(f => f.id);

describe("Go: only the exploitable argument of a sink is checked", () => {
  it("HTTP clients: the URL, not the content type, body or form", () => {
    expect(goIds(`http.Post("https://api.example.com/items", "text/plain", strings.NewReader(x))`)).not.toContain("ssrf");
    expect(goIds(`http.PostForm("https://api.example.com/items", url.Values{"q": {x}})`)).not.toContain("ssrf");
    expect(goIds(`http.Get(x)`)).toContain("ssrf");
  });

  it("commands: the program (or a shell's command), other argv elements are argument injection", () => {
    expect(goIds(`exec.Command("git", "log", "--", x).Run()`)).toEqual([]);
    expect(goIds(`exec.Command("git", "log", x).Run()`)).toEqual(["argument-injection"]);
    expect(goIds(`exec.CommandContext(ctx, "git", "log", x).Run()`)).toEqual(["argument-injection"]);
    expect(goIds(`exec.Command("sh", "-c", "ls "+x).Run()`)).toContain("command-injection");
    expect(goIds(`exec.Command(x).Run()`)).toContain("command-injection");
    // CommandContext's first argument is the context, the program comes second
    expect(goIds(`exec.CommandContext(ctx, x).Run()`)).toContain("command-injection");
  });
});

describe("the full scanner agrees: the regex layer's line-level duplicate is dropped where the engine proved the sink safe", () => {
  const scanIds = (path: string, src: string) => analyzeFile(path, src).indicators.map(i => i.id);
  it("Go exec.Command without a shell, Java Files.write data and ProcessBuilder after --", () => {
    const go = scanIds("h.go", `package main\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tx := r.URL.Query().Get("x")\n\texec.Command("ping", x).Run()\n}\n`);
    expect(go).toContain("argument-injection");
    expect(go).not.toContain("command-injection");
    const java = (b: string) => scanIds("C.java", `@RestController public class C {\n  @GetMapping("/x") public void a(@RequestParam String x) throws Exception {\n    ${b}\n  }\n}\n`);
    expect(java(`Files.write(Paths.get("/var/app/out.txt"), x.getBytes());`)).not.toContain("path-traversal");
    expect(java(`new ProcessBuilder("git", "log", "--", x).start();`)).not.toContain("command-injection");
  });
});

const phpIds = (body: string) => {
  const src = `<?php\n$x = $_GET['x'];\n${body}\n`;
  return scanAstTaintPHP(src, "a.php", parsePhpSourceSync(src, "a.php")!).map(f => f.id);
};

describe("PHP: only the exploitable argument of a sink is checked", () => {
  it("cURL: only options that choose the destination", () => {
    expect(phpIds(`curl_setopt($ch, CURLOPT_POSTFIELDS, $x);`)).not.toContain("ssrf");
    expect(phpIds(`curl_setopt($ch, CURLOPT_HTTPHEADER, ["X-Id: " . $x]);`)).not.toContain("ssrf");
    expect(phpIds(`curl_setopt($ch, CURLOPT_URL, $x);`)).toContain("ssrf");
    expect(phpIds(`curl_setopt($ch, CURLOPT_PROXY, $x);`)).toContain("ssrf");
    expect(phpIds(`$curl->setopt(CURLOPT_POSTFIELDS, $x);`)).not.toContain("ssrf");
    expect(phpIds(`$curl->setopt(CURLOPT_URL, $x);`)).toContain("ssrf");
  });

  it("files: the path, not the data written or the mode", () => {
    expect(phpIds(`file_put_contents("/var/app/out.txt", $x);`)).not.toContain("path-traversal");
    expect(phpIds(`fopen("/var/app/out.txt", $x);`)).not.toContain("path-traversal");
    expect(phpIds(`file_put_contents("/var/app/" . $x, "data");`)).toContain("path-traversal");
    expect(phpIds(`readfile($x);`)).toContain("path-traversal");
  });

  it("commands, headers and SQL: the command / header line / query text only", () => {
    expect(phpIds(`exec("uptime", $x);`)).not.toContain("command-injection");
    expect(phpIds(`exec("ls " . $x);`)).toContain("command-injection");
    expect(phpIds(`header("X-Frame-Options: DENY", true, $x);`)).toEqual([]);
    expect(phpIds(`header("Location: " . $x);`)).toContain("open-redirect");
    expect(phpIds(`$pdo->query("SELECT * FROM u", $x);`)).not.toContain("sql-injection");
    expect(phpIds(`$pdo->query("SELECT * FROM u WHERE id = " . $x);`)).toContain("sql-injection");
    expect(phpIds(`mysqli_query($conn, "SELECT * FROM u WHERE id = " . $x);`)).toContain("sql-injection");
  });
});

describe("Python: only the exploitable argument of a sink is checked", () => {
  it("HTTP clients: the URL, not params/data/json/headers", () => {
    expect(pyIds(`requests.post("https://api.example.com/items", data=x)`)).not.toContain("ssrf");
    expect(pyIds(`requests.get("https://api.example.com/items", params={"q": x}, headers={"X": x})`)).not.toContain("ssrf");
    expect(pyIds(`requests.request("POST", "https://api.example.com", json={"a": x})`)).not.toContain("ssrf");
    expect(pyIds(`urllib.request.urlopen("https://api.example.com", data=x)`)).not.toContain("ssrf");
    expect(pyIds(`requests.get(x)`)).toContain("ssrf");
    expect(pyIds(`requests.get(url=x)`)).toContain("ssrf");
    expect(pyIds(`requests.request("GET", x)`)).toContain("ssrf");
    expect(pyIds(`requests.get("https://api.example.com", proxies={"https": x})`)).toContain("ssrf");
  });

  it("commands: the command, not cwd/env/input", () => {
    expect(pyIds(`subprocess.run("ls -l", shell=True, cwd=x)`)).not.toContain("command-injection");
    expect(pyIds(`subprocess.run(["ls"], input=x)`)).not.toContain("command-injection");
    expect(pyIds(`os.popen("uptime", x)`)).not.toContain("command-injection");
    expect(pyIds(`subprocess.run("ls " + x, shell=True)`)).toContain("command-injection");
    expect(pyIds(`subprocess.run(args="ls " + x, shell=True)`)).toContain("command-injection");
    expect(pyIds(`os.system("ls " + x)`)).toContain("command-injection");
  });

  it("files: the path(s), not the mode or other options", () => {
    expect(pyIds(`open("/var/app/data.txt", x)`)).not.toContain("path-traversal");
    expect(pyIds(`os.makedirs("/var/app/cache", mode=int(x) if False else 0o755, exist_ok=x)`)).not.toContain("path-traversal");
    expect(pyIds(`open(x)`)).toContain("path-traversal");
    expect(pyIds(`open(file=x)`)).toContain("path-traversal");
    expect(pyIds(`shutil.copy("/var/app/a", x)`)).toContain("path-traversal");
  });

  it("redirects and templates: the location / template source, not the code / context", () => {
    expect(pyIds(`return redirect("/home", code=x)`)).not.toContain("open-redirect");
    expect(pyIds(`return redirect(x)`)).toContain("open-redirect");
    expect(pyIds(`return render_template_string("<p>{{ name }}</p>", name=x)`)).not.toContain("ssti");
    expect(pyIds(`return render_template_string(x)`)).toContain("ssti");
  });
});
