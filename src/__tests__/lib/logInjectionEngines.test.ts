/**
 * @jest-environment node
 *
 * Log injection (CWE-117) beyond JS/TS and C#: request input written to the log by Python logging, SLF4J / Log4j /
 * java.util.logging (Java, Kotlin), Go's log / logrus / zap sugar, PHP error_log / syslog / PSR-3 loggers and Ruby's
 * Logger / Rails.logger. A constant message, structured context and a non-logger receiver are not.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import { warmGoTaintEngine } from "@/lib/astTaintGo";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";
import { warmKotlinTaintEngine } from "@/lib/astTaintKotlin";

beforeAll(async () => {
  await warmPythonTaintEngine(); await warmGoTaintEngine(); await warmPhpTaintEngine(); await warmRubyTaintEngine(); await warmKotlinTaintEngine();
}, 120000);

const log = (path: string, code: string) => analyzeFile(path, code).indicators.some(i => i.id === "log-injection" && !!i.sourceExpr);

describe("Python", () => {
  const py = (stmt: string) => `import logging\nfrom flask import request\nlogger = logging.getLogger(__name__)\n\n@app.route("/login")\ndef login():\n    user = request.args.get("user")\n    ${stmt}\n    return "ok"\n`;
  it("logging / logger calls with request input", () => {
    expect(log("app.py", py(`logger.warning("login failed for %s", user)`))).toBe(true);
    expect(log("app.py", py(`logging.info("user " + user)`))).toBe(true);
    expect(log("app.py", py(`app.logger.error(f"bad user {user}")`))).toBe(true);
  });
  it("not a constant, a dict of context, or math.log", () => {
    expect(log("app.py", py(`logger.warning("login failed")`))).toBe(false);
    expect(log("app.py", py(`logger.info("login", {"user": user})`))).toBe(false);
    expect(log("app.py", py(`x = math.log(len(user))`))).toBe(false);
  });
});

describe("Java and Kotlin", () => {
  const java = (stmt: string) => `import javax.servlet.http.*;\npublic class L extends HttpServlet {\n    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(L.class);\n    public void doGet(HttpServletRequest request, HttpServletResponse response) {\n        String user = request.getParameter("user");\n        ${stmt}\n    }\n}\n`;
  it("Java: SLF4J / java.util.logging with request input; not a constant or a non-logger", () => {
    expect(log("src/L.java", java(`log.warn("login failed for " + user);`))).toBe(true);
    expect(log("src/L.java", java(`IO.logger.log(java.util.logging.Level.WARNING, "bad " + user);`))).toBe(true);
    expect(log("src/L.java", java(`log.warn("login failed");`))).toBe(false);
    expect(log("src/L.java", java(`cache.warn(user);`))).toBe(false);
  });
  const kt = (stmt: string) => `@RestController\nclass L {\n    private val log = LoggerFactory.getLogger(L::class.java)\n    @GetMapping("/login")\n    fun login(@RequestParam user: String): String {\n        ${stmt}\n        return "ok"\n    }\n}\n`;
  it("Kotlin: a logger with request input; not a constant", () => {
    expect(log("L.kt", kt(`log.warn("login failed for " + user)`))).toBe(true);
    expect(log("L.kt", kt(`log.warn("login failed")`))).toBe(false);
  });
});

describe("Go", () => {
  const go = (stmt: string) => `package main\n\nimport (\n\t"log"\n\t"net/http"\n)\n\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\tuser := r.URL.Query().Get("user")\n\t${stmt}\n}\n`;
  it("log.Printf / logger.Infof with request input; not fmt or a constant", () => {
    expect(log("main.go", go(`log.Printf("login failed for %s", user)`))).toBe(true);
    expect(log("main.go", go(`logger.Infof("user %s", user)`))).toBe(true);
    expect(log("main.go", go(`log.Println("login failed")`))).toBe(false);
    expect(log("main.go", go(`_ = fmt.Errorf("bad %s", user)`))).toBe(false);
  });
  it("Go: CR/LF replaced, strconv.Quote, or a %q verb is not injectable", () => {
    expect(log("main.go", go(`clean := strings.ReplaceAll(strings.ReplaceAll(user, "\\n", ""), "\\r", "")\n\tlog.Printf("Login: %s", clean)`))).toBe(false);
    expect(log("main.go", go(`log.Printf("user=%s", strconv.Quote(user))`))).toBe(false);
    expect(log("main.go", go(`log.Printf("user=%q logged in", user)`))).toBe(false);
    // replacing something else leaves the line breaks in
    expect(log("main.go", go(`clean := strings.ReplaceAll(user, "<", "")\n\tlog.Printf("Login: %s", clean)`))).toBe(true);
  });
});

describe("PHP", () => {
  const php = (stmt: string) => `<?php\nfunction login() {\n    $user = $_GET['user'];\n    ${stmt}\n}\n`;
  it("error_log / syslog / a PSR-3 logger with request input; not a constant", () => {
    expect(log("login.php", php(`error_log("login failed for " . $user);`))).toBe(true);
    expect(log("login.php", php(`syslog(LOG_WARNING, "bad " . $user);`))).toBe(true);
    expect(log("login.php", php(`$logger->warning("bad " . $user);`))).toBe(true);
    expect(log("login.php", php(`error_log("login failed");`))).toBe(false);
    expect(log("login.php", php(`$cache->warning($user);`))).toBe(false);
  });
});

describe("Ruby", () => {
  const rb = (stmt: string) => `class SessionsController < ApplicationController\n  def create\n    user = params[:user]\n    ${stmt}\n  end\nend\n`;
  it("logger / Rails.logger with request input; not a constant, a hash, or a non-logger", () => {
    expect(log("app/controllers/sessions_controller.rb", rb(`logger.warn("login failed for #{user}")`))).toBe(true);
    expect(log("app/controllers/sessions_controller.rb", rb(`Rails.logger.info("user " + user)`))).toBe(true);
    expect(log("app/controllers/sessions_controller.rb", rb(`logger.warn("login failed")`))).toBe(false);
    expect(log("app/controllers/sessions_controller.rb", rb(`cache.warn(user)`))).toBe(false);
  });
  it("Ruby: gsub of CR/LF (other control whitespace too), JSON.generate, inspect", () => {
    expect(log("app/controllers/sessions_controller.rb", rb(`safe = user.gsub(/[\\r\\n\\t]/, '_')\n    logger.info("User #{safe} logged in")`))).toBe(false);
    expect(log("app/controllers/sessions_controller.rb", rb(`logger.info(JSON.generate({ event: 'login', user: user }))`))).toBe(false);
    expect(log("app/controllers/sessions_controller.rb", rb(`logger.info("User #{user.inspect}")`))).toBe(false);
    expect(log("app/controllers/sessions_controller.rb", rb(`safe = user.gsub(/[<>]/, '')\n    logger.info("User #{safe}")`))).toBe(true);
  });
});
