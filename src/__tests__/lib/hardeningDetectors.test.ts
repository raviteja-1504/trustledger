/**
 * Line-level hardening checks the taint engines can't see: (Express) a rate limiter keyed on a client-written
 * forwarding header, metrics / debug endpoints with no auth middleware, a login that keeps the pre-login session id,
 * an admin-guarded route shadowed by an earlier unguarded registration; (Java) a key generated for a broken cipher.
 * Each has a twin that stays silent.
 */
import { analyzeFile } from "@/lib/scanner";

// A JS/TS snippet sits in a real Express module: the scanner skips near-empty files, which would make every
// "stays silent" assertion pass whatever the detector does.
const PRE = `const express = require('express');\nconst app = express();\nconst router = express.Router();\n`;
const wrap = (code: string, path: string) => (/\.[jt]s$/.test(path) ? `${PRE}${code}\napp.listen(3000);\nmodule.exports = { app, router };\n` : code);
const ids = (code: string, path = "server.js") => analyzeFile(path, wrap(code, path)).indicators.map(i => i.id);

describe("rate limiter key", () => {
  it("keyed on X-Forwarded-For (inline or in a body); the default key or req.ip is not", () => {
    expect(ids(`app.use('/reset', rateLimit({\n  windowMs: 60000,\n  max: 5,\n  keyGenerator ({ headers, ip }) { return headers['X-Forwarded-For'] ?? ip }\n}))\n`)).toContain("rate-limit-bypass");
    expect(ids(`const limiter = rateLimit({\n  max: 5,\n  keyGenerator: (req) => {\n    return req.headers["x-forwarded-for"] || req.ip;\n  },\n});\n`)).toContain("rate-limit-bypass");
    expect(ids(`app.set('trust proxy', 1)\nconst limiter = rateLimit({\n  max: 5,\n  keyGenerator: (req) => req.ip,\n  message: 'x-forwarded-for is ignored',\n});\n`)).not.toContain("rate-limit-bypass");
    expect(ids(`const ip = req.headers['x-forwarded-for']\n`)).not.toContain("rate-limit-bypass");
    // the header in a LATER option (skip), not in the key generator
    expect(ids(`const limiter = rateLimit({\n  keyGenerator: (req) => req.ip,\n  skip: (req) => req.headers['x-forwarded-for'] === TRUSTED,\n})\n`)).not.toContain("rate-limit-bypass");
    // the word in a log message is no key generator
    expect(ids(`logger.info("keyGenerator ignores 'x-forwarded-for' now", { at: Date.now() })\n`)).not.toContain("rate-limit-bypass");
  });
  it("code quoted inside a string is not code", () => {
    const quoted = `const FIX = {\n  code_before: "keyGenerator: (req) => req.headers['x-forwarded-for']",\n  session: "req.session.userId = user._id;",\n  route: "app.get('/metrics', serveMetrics())",\n};\n`;
    const found = ids(quoted);
    for (const id of ["rate-limit-bypass", "session-fixation", "unauthenticated-diagnostics"]) expect(found).not.toContain(id);
  });
  it("is a JS/TS check only", () => {
    expect(ids(`keyGenerator = lambda r: r.headers['X-Forwarded-For']\n`, "app.py")).not.toContain("rate-limit-bypass");
  });
});

describe("diagnostics endpoints", () => {
  it("/metrics or /actuator with only a handler; with auth middleware, or mounted behind it, it is not", () => {
    expect(ids(`app.get('/metrics', utils.asyncHandler(metrics.serveMetrics()))\n`)).toContain("unauthenticated-diagnostics");
    expect(ids(`router.get("/actuator/env", (req, res) => res.json(process.env))\n`, "routes.ts")).toContain("unauthenticated-diagnostics");
    expect(ids(`app.get('/metrics', requireAuth, serveMetrics())\n`)).not.toContain("unauthenticated-diagnostics");
    expect(ids(`app.use('/metrics', basicAuth({ users }))\napp.get('/metrics', serveMetrics())\n`)).not.toContain("unauthenticated-diagnostics");
    expect(ids(`app.get('/metrics-dashboard', page)\napp.get('/products', list)\n`)).not.toContain("unauthenticated-diagnostics");
    // Windows line endings
    expect(ids(`const x = 1\r\napp.get('/metrics', utils.asyncHandler(metrics.serveMetrics()))\r\nconst y = 2\r\n`)).toContain("unauthenticated-diagnostics");
  });
});

describe("session fixation", () => {
  it("logging in on the existing session; inside regenerate(), or a logout reset, it is not", () => {
    expect(ids(`function login(req, res) {\n  const user = find(req.body.name);\n  req.session.userId = user._id;\n  res.redirect('/');\n}\n`)).toContain("session-fixation");
    expect(ids(`function login(req, res, next) {\n  const user = find(req.body.name);\n  req.session.regenerate((err) => {\n    if (err) return next(err);\n    req.session.userId = user._id;\n    res.redirect('/');\n  });\n}\n`)).not.toContain("session-fixation");
    expect(ids(`function logout(req, res) {\n  req.session.userId = null;\n  res.redirect('/');\n}\n`)).not.toContain("session-fixation");
    expect(ids(`function check(req) {\n  return req.session.userId === undefined;\n}\n`)).not.toContain("session-fixation");
  });
});

describe("Java key for a broken cipher", () => {
  it("KeyGenerator / SecretKeyFactory for DES, 3DES or RC4; an AES key is not", () => {
    const java = (alg: string) => `class C {\n  void f() throws Exception {\n    javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("${alg}").generateKey();\n  }\n}\n`;
    expect(ids(java("DES"), "C.java")).toContain("weak-crypto");
    expect(ids(java("DESede"), "C.java")).toContain("weak-crypto");
    expect(ids(java("RC4"), "C.java")).toContain("weak-crypto");
    expect(ids(java("AES"), "C.java")).not.toContain("weak-crypto");
    expect(ids(java("HmacSHA256"), "C.java")).not.toContain("weak-crypto");
  });
});

describe("Android cleartext storage and clipboard", () => {
  const activity = (body: string) => `package app.demo

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import java.io.FileWriter

class LoginActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val username = findViewById<EditText>(R.id.username)
        val password = findViewById<EditText>(R.id.password)
${body}
    }
}
`;
  const kt = (body: string) => analyzeFile("app/src/main/java/app/demo/LoginActivity.kt", activity(body)).indicators.map(i => i.id);
  it("a password written to a file, directly or through a built string, or to plain preferences", () => {
    expect(kt(`        val f = File.createTempFile("users", "tmp", File(applicationInfo.dataDir))\n        val fw = FileWriter(f)\n        fw.write("password is " + password.text.toString())\n        fw.close()`)).toContain("cleartext-sensitive-storage");
    expect(kt(`        val data = "User - \${username.text} Password - \${password.text}"\n        val fw = FileWriter(File(getExternalFilesDir(null), "u.txt"))\n        fw.write(data)\n        fw.close()`)).toContain("cleartext-sensitive-storage");
    expect(kt(`        getSharedPreferences("auth", MODE_PRIVATE).edit().putString("password", password.text.toString()).apply()`)).toContain("cleartext-sensitive-storage");
    // Windows line endings, through the built string
    const crlf = activity(`        val data = "User - \${username.text} Password - \${password.text}"\n        val fw = FileWriter(File(getExternalFilesDir(null), "u.txt"))\n        fw.write(data)\n        fw.close()`).replace(/\n/g, "\r\n");
    expect(analyzeFile("app/src/main/java/app/demo/LoginActivity.kt", crlf).indicators.map(i => i.id)).toContain("cleartext-sensitive-storage");
  });
  it("encrypted stores, a non-secret value, or a StringBuilder are not storage of a secret", () => {
    expect(kt(`        val prefs = EncryptedSharedPreferences.create(this, "auth", key, scheme1, scheme2)\n        prefs.edit().putString("password", password.text.toString()).apply()`)).not.toContain("cleartext-sensitive-storage");
    expect(kt(`        val fw = FileWriter(File(filesDir, "u.txt"))\n        fw.write("user is " + username.text.toString())\n        fw.close()`)).not.toContain("cleartext-sensitive-storage");
    // a SQLite row with the password column in the clear; hashed, or a non-secret column, is fine
    const row = (v: string, col = "password") => `        val record = ContentValues()\n        record.put("username", username.text.toString())\n        record.put("${col}", ${v})\n        db.insert("accounts", null, record)`;
    expect(kt(row("password.text.toString()"))).toContain("cleartext-sensitive-storage");
    expect(kt(row("BCrypt.hashpw(password.text.toString(), BCrypt.gensalt())"))).not.toContain("cleartext-sensitive-storage");
    expect(kt(row("username.text.toString()", "display_name"))).not.toContain("cleartext-sensitive-storage");
    // a Map's put is not a database row
    expect(kt(`        val headers = HashMap<String, String>()\n        headers.put("password", password.text.toString())`)).not.toContain("cleartext-sensitive-storage");
    // a hashed value is not the secret in the clear
    expect(kt(`        getSharedPreferences("pins", MODE_PRIVATE).edit().putString("pin", hashPIN(password.text.toString())).apply()`)).not.toContain("cleartext-sensitive-storage");
    expect(kt(`        val fw = FileWriter(File(filesDir, "u.txt"))\n        val sb = StringBuilder()\n        sb.append(password.text)\n        fw.write("saved")\n        fw.close()`)).not.toContain("cleartext-sensitive-storage");
  });
  it("an OTP or card number on the clipboard; ordinary text is not", () => {
    expect(kt(`        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager\n        val clip = ClipData.newPlainText("CC Card", otp.toString())\n        clipboard.setPrimaryClip(clip)`)).toContain("sensitive-clipboard");
    expect(kt(`        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager\n        val clip = ClipData.newPlainText("share link", url)\n        clipboard.setPrimaryClip(clip)`)).not.toContain("sensitive-clipboard");
  });
});

describe("shadowed role guard", () => {
  it("an unguarded route registered before its admin-guarded twin; the guarded one alone is fine", () => {
    const both = `app.get("/benefits", isLoggedIn, benefits.display);\napp.get("/benefits", isLoggedIn, isAdmin, benefits.display);\n`;
    const found = analyzeFile("routes/index.js", wrap(both, "routes/index.js")).indicators.filter(i => i.id === "missing-function-level-authz");
    expect(found.map(i => i.line)).toEqual([4]);   // the unguarded registration (after the 3-line module header)
    expect(ids(`app.get("/benefits", isLoggedIn, isAdmin, benefits.display);\napp.post("/benefits", isLoggedIn, isAdmin, benefits.update);\n`, "routes/index.js")).not.toContain("missing-function-level-authz");
    // the first registration already has a role check
    expect(ids(`app.get("/reports", isAdmin, reports.list);\napp.get("/reports", isAdmin, audit, reports.list);\n`, "routes/index.js")).not.toContain("missing-function-level-authz");
    // a commented-out unguarded line is not registered
    expect(ids(`// app.get("/benefits", isLoggedIn, benefits.display);\napp.get("/benefits", isLoggedIn, isAdmin, benefits.display);\n`, "routes/index.js")).not.toContain("missing-function-level-authz");
  });
});
