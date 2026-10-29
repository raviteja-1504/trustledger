/**
 * @jest-environment node
 *
 * Line detectors found scoring OWASP Juice Shop's vuln-code-snippet challenges and the Goatlin / AndroGoat Android
 * apps: directory listing, a URL allowlist matched by substring, WebView file-URL access, and a credential compared
 * against a literal. Each has a safe twin.
 */
import { analyzeFile } from "@/lib/scanner";

const ids = (file: string, code: string) => analyzeFile(file, code).indicators.map(i => i.id);

describe("directory listing", () => {
  it("serve-index in Express and ASP.NET Core's directory browser; plain static files are not", () => {
    expect(ids("server.ts", `import serveIndex from 'serve-index'\nconst app = express()\napp.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true }))\n`)).toContain("directory-listing");
    expect(ids("Program.cs", `var app = builder.Build();\napp.UseStaticFiles();\napp.UseDirectoryBrowser();\napp.Run();\n`)).toContain("directory-listing");
    expect(ids("server.ts", `import serveStatic from 'serve-static'\nconst app = express()\napp.use('/public', express.static('public'))\n`)).not.toContain("directory-listing");
  });
});

describe("URL allowlist by substring", () => {
  it("url.includes(allowedUrl); an exact Set lookup is not", () => {
    const code = (check: string) => `export const isRedirectAllowed = (url: string) => {\n  let allowed = false\n  for (const allowedUrl of redirectAllowlist) {\n    ${check}\n  }\n  return allowed\n}\n`;
    expect(ids("lib/insecurity.ts", code(`allowed = allowed || url.includes(allowedUrl)`))).toContain("open-redirect");
    expect(ids("lib/insecurity.ts", code(`allowed = allowed || redirectAllowlist.has(new URL(url).origin)`))).not.toContain("open-redirect");
  });
});

describe("WebView file access", () => {
  it("allowUniversalAccessFromFileURLs / setAllowFileAccessFromFileURLs set true; false is fine", () => {
    const kt = (v: string) => `class A : AppCompatActivity() {\n    fun setup(webView: WebView) {\n        val s = webView.settings\n        s.allowUniversalAccessFromFileURLs = ${v}\n    }\n}\n`;
    expect(ids("app/A.kt", kt("true"))).toContain("webview-insecure-settings");
    expect(ids("app/A.kt", kt("false"))).not.toContain("webview-insecure-settings");
    expect(ids("app/A.java", `class A {\n  void setup(WebView w) {\n    w.getSettings().setAllowFileAccessFromFileURLs(true);\n  }\n}\n`)).toContain("webview-insecure-settings");
  });
});

describe("credential compared against a literal", () => {
  it("a backdoor password compare; UI state words and empty checks are not", () => {
    const kt = (cond: string) => `class LoginTask(private val mUsername: String, private val mPassword: String) {\n    fun run(): Boolean {\n        if (${cond}) {\n            return true\n        }\n        return false\n    }\n}\n`;
    expect(ids("app/Login.kt", kt(`(mUsername == "Supervisor") and (mPassword == "MySuperSecretPassword123!")`))).toContain("hardcoded-secret");
    expect(ids("app/Login.kt", kt(`passwordField == "hidden"`))).not.toContain("hardcoded-secret");
    expect(ids("app/Login.kt", kt(`mPassword == ""`))).not.toContain("hardcoded-secret");
    // configuration compared with its known default, to warn about it
    expect(ids("app/check.ts", `export function check() {\n  const warn = process.env.CRON_SECRET === "dev-cron-secret";\n  return warn;\n}\n`)).not.toContain("hardcoded-secret");
    expect(ids("app/check.ts", `export function check(secret: string) {\n  const weak = secret === "placeholder-secret-1";\n  return weak;\n}\n`)).not.toContain("hardcoded-secret");
  });
});
