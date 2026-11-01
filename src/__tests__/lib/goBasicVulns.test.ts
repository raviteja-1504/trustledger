/**
 * @jest-environment node
 *
 * The everyday Go vulnerabilities, end to end through the scanner (data-flow engine + line rules): each one in its
 * most common net/http shape is reported, and its usual fix is not.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmGoTaintEngine } from "@/lib/astTaintGo";

beforeAll(async () => { await warmGoTaintEngine(); }, 120000);

const handler = (imports: string[], body: string) => `package main

import (
${["net/http", ...imports].map(i => `\t"${i}"`).join("\n")}
)

func Handle(w http.ResponseWriter, r *http.Request) {
${body}
}
`;
const ids = (code: string) => new Set(analyzeFile("handlers/h.go", code).indicators.map(i => i.id));

const CASES: Array<{ name: string; id: string; imports: string[]; bad: string; good: string }> = [
  { name: "SQL injection", id: "sql-injection", imports: ["database/sql", "fmt"],
    bad: `\tid := r.URL.Query().Get("id")\n\tdb.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id))`,
    good: `\tid := r.URL.Query().Get("id")\n\tdb.Query("SELECT * FROM users WHERE id = $1", id)` },
  { name: "SQL injection by concatenation", id: "sql-injection", imports: ["database/sql"],
    bad: `\tname := r.FormValue("name")\n\tdb.Exec("DELETE FROM users WHERE name = '" + name + "'")`,
    good: `\tname := r.FormValue("name")\n\tdb.Exec("DELETE FROM users WHERE name = ?", name)` },
  { name: "command injection through a shell", id: "command-injection", imports: ["os/exec"],
    bad: `\thost := r.URL.Query().Get("host")\n\texec.Command("sh", "-c", "ping -c 1 "+host).Run()`,
    good: `\texec.Command("sh", "-c", "uptime").Run()` },
  { name: "XSS writing input into the response", id: "xss", imports: ["fmt"],
    bad: `\tname := r.URL.Query().Get("name")\n\tfmt.Fprintf(w, "<h1>Hello %s</h1>", name)`,
    good: `\tname := r.URL.Query().Get("name")\n\tfmt.Fprintf(w, "<h1>Hello %s</h1>", html.EscapeString(name))` },
  { name: "path traversal", id: "path-traversal", imports: ["os"],
    bad: `\tf := r.URL.Query().Get("file")\n\tdata, _ := os.ReadFile("/srv/files/" + f)\n\tw.Write(data)`,
    good: `\tf := r.URL.Query().Get("file")\n\tdata, _ := os.ReadFile("/srv/files/" + filepath.Base(f))\n\tw.Write(data)` },
  { name: "SSRF", id: "ssrf", imports: [],
    bad: `\ttarget := r.URL.Query().Get("url")\n\tresp, _ := http.Get(target)\n\tdefer resp.Body.Close()`,
    good: `\tresp, _ := http.Get("https://api.example.com/status")\n\tdefer resp.Body.Close()` },
  { name: "open redirect", id: "open-redirect", imports: [],
    bad: `\tnext := r.URL.Query().Get("next")\n\thttp.Redirect(w, r, next, http.StatusFound)`,
    good: `\thttp.Redirect(w, r, "/dashboard", http.StatusFound)` },
  { name: "log injection", id: "log-injection", imports: ["log"],
    bad: `\tuser := r.FormValue("user")\n\tlog.Printf("login failed for %s", user)`,
    good: `\tlog.Printf("login failed")` },
  { name: "weak hash", id: "weak-crypto", imports: ["crypto/md5"],
    bad: `\tsum := md5.Sum([]byte(r.FormValue("password")))\n\tw.Write(sum[:])`,
    good: `\tsum := sha256.Sum256([]byte(r.FormValue("password")))\n\tw.Write(sum[:])` },
  { name: "TLS verification disabled", id: "tls-verification-disabled", imports: ["crypto/tls"],
    bad: `\tclient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}\n\tclient.Get("https://api.example.com")`,
    good: `\tclient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}\n\tclient.Get("https://api.example.com")` },
  { name: "weak random token", id: "insecure-randomness", imports: ["math/rand", "fmt"],
    bad: `\ttoken := fmt.Sprintf("%d", rand.Int63())\n\thttp.SetCookie(w, &http.Cookie{Name: "session", Value: token, HttpOnly: true, Secure: true})`,
    good: `\tb := make([]byte, 32)\n\tcrand.Read(b)\n\ttoken := hex.EncodeToString(b)\n\thttp.SetCookie(w, &http.Cookie{Name: "session", Value: token, HttpOnly: true, Secure: true})` },
  { name: "hard-coded secret", id: "hardcoded-secret", imports: [],
    // a made-up key in no provider's format, so repository secret scanning has nothing to match
    bad: `\tapiKey := "Zq8xL2vR7nT4pW9kB3mH6cJ1"\n\treq, _ := http.NewRequest("GET", "https://api.example.com/v1/orders", nil)\n\treq.Header.Set("Authorization", "Bearer "+apiKey)`,
    good: `\tapiKey := os.Getenv("ORDERS_API_KEY")\n\treq, _ := http.NewRequest("GET", "https://api.example.com/v1/orders", nil)\n\treq.Header.Set("Authorization", "Bearer "+apiKey)` },
];

describe("weak cipher use", () => {
  const enc = (imports: string[], body: string) => ids(handler(["crypto/aes", "crypto/cipher", ...imports], body));
  it("64-bit-block ciphers, ECB, a fixed IV, an unauthenticated mode, repeating-key XOR", () => {
    expect(enc(["golang.org/x/crypto/blowfish"], `\tb, _ := blowfish.NewCipher([]byte(r.FormValue("k")))\n\t_ = b`)).toContain("weak-crypto");
    expect(enc([], `\tblock, _ := aes.NewCipher(key)\n\tfor i := 0; i < len(p); i += 16 {\n\t\tblock.Encrypt(ct[i:i+16], p[i:i+16])\n\t}`)).toContain("weak-crypto");
    expect(enc(["crypto/hmac"], `\tblock, _ := aes.NewCipher(key)\n\tiv := make([]byte, aes.BlockSize)\n\tcipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, p)\n\tmac := hmac.New(sha256.New, key)\n\t_ = mac`)).toContain("weak-crypto");
    expect(enc(["crypto/rand", "io"], `\tblock, _ := aes.NewCipher(key)\n\tiv := ct[:16]\n\tio.ReadFull(rand.Reader, iv)\n\tcipher.NewCTR(block, iv).XORKeyStream(ct[16:], p)`)).toContain("weak-crypto");
    expect(enc([], `\tkey := []byte(r.FormValue("k"))\n\tfor i := range data {\n\t\tdata[i] ^= key[i%len(key)]\n\t}`)).toContain("weak-crypto");
  });
  it("AES-GCM with a random nonce, or a random IV with an HMAC over the ciphertext, is not", () => {
    expect(enc(["crypto/rand", "io"], `\tblock, _ := aes.NewCipher(key)\n\tgcm, _ := cipher.NewGCM(block)\n\tnonce := make([]byte, gcm.NonceSize())\n\tio.ReadFull(rand.Reader, nonce)\n\tct := gcm.Seal(nil, nonce, p, nil)\n\t_ = ct`)).not.toContain("weak-crypto");
    expect(enc(["crypto/rand", "crypto/hmac", "io"], `\tblock, _ := aes.NewCipher(key)\n\tiv := ct[:16]\n\tio.ReadFull(rand.Reader, iv)\n\tcipher.NewCBCEncrypter(block, iv).CryptBlocks(ct[16:], p)\n\tmac := hmac.New(sha256.New, macKey)\n\t_ = mac`)).not.toContain("weak-crypto");
    // a checksum that XORs bytes together, or one XOR mixing a key into a hash, is not encryption
    expect(enc([], `\tvar sum byte\n\tfor _, b := range data {\n\t\tsum ^= b\n\t}\n\t_ = sum`)).not.toContain("weak-crypto");
    expect(enc([], `\th := seed ^ keyHash\n\t_ = h`)).not.toContain("weak-crypto");
  });
  it("a GCM nonce that is never randomized is", () => {
    expect(enc([], `\tblock, _ := aes.NewCipher(key)\n\tgcm, _ := cipher.NewGCM(block)\n\tnonce := make([]byte, gcm.NonceSize())\n\tct := gcm.Seal(nil, nonce, p, nil)\n\t_ = ct`)).toContain("weak-crypto");
  });
});

describe("exec.Command arguments", () => {
  const cmd = (body: string) => ids(handler(["os/exec", "strconv", "path/filepath", "strings"], body));
  it("a parsed and re-formatted number is neither command nor argument injection", () => {
    const found = cmd(`\tnStr := r.URL.Query().Get("lines")\n\tn, err := strconv.Atoi(nStr)\n\tif err != nil || n < 1 || n > 1000 {\n\t\treturn\n\t}\n\texec.Command("head", "-n", strconv.Itoa(n), "/var/log/syslog").Output()`);
    expect(found).not.toContain("command-injection");
    expect(found).not.toContain("argument-injection");
  });
  it("the value of a long option, or an absolute path, cannot become an option; a bare value can", () => {
    expect(cmd(`\tformat := r.URL.Query().Get("format")\n\texec.Command("convert", "--format", format, "/tmp/in", "/tmp/out").Run()`)).not.toContain("argument-injection");
    expect(cmd(`\tabs, _ := filepath.Abs(filepath.Join("/var/data", r.URL.Query().Get("f")))\n\tif !strings.HasPrefix(abs, "/var/data") {\n\t\treturn\n\t}\n\texec.Command("cat", abs).Output()`)).not.toContain("argument-injection");
    expect(cmd(`\thost := r.URL.Query().Get("host")\n\texec.Command("ping", "-c", "1", host).Output()`)).toContain("argument-injection");
    expect(cmd(`\tdir := r.URL.Query().Get("dir")\n\texec.Command("ls", "-la", dir).Output()`)).toContain("argument-injection");
  });
});

describe("redirect and SSRF guards", () => {
  const go = (imports: string[], body: string) => ids(handler(["net/url", ...imports], body));
  it("rejecting other hosts clears a redirect; a check that lets any host through does not", () => {
    const redirect = (gate: string) => go([], `\tparsed, err := url.Parse(r.URL.Query().Get("next"))\n\tif err != nil {\n\t\treturn\n\t}\n${gate}\n\thttp.Redirect(w, r, parsed.String(), http.StatusFound)`);
    expect(redirect(`\tif parsed.Host != "" && parsed.Host != r.Host {\n\t\treturn\n\t}`)).not.toContain("open-redirect");
    expect(redirect(`\tif parsed.Host != "" && !allowedHosts[parsed.Host] {\n\t\treturn\n\t}`)).not.toContain("open-redirect");
    expect(redirect(`\tif parsed.Host == "" {\n\t\treturn\n\t}`)).toContain("open-redirect");
    expect(redirect(``)).toContain("open-redirect");
  });
  it("a host checked against the request's own host still allows a server-side request there; a literal host does not", () => {
    const fetch = (gate: string) => go([], `\tparsed, _ := url.Parse(r.URL.Query().Get("url"))\n${gate}\n\thttp.Get(parsed.String())`);
    expect(fetch(`\tif parsed.Host != "" && parsed.Host != "api.example.com" {\n\t\treturn\n\t}`)).not.toContain("ssrf");
    expect(fetch(`\tif parsed.Host != "" && parsed.Host != r.Host {\n\t\treturn\n\t}`)).toContain("ssrf");
  });
  it("a subdomain suffix check needs its leading dot", () => {
    const fetch = (suffix: string) => go(["strings"], `\tparsed, err := url.Parse(r.URL.Query().Get("url"))\n\tif err != nil || !strings.HasSuffix(parsed.Hostname(), "${suffix}") {\n\t\treturn\n\t}\n\thttp.Get(parsed.String())`);
    expect(fetch(".example.com")).not.toContain("ssrf");
    expect(fetch("example.com")).toContain("ssrf");
  });
  it("refusing every private address the host resolves to clears the request; looking it up without refusing does not", () => {
    const fetch = (check: string) => go(["net"], `\tparsed, _ := url.Parse(r.URL.Query().Get("url"))\n\tips, _ := net.LookupIP(parsed.Hostname())\n\tfor _, ip := range ips {\n${check}\n\t}\n\thttp.Get(parsed.String())`);
    expect(fetch(`\t\tif ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {\n\t\t\treturn\n\t\t}`)).not.toContain("ssrf");
    expect(fetch(`\t\tif isPrivateAddr(ip) {\n\t\t\treturn\n\t\t}`)).not.toContain("ssrf");
    expect(fetch(`\t\tif ip.IsLoopback() {\n\t\t\treturn\n\t\t}`)).toContain("ssrf");
    expect(fetch(`\t\tlog.Println(ip)`)).toContain("ssrf");
  });
});

describe("helpers and library functions (string parameters, no caller in the file)", () => {
  const scan = (code: string) => analyzeFile("store/users.go", code).indicators;
  const SQL = `package main\n\nimport (\n    "database/sql"\n    "fmt"\n)\n\nfunc getUser(db *sql.DB, username string) {\n    query := fmt.Sprintf(\n        "SELECT * FROM users WHERE username = '%s'",\n        username,\n    )\n\n    db.Query(query)\n}\n`;
  const CMD = `package main\n\nimport (\n    "os/exec"\n)\n\nfunc pingHost(host string) {\n    cmd := exec.Command("sh", "-c", "ping -c 1 "+host)\n    cmd.Run()\n}\n`;
  const PATH = `package main\n\nimport (\n    "os"\n)\n\nfunc readFile(filename string) ([]byte, error) {\n    path := "/var/www/uploads/" + filename\n    return os.ReadFile(path)\n}\n`;
  it("SQL, command and path sinks reached by a string parameter are reported, at lower confidence", () => {
    for (const [code, id] of [[SQL, "sql-injection"], [CMD, "command-injection"], [PATH, "path-traversal"]] as const) {
      const f = scan(code).find(i => i.id === id);
      expect(f).toBeDefined();
      expect(f!.confidence).toBe(70);
      expect(f!.detail).toMatch(/assumed untrusted/);
    }
  });
  it("a parameterised query, a fixed command, a cleaned name, or a non-string parameter is not", () => {
    expect(scan(SQL.replace(/query := fmt\.Sprintf\([\s\S]*?\)\n/, `query := "SELECT * FROM users WHERE username = $1"\n`).replace("db.Query(query)", "db.Query(query, username)")).some(i => i.id === "sql-injection")).toBe(false);
    expect(scan(CMD.replace(`"ping -c 1 "+host`, `"uptime"`)).some(i => i.id === "command-injection")).toBe(false);
    expect(scan(PATH.replace(`"/var/www/uploads/" + filename`, `"/var/www/uploads/" + filepath.Base(filename)`)).some(i => i.id === "path-traversal")).toBe(false);
    expect(scan(SQL.replace("username string", "username int").replace("'%s'", "%d")).some(i => i.id === "sql-injection")).toBe(false);
  });
  it("a function this file calls with a constant is judged at that call, not assumed tainted", () => {
    const called = SQL + `\nfunc main() {\n    getUser(nil, "admin")\n}\n`;
    expect(scan(called).some(i => i.id === "sql-injection" && i.confidence === 70)).toBe(false);
  });
});

describe("a request read inside a helper (source -> builder -> sink across three functions)", () => {
  const app = (fetch: string) => `package main

import (
\t"database/sql"
\t"fmt"
\t"net/http"
)

func getUserInput(r *http.Request) string {
\treturn r.URL.Query().Get("username")
}

${fetch}

func userHandler(db *sql.DB) http.HandlerFunc {
\treturn func(w http.ResponseWriter, r *http.Request) {
\t\tusername := getUserInput(r)
\t\tfetchUser(db, username)
\t\tfmt.Fprintln(w, "User fetched")
\t}
}
`;
  const sqlAt = (code: string) => analyzeFile("main.go", code).indicators.filter(i => i.id === "sql-injection");
  it("SQL built from the helper's value is reported at full confidence", () => {
    const found = sqlAt(app(`func fetchUser(db *sql.DB, username string) {\n\tquery := fmt.Sprintf("SELECT id FROM users WHERE username = '%s'", username)\n\tdb.Query(query)\n}`));
    expect(found.length).toBeGreaterThan(0);
    expect(found.every(f => f.confidence === 95)).toBe(true);
  });
  it("the same value bound as a query parameter is not", () => {
    expect(sqlAt(app(`func fetchUser(db *sql.DB, username string) {\n\tdb.Query("SELECT id FROM users WHERE username = ?", username)\n}`))).toHaveLength(0);
  });
  it("a helper that returns a constant is no source", () => {
    const constant = app(`func fetchUser(db *sql.DB, username string) {\n\tquery := fmt.Sprintf("SELECT id FROM users WHERE username = '%s'", username)\n\tdb.Query(query)\n}`)
      .replace(`return r.URL.Query().Get("username")`, `return "guest"`);
    expect(sqlAt(constant).some(f => f.confidence === 95)).toBe(false);
  });
});

describe("log injection", () => {
  const lg = (imports: string[], body: string) => ids(handler(imports, body)).has("log-injection");
  it("slog messages, and fmt.Fprintf to stderr, log.Writer() or an appended .log file", () => {
    expect(lg(["log/slog"], `\taction := r.URL.Query().Get("action")\n\tslog.Info("user performed: " + action)`)).toBe(true);
    expect(lg(["os", "fmt"], `\tua := r.Header.Get("User-Agent")\n\tfmt.Fprintf(os.Stderr, "request: "+ua+"\\n")`)).toBe(true);
    expect(lg(["os", "fmt"], `\ta := r.FormValue("action")\n\tf, _ := os.OpenFile("/var/log/app.log", os.O_APPEND|os.O_WRONLY, 0644)\n\tfmt.Fprintf(f, "Action: %s\\n", a)`)).toBe(true);
  });
  it("quoted verbs, escaped line breaks, slog attributes or a data file are not", () => {
    expect(lg(["log", "fmt"], `\tu := r.FormValue("u")\n\tfmt.Fprintf(log.Writer(), "login by %q\\n", u)`)).toBe(false);
    expect(lg(["log", "fmt"], `\tu := r.FormValue("u")\n\tmsg := fmt.Sprintf("register user=%q", u)\n\tlog.Println(msg)`)).toBe(false);
    expect(lg(["log", "strings"], `\tu := r.FormValue("u")\n\tsafe := strings.ReplaceAll(u, "\\n", "\\\\n")\n\tsafe = strings.ReplaceAll(safe, "\\r", "\\\\r")\n\tlog.Printf("user=%s", safe)`)).toBe(false);
    expect(lg(["log/slog"], `\tu := r.FormValue("u")\n\tslog.Info("login", "user", u)`)).toBe(false);
    expect(lg(["os", "fmt"], `\ta := r.FormValue("a")\n\tf, _ := os.OpenFile("/srv/export.csv", os.O_APPEND|os.O_WRONLY, 0644)\n\tfmt.Fprintf(f, "%s\\n", a)`)).toBe(false);
  });
  it("a replacement that writes the line break back still counts", () => {
    expect(lg(["log", "strings"], `\tu := r.FormValue("u")\n\tsafe := strings.ReplaceAll(u, "\\n", "\\n")\n\tlog.Printf("user=%s", safe)`)).toBe(true);
  });
});

describe("hard-coded hex keys", () => {
  it("a random 32-digit hex key in a credential variable is a secret; a hash, a short or a repetitive value is not", () => {
    const code = (line: string) => handler([], `${line}\n\t_ = v`);
    // reported by the API-key rule or, for a name it doesn't cover, by the entropy rule
    const secret = (line: string) => { const found = ids(code(line)); return found.has("high-entropy-secret") || found.has("hardcoded-secret"); };
    expect(secret(`\tapiKey := "9f8c2b7e4a1d6053c8e1b4f7a2d9c6e3"\n\tv := apiKey`)).toBe(true);
    // a generic name only the entropy rule judges
    expect(secret(`\tkey := "9f8c2b7e4a1d6053c8e1b4f7a2d9c6e3"\n\tv := key`)).toBe(true);
    expect(secret(`\tkey := "9f8c2b7e4a1d6053c8e1b4f7a2d9c6e3" // sha256 digest of the release tarball\n\tv := key`)).toBe(false);
    // short hex under a generic name: the entropy rule needs 32+ digits (an apiKey of any length is the API-key rule's)
    expect(secret(`\tkey := "9f8c2b7e4a1d6053"\n\tv := key`)).toBe(false);
    expect(secret(`\tkey := "aaaaaaaabbbbbbbbaaaaaaaabbbbbbbb"\n\tv := key`)).toBe(false);
  });
});

describe("basic Go vulnerabilities", () => {
  for (const c of CASES) {
    it(`${c.name}: reported, and its fix is not`, () => {
      expect(ids(handler(c.imports, c.bad))).toContain(c.id);
      expect(ids(handler(c.imports, c.good))).not.toContain(c.id);
    });
  }
});
