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
  { name: "hard-coded secret", id: "high-entropy-secret", imports: [],
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

describe("basic Go vulnerabilities", () => {
  for (const c of CASES) {
    it(`${c.name}: reported, and its fix is not`, () => {
      expect(ids(handler(c.imports, c.bad))).toContain(c.id);
      expect(ids(handler(c.imports, c.good))).not.toContain(c.id);
    });
  }
});
