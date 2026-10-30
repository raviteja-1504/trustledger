/**
 * @jest-environment node
 *
 * Go checks for the sast-benchmark categories that scored zero: request data stored in the session (trust boundary),
 * an upload saved under its client-chosen name, an attacker-chosen index with no bounds check, a package-level write
 * from a goroutine with no lock, a cookie-authenticated state change with no CSRF defence, and stack traces /
 * contextual errors in the response. Each has a twin that stays silent.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmGoTaintEngine } from "@/lib/astTaintGo";

beforeAll(async () => { await warmGoTaintEngine(); }, 120000);

const file = (body: string, pre = "") => `package main

import (
\t"net/http"
\t"os"
\t"path/filepath"
\t"runtime/debug"
\t"strconv"
\t"sync"
)

${pre}
func Handler(w http.ResponseWriter, r *http.Request) {
${body}
}
`;
const ids = (code: string) => analyzeFile("handlers/h.go", code).indicators.map(i => i.id);

describe("trust boundary", () => {
  it("request data into session.Values / session.Set; a server-chosen value is not", () => {
    expect(ids(file(`\tsession, _ := Store.Get(r, "app")\n\trole := r.FormValue("role")\n\tsession.Values["role"] = role\n\tsession.Save(r, w)`))).toContain("trust-boundary");
    expect(ids(file(`\tsession, _ := Store.Get(r, "app")\n\tsession.Values["role"] = "user"\n\tsession.Save(r, w)`))).not.toContain("trust-boundary");
    expect(ids(file(`\tsession := Sessions.Default(r)\n\tsession.Set("role", r.FormValue("role"))`))).toContain("trust-boundary");
    expect(ids(file(`\tsession := Sessions.Default(r)\n\tsession.Set("role", "user")`))).not.toContain("trust-boundary");
  });
});

describe("file upload", () => {
  it("the client's filename as the destination; a generated name is not", () => {
    expect(ids(file(`\tfile, header, err := r.FormFile("upload")\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer file.Close()\n\tdestPath := filepath.Join("/uploads", header.Filename)\n\tdst, _ := os.Create(destPath)\n\t_ = dst`))).toContain("insecure-file-upload");
    expect(ids(file(`\tfile, _, err := r.FormFile("upload")\n\tif err != nil {\n\t\treturn\n\t}\n\tdefer file.Close()\n\tdestPath := filepath.Join("/uploads", newUploadID()+".bin")\n\tdst, _ := os.Create(destPath)\n\t_ = dst`))).not.toContain("insecure-file-upload");
  });
  it("a request path that is not the upload's name is path traversal, not an upload finding", () => {
    const found = ids(file(`\tdst, _ := os.Create(filepath.Join("/uploads", r.FormValue("name")))\n\t_ = dst`));
    expect(found).toContain("path-traversal");
    expect(found).not.toContain("insecure-file-upload");
  });
  it("gin's c.SaveUploadedFile writes to its second argument", () => {
    const gin = (dst: string) => `package main\n\nimport "github.com/gin-gonic/gin"\n\nfunc Upload(c *gin.Context) {\n\tfile, _ := c.FormFile("upload")\n\tc.SaveUploadedFile(file, ${dst})\n}\n`;
    expect(ids(gin(`"/uploads/" + file.Filename`))).toContain("insecure-file-upload");
    expect(ids(gin(`"/uploads/fixed.bin"`))).not.toContain("insecure-file-upload");
  });
});

describe("unchecked index", () => {
  const pre = `var items = []string{"a", "b", "c"}`;
  it("an index from the query with no bounds check; one checked against len is not", () => {
    expect(ids(file(`\ti, _ := strconv.Atoi(r.URL.Query().Get("index"))\n\tw.Write([]byte(items[i]))`, pre))).toContain("input-validation");
    expect(ids(file(`\ti, _ := strconv.Atoi(r.URL.Query().Get("index"))\n\tif i < 0 || i >= len(items) {\n\t\treturn\n\t}\n\tw.Write([]byte(items[i]))`, pre))).not.toContain("input-validation");
    // a write out of range panics just the same
    expect(ids(file(`\ti, _ := strconv.Atoi(r.URL.Query().Get("index"))\n\titems[i] = "x"`, pre))).toContain("input-validation");
  });
  it("make() sized by the query with no cap; a capped size is not", () => {
    expect(ids(file(`\tn, _ := strconv.Atoi(r.URL.Query().Get("size"))\n\tbuf := make([]byte, n)\n\tw.Write(buf)`))).toContain("integer-overflow");
    expect(ids(file(`\tn, _ := strconv.Atoi(r.URL.Query().Get("size"))\n\tif n > 4096 {\n\t\treturn\n\t}\n\tbuf := make([]byte, n)\n\tw.Write(buf)`))).not.toContain("integer-overflow");
  });
  it("a map lookup is no index out of range", () => {
    expect(ids(file(`\tk := r.URL.Query().Get("k")\n\tw.Write([]byte(lookup[k]))`, `var lookup = map[string]string{"a": "b"}`))).not.toContain("input-validation");
  });
});

describe("data race", () => {
  const pre = `var shared = make(map[string]int)\nvar mu sync.Mutex`;
  it("a package-level map written from goroutines with no lock; with a mutex it is not", () => {
    expect(ids(file(`\tkey := r.URL.Query().Get("key")\n\tvar wg sync.WaitGroup\n\twg.Add(1)\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tshared[key] = 1\n\t}()\n\twg.Wait()`, pre))).toContain("race-condition");
    expect(ids(file(`\tkey := r.URL.Query().Get("key")\n\tvar wg sync.WaitGroup\n\twg.Add(1)\n\tgo func() {\n\t\tdefer wg.Done()\n\t\tmu.Lock()\n\t\tshared[key] = 1\n\t\tmu.Unlock()\n\t}()\n\twg.Wait()`, pre))).not.toContain("race-condition");
  });
  it("a variable the goroutine declares itself is not shared", () => {
    expect(ids(file(`\tgo func() {\n\t\tvar local int\n\t\tlocal = 2\n\t\t_ = local\n\t}()`, pre))).not.toContain("race-condition");
  });
});

describe("CSRF", () => {
  const change = (extra: string) => file(`\tcookie, err := r.Cookie("session_id")\n\tif err != nil {\n\t\treturn\n\t}\n${extra}\tDB.Exec("UPDATE users SET email = ? WHERE token = ?", r.FormValue("email"), cookie.Value)`);
  it("a cookie-authenticated update with no token, Origin or SameSite; with a token check it is not", () => {
    expect(ids(change(""))).toContain("csrf");
    expect(ids(change(`\tif r.Header.Get("X-CSRF-Token") != expectedToken(cookie.Value) {\n\t\treturn\n\t}\n`))).not.toContain("csrf");
  });
  it("a cookie-authenticated read changes nothing, so it is not CSRF", () => {
    expect(ids(file(`\tcookie, err := r.Cookie("session_id")\n\tif err != nil {\n\t\treturn\n\t}\n\trow := DB.QueryRow("SELECT email FROM users WHERE token = ?", cookie.Value)\n\t_ = row`))).not.toContain("csrf");
  });
  it("a handler with no cookie or session use is left alone (its auth may be middleware)", () => {
    expect(ids(file(`\tDB.Exec("UPDATE users SET email = ? WHERE id = ?", r.FormValue("email"), r.FormValue("id"))`))).not.toContain("csrf");
  });
});

describe("IDOR vs. authentication", () => {
  it("looking up the caller's own session by its cookie is not IDOR; a client-chosen record id still is", () => {
    const session = `\tcookie, err := r.Cookie("session_id")\n\tif err != nil {\n\t\treturn\n\t}\n\tvar uid string\n\t_ = DB.QueryRow("SELECT user_id FROM sessions WHERE token = ?", cookie.Value).Scan(&uid)\n`;
    expect(ids(file(session))).not.toContain("idor");
    // the cookie value itself is the credential, whatever the session table's column is called
    expect(ids(file(`\tc, err := r.Cookie("sid")\n\tif err != nil {\n\t\treturn\n\t}\n\tvar uid string\n\t_ = DB.QueryRow("SELECT user_id FROM logins WHERE id = ?", c.Value).Scan(&uid)\n`))).not.toContain("idor");
    // a .Value that is no cookie is still a client-chosen id
    expect(ids(file(`\tvar req struct{ Value string }\n\t_ = json.NewDecoder(r.Body).Decode(&req)\n\tvar body string\n\t_ = DB.QueryRow("SELECT body FROM notes WHERE id = ?", req.Value).Scan(&body)\n`))).toContain("idor");
    expect(ids(file(`\tcookie, err := r.Cookie("sid")\n\tif err != nil {\n\t\treturn\n\t}\n\tvar uid string\n\t_ = DB.QueryRow("SELECT user_id FROM logins WHERE id = ?", cookie.Value).Scan(&uid)\n`))).not.toContain("idor");
    expect(ids(file(`\ttok := r.Header.Get("X-Api-Key")\n\tvar uid string\n\t_ = DB.QueryRow("SELECT user_id FROM api_keys WHERE api_key = ?", tok).Scan(&uid)\n`))).not.toContain("idor");
    expect(ids(file(session + `\tid := r.URL.Query().Get("id")\n\tvar body string\n\t_ = DB.QueryRow("SELECT body FROM notes WHERE id = ?", id).Scan(&body)\n`))).toContain("idor");
  });
});

describe("weak randomness", () => {
  const src = (imp: string, body: string) => `package main\n\nimport (\n\t"encoding/hex"\n\t"fmt"\n\t${imp}\n\t"net/http"\n)\n\nfunc Handler(w http.ResponseWriter, r *http.Request) {\n${body}\n}\n`;
  const rid = (code: string) => analyzeFile("handlers/h.go", code).indicators.filter(i => i.id === "insecure-randomness").map(i => i.line);
  it("a math/rand value that becomes a token, through a buffer or a generator; crypto/rand or a shuffle is not", () => {
    expect(rid(src(`"math/rand"`, `\tb := make([]byte, 16)\n\tfor i := range b {\n\t\tb[i] = byte(rand.Intn(256))\n\t}\n\tsessionToken := hex.EncodeToString(b)\n\tfmt.Fprint(w, sessionToken)`))).toEqual([13]);
    expect(rid(src(`"math/rand"`, `\tsrc := rand.New(rand.NewSource(42))\n\tresetToken := fmt.Sprintf("%016x", src.Int63())\n\tfmt.Fprint(w, resetToken)`))).toEqual([12]);
    expect(rid(src(`"math/rand"`, `\tbuf := make([]byte, 16)\n\trand.Read(buf)\n\tid := hex.EncodeToString(buf)\n\thttp.SetCookie(w, &http.Cookie{Name: "sid", Value: id})`))).toEqual([12]);
    // a cookie struct built on its own line and handed to a helper
    expect(rid(src(`"math/rand"`, `\tbuf := make([]byte, 16)\n\trand.Read(buf)\n\tid := hex.EncodeToString(buf)\n\tc := &http.Cookie{Name: "sid", Value: id}\n\twriteCookie(w, c)`))).toEqual([12]);
    expect(rid(src(`"crypto/rand"`, `\tbuf := make([]byte, 16)\n\trand.Read(buf)\n\ttoken := hex.EncodeToString(buf)\n\tfmt.Fprint(w, token)`))).toEqual([]);
    expect(rid(src(`"math/rand"`, `\titems := []string{"a", "b"}\n\trand.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })\n\tdelay := rand.Intn(100)\n\tfmt.Fprint(w, items, delay)`))).toEqual([]);
  });
});

describe("information disclosure", () => {
  it("a stack trace or a contextual error in the response; the bare http.Error idiom is not", () => {
    expect(ids(file(`\tw.Write(debug.Stack())`))).toContain("verbose-error");
    expect(ids(file(`\terr := doWork()\n\tif err != nil {\n\t\thttp.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)\n\t}`))).toContain("verbose-error");
    expect(ids(file(`\terr := doWork()\n\tif err != nil {\n\t\thttp.Error(w, err.Error(), http.StatusInternalServerError)\n\t}`))).not.toContain("verbose-error");
  });
});
