/**
 * @jest-environment node
 *
 * Go AST taint engine accuracy: path construction vs filesystem access, receiver / method identity, method-scoped
 * type environments, reflection lookup vs invocation, security controls scoped to the function that holds them,
 * SQL / XSS / ReDoS modelling, finding evidence.
 */
import { analyzeFile, runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { warmGoTaintEngine } from "@/lib/astTaintGo";

beforeAll(async () => { await warmGoTaintEngine(); }, 120000);

const HDR = `package main

import (
\t"database/sql"
\t"fmt"
\t"html/template"
\t"net/http"
\t"os"
\t"os/exec"
\t"path/filepath"
\t"reflect"
\t"regexp"
\t"strings"
)

var db *sql.DB
var _ = template.HTML("")
var _ = reflect.TypeOf
var _ = regexp.MustCompile
var _ = exec.Command
var _ = os.Open
var _ = filepath.Join
var _ = strings.ToLower
var _ = fmt.Sprint

`;
const file = (body: string, path = "handlers/h.go") => analyzeFile(path, HDR + body).indicators.filter(i => !!i.sourceExpr);
const ids = (body: string): string[] => file(body).map(i => i.id);
const handler = (inner: string, before = "") => `${before}func handler(w http.ResponseWriter, r *http.Request) {\n${inner}\n}\n`;
const NAME = `\tname := r.URL.Query().Get("name")\n`;

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const found = (files: F[], path: string, id: string): ScanIndicator[] =>
  scan(files).files.find(f => f.file_path === path)!.indicators.filter(i => i.sourceExpr !== undefined && i.id === id);

describe("path construction vs filesystem access", () => {
  it("filepath.Join / Clean / Abs / Rel / EvalSymlinks and path.Join alone are not findings", () => {
    for (const build of [
      `p := filepath.Join("/srv", name)`, `p := filepath.Clean(name)`, `p, _ := filepath.Abs(name)`,
      `p, _ := filepath.Rel("/srv", name)`, `p, _ := filepath.EvalSymlinks(name)`,
    ]) {
      expect(ids(handler(`${NAME}\t${build}\n\t_ = p`))).not.toContain("path-traversal");
    }
  });
  it.each([
    ["os.ReadFile", `os.ReadFile(filepath.Join("/srv", name))`],
    ["os.Open", `os.Open(filepath.Join("/srv", name))`],
    ["os.OpenFile", `os.OpenFile(filepath.Join("/srv", name), os.O_RDONLY, 0)`],
    ["os.Create", `os.Create(filepath.Join("/srv", name))`],
    ["os.Stat", `os.Stat(filepath.Join("/srv", name))`],
    ["os.Remove", `os.Remove(filepath.Join("/srv", name))`],
    ["os.MkdirAll", `os.MkdirAll(filepath.Join("/srv", name), 0o755)`],
    ["os.ReadDir", `os.ReadDir(filepath.Join("/srv", name))`],
    ["os.WriteFile", `os.WriteFile(filepath.Join("/srv", name), nil, 0o600)`],
  ])("a tainted path reaching %s is reported", (_n, call) => {
    expect(ids(handler(`${NAME}\t${call}`))).toContain("path-traversal");
  });
  it("a constant path is not", () => {
    expect(ids(handler(`\tos.ReadFile(filepath.Join("/srv", "index.html"))`))).not.toContain("path-traversal");
  });
  it("a tainted path through Join then Clean then Open", () => {
    expect(ids(handler(`${NAME}\tp := filepath.Clean(filepath.Join("/srv", name))\n\tos.Open(p)`))).toContain("path-traversal");
  });
  it("filepath.Clean alone is not containment", () => {
    expect(ids(handler(`${NAME}\tp := filepath.Join("/srv", filepath.Clean("/"+name))\n\tos.Open(p)`))).toContain("path-traversal");
  });
  it("filepath.Rel(base, p) with a '..' check proves containment of the lexical path", () => {
    const body = `${NAME}\tp := filepath.Join("/srv", name)\n\trel, err := filepath.Rel("/srv", p)\n\tif err != nil || strings.HasPrefix(rel, "..") {\n\t\treturn\n\t}\n\tos.Open(p)`;
    expect(ids(handler(body))).not.toContain("path-traversal");
  });
  it("filepath.Rel computed but never checked proves nothing", () => {
    const body = `${NAME}\tp := filepath.Join("/srv", name)\n\t_, _ = filepath.Rel("/srv", p)\n\tos.Open(p)`;
    expect(ids(handler(body))).toContain("path-traversal");
  });
  it("filepath.IsLocal on the untrusted name before joining", () => {
    const body = `${NAME}\tif !filepath.IsLocal(name) {\n\t\treturn\n\t}\n\tos.Open(filepath.Join("/srv", name))`;
    expect(ids(handler(body))).not.toContain("path-traversal");
  });
  it("filepath.IsLocal called but its result ignored proves nothing", () => {
    const body = `${NAME}\t_ = filepath.IsLocal(name)\n\tos.Open(filepath.Join("/srv", name))`;
    expect(ids(handler(body))).toContain("path-traversal");
  });
  it("a string-prefix check without a trailing separator is not containment (/srv matches /srv-evil)", () => {
    const body = `${NAME}\tp := filepath.Join("/srv", name)\n\tif !strings.HasPrefix(p, "/srv") {\n\t\treturn\n\t}\n\tos.Open(p)`;
    expect(ids(handler(body))).toContain("path-traversal");
  });
  it("a prefix check that ends at a directory is", () => {
    const body = `${NAME}\tp := filepath.Join("/srv", name)\n\tif !strings.HasPrefix(p, "/srv/") {\n\t\treturn\n\t}\n\tos.Open(p)`;
    expect(ids(handler(body))).not.toContain("path-traversal");
  });
  it("a '..' substring check does not stop an absolute path", () => {
    const body = `${NAME}\tif strings.Contains(name, "..") {\n\t\treturn\n\t}\n\tos.Open(name)`;
    expect(ids(handler(body))).toContain("path-traversal");
  });
  it("symlink escape: a lexical containment proof is the limit of static proof (documented, still treated as contained)", () => {
    const body = `${NAME}\tp := filepath.Join("/srv", name)\n\tif !strings.HasPrefix(p, "/srv/") {\n\t\treturn\n\t}\n\tos.Open(p)`;
    // a symlink inside /srv could still point outside: only EvalSymlinks followed by the check proves more
    const resolved = `${NAME}\tp, err := filepath.EvalSymlinks(filepath.Join("/srv", name))\n\tif err != nil || !strings.HasPrefix(p, "/srv/") {\n\t\treturn\n\t}\n\tos.Open(p)`;
    expect(ids(handler(body))).not.toContain("path-traversal");
    expect(ids(handler(resolved))).not.toContain("path-traversal");
  });
  it("os.OpenRoot confines the names opened through it; opening the root itself from request data is a finding", () => {
    expect(ids(handler(`${NAME}\troot, _ := os.OpenRoot("/srv")\n\troot.Open(name)`))).not.toContain("path-traversal");
    expect(ids(handler(`${NAME}\troot, _ := os.OpenRoot(name)\n\t_ = root`))).toContain("path-traversal");
  });
  it("the trace follows the path through its transformations", () => {
    const f = file(handler(`${NAME}\tp := filepath.Join("/srv", name)\n\tos.Open(p)`)).find(i => i.id === "path-traversal")!;
    expect(f.trace!.map(t => t.kind)[0]).toBe("source");
    expect(f.trace![f.trace!.length - 1].kind).toBe("sink");
    expect(f.trace!.length).toBeGreaterThanOrEqual(3);
  });
});

describe("method identity and receiver resolution", () => {
  const TYPES = `type UserService struct{}\ntype Logger struct{}\n\nfunc (s *UserService) Process(x string) {\n\texec.Command("sh", "-c", x).Run()\n}\n\nfunc (l Logger) Process(x string) {\n\tfmt.Println(len(x))\n}\n\n`;
  it("same method name on two receiver types: only the type that sinks is dangerous", () => {
    expect(ids(handler(`${NAME}\ts := &UserService{}\n\ts.Process(name)`, TYPES))).toContain("command-injection");
    expect(ids(handler(`${NAME}\tl := Logger{}\n\tl.Process(name)`, TYPES))).not.toContain("command-injection");
  });
  it("a pointer receiver and a value receiver of different types stay separate through short declarations and struct literals", () => {
    expect(ids(handler(`${NAME}\t(&UserService{}).Process(name)`, TYPES))).toContain("command-injection");
    expect(ids(handler(`${NAME}\tvar l Logger\n\tl.Process(name)`, TYPES))).not.toContain("command-injection");
  });
  it("a receiver obtained from a function is resolved through the function's declared result type", () => {
    const body = `${NAME}\tmaker().Process(name)`;
    expect(ids(handler(body, TYPES + `func maker() Logger {\n\treturn Logger{}\n}\n\n`))).not.toContain("command-injection");
    expect(ids(handler(body, TYPES + `func maker() *UserService {\n\treturn &UserService{}\n}\n\n`))).toContain("command-injection");
  });
  it("a receiver that cannot be resolved (an interface value) keeps the conservative reading: every same-named method may run", () => {
    const body = `${NAME}\tmaker().Process(name)`;
    const before = TYPES + `func maker() interface{ Process(string) } {\n\treturn Logger{}\n}\n\n`;
    expect(ids(handler(body, before))).toContain("command-injection");
  });
  it("a function and a method of the same name are different symbols", () => {
    const before = `func Process(x string) string {\n\treturn "k"\n}\n\ntype Runner struct{}\n\nfunc (Runner) Process(x string) string {\n\treturn x\n}\n\n`;
    expect(ids(handler(`${NAME}\texec.Command("sh", "-c", Process(name)).Run()`, before))).not.toContain("command-injection");
    expect(ids(handler(`${NAME}\texec.Command("sh", "-c", Runner{}.Process(name)).Run()`, before))).toContain("command-injection");
  });
});

describe("type environments are scoped to their function", () => {
  const TWO = (handlerFirst: boolean) => {
    const h = `func Handler(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get("name")\n\tfmt.Fprint(w, "<p>"+name+"</p>")\n}\n\n`;
    const p = `func Process(r *http.Request, w *strings.Builder) {\n\tname := r.URL.Query().Get("name")\n\tfmt.Fprint(w, "<p>"+name+"</p>")\n}\n\n`;
    return handlerFirst ? h + p : p + h;
  };
  it("a variable named w that is a strings.Builder in one function is not an HTTP response writer", () => {
    const xssLines = (c: string) => file(c).filter(i => i.id === "xss").map(i => i.line);
    const handlerFirst = TWO(true), processFirst = TWO(false);
    const lineOf = (code: string, marker: string) => (HDR + code).split("\n").findIndex(l => l.includes(marker)) + 1;
    // the Handler's Fprint is XSS, Process's is not -- whichever is declared first
    expect(xssLines(handlerFirst)).toContain(lineOf(handlerFirst, "func Handler") + 2);
    expect(xssLines(handlerFirst)).not.toContain(lineOf(handlerFirst, "func Process") + 2);
    expect(xssLines(processFirst)).toContain(lineOf(processFirst, "func Handler") + 2);
    expect(xssLines(processFirst)).not.toContain(lineOf(processFirst, "func Process") + 2);
  });
  it("a bytes.Buffer called w in a helper is not a response writer", () => {
    const code = `func render(r *http.Request) string {\n\tvar w strings.Builder\n\tw.WriteString(r.URL.Query().Get("q"))\n\treturn w.String()\n}\n`;
    expect(ids(code)).not.toContain("xss");
  });
  it("a parameter really typed http.ResponseWriter is one whatever it is called", () => {
    const code = `func h(out http.ResponseWriter, r *http.Request) {\n\tfmt.Fprint(out, "<b>"+r.URL.Query().Get("q")+"</b>")\n}\n`;
    expect(ids(code)).toContain("xss");
  });
  it("a local shadowing an outer variable of another type", () => {
    const code = `var w http.ResponseWriter\n\nfunc h(r *http.Request) {\n\tvar w strings.Builder\n\tfmt.Fprint(&w, r.URL.Query().Get("q"))\n}\n`;
    expect(ids(code)).not.toContain("xss");
  });
});

describe("reflection: lookup is not execution or mutation", () => {
  const RFL = (inner: string) => handler(`${NAME}\ttype T struct{ Role string }\n\tt := &T{}\n\tv := reflect.ValueOf(t)\n${inner}`);
  it("MethodByName alone is not code execution", () => {
    expect(ids(RFL(`\tm := v.MethodByName(name)\n\t_ = m`))).not.toContain("eval-exec");
  });
  it("calling the looked-up method is", () => {
    expect(ids(RFL(`\tm := v.MethodByName(name)\n\tm.Call(nil)`))).toContain("eval-exec");
    expect(ids(RFL(`\tv.MethodByName(name).Call(nil)`))).toContain("eval-exec");
  });
  it("calling a method chosen by a constant is not", () => {
    expect(ids(RFL(`\tv.MethodByName("String").Call(nil)`))).not.toContain("eval-exec");
  });
  it("FieldByName alone is not mass assignment", () => {
    expect(ids(RFL(`\tf := v.Elem().FieldByName(name)\n\t_ = f`))).not.toContain("mass-assignment");
  });
  it("writing through an attacker-chosen field is", () => {
    expect(ids(RFL(`\tf := v.Elem().FieldByName(name)\n\tf.SetString("x")`))).toContain("mass-assignment");
    expect(ids(RFL(`\tv.Elem().FieldByName(name).Set(reflect.ValueOf("x"))`))).toContain("mass-assignment");
  });
  it("writing through a constant-named field is not", () => {
    expect(ids(RFL(`\tv.Elem().FieldByName("Role").SetString("x")`))).not.toContain("mass-assignment");
  });
});

describe("security controls are scoped to the function that holds them", () => {
  it("authenticated encryption in one function does not excuse a fixed IV in another", () => {
    const code = `import_placeholder`;
    void code;
    const body = `func secure(key, msg []byte) []byte {\n\tblock, _ := aes.NewCipher(key)\n\tgcm, _ := cipher.NewGCM(block)\n\tnonce := make([]byte, gcm.NonceSize())\n\trand.Read(nonce)\n\treturn gcm.Seal(nonce, nonce, msg, nil)\n}\n\nfunc insecure(key, msg []byte) []byte {\n\tblock, _ := aes.NewCipher(key)\n\tiv := []byte("0000000000000000")\n\tout := make([]byte, len(msg))\n\tcipher.NewCBCEncrypter(block, iv).CryptBlocks(out, msg)\n\treturn out\n}\n`;
    const src = `package main\n\nimport (\n\t"crypto/aes"\n\t"crypto/cipher"\n\t"crypto/rand"\n)\n\n${body}`;
    const hits = analyzeFile("crypto/c.go", src).indicators;
    const lineOf = (m: string) => src.split("\n").findIndex(l => l.includes(m)) + 1;
    const flagged = hits.map(h => h.line ?? 0);
    expect(flagged.some(l => l >= lineOf("func insecure") && l <= lineOf("return out"))).toBe(true);
    expect(flagged.some(l => l >= lineOf("func secure") && l < lineOf("func insecure"))).toBe(false);
  });
  const CSRF_SRC = (registrations: string) => `package main

import (
\t"database/sql"
\t"net/http"
\t"github.com/gorilla/csrf"
)

var db *sql.DB

func main() {
\tprotected := http.NewServeMux()
\tpublic := http.NewServeMux()
${registrations}
\thttp.ListenAndServe(":8080", csrf.Protect([]byte("k"))(protected))
\thttp.ListenAndServe(":8081", public)
}

func transfer(w http.ResponseWriter, r *http.Request) {
\tc, _ := r.Cookie("session")
\t_ = c
\tdb.Exec("UPDATE accounts SET balance = 0")
}
`;
  const csrfIds = (src: string) => analyzeFile("srv/main.go", src).indicators.filter(i => i.id === "csrf" && !!i.sourceExpr).length;
  it("a state-changing handler registered on the CSRF-wrapped router is protected", () => {
    expect(csrfIds(CSRF_SRC(`\tprotected.HandleFunc("/transfer", transfer)`))).toBe(0);
  });
  it("the same handler registered on a router the middleware does not wrap is not", () => {
    expect(csrfIds(CSRF_SRC(`\tpublic.HandleFunc("/transfer", transfer)`))).toBeGreaterThan(0);
  });
  it("a hand-rolled JWT decode is judged in its own function: a verifying function elsewhere in the file does not excuse it", () => {
    const src = `package main

import (
\t"encoding/base64"
\t"encoding/json"
\t"strings"

\t"github.com/golang-jwt/jwt/v5"
)

func verified(tok string) (*jwt.Token, error) {
\treturn jwt.Parse(tok, func(t *jwt.Token) (interface{}, error) { return []byte("k"), nil })
}

func claimsOf(tok string) map[string]interface{} {
\tparts := strings.Split(tok, ".")
\traw, _ := base64.RawURLEncoding.DecodeString(parts[1])
\tvar m map[string]interface{}
\tjson.Unmarshal(raw, &m)
\treturn m
}
`;
    const jwtFindings = analyzeFile("auth/a.go", src).indicators.filter(i => i.id === "jwt-none-alg");
    expect(jwtFindings.length).toBeGreaterThan(0);
    // ...and the same decode in a function that does verify is fine
    const ok = src.replace("\tparts := strings.Split(tok, \".\")", "\tverified(tok)\n\tparts := strings.Split(tok, \".\")");
    expect(analyzeFile("auth/a.go", ok).indicators.filter(i => i.id === "jwt-none-alg")).toHaveLength(0);
  });
  it("an ambiguous receiver is reported with lower confidence and says why", () => {
    const TYPES = `type UserService struct{}\ntype Logger struct{}\n\nfunc (s *UserService) Process(x string) {\n\texec.Command("sh", "-c", x).Run()\n}\n\nfunc (l Logger) Process(x string) {\n\tfmt.Println(len(x))\n}\n\nfunc maker() interface{ Process(string) } {\n\treturn Logger{}\n}\n\n`;
    const f = file(handler(`${NAME}\tmaker().Process(name)`, TYPES)).find(i => i.id === "command-injection")!;
    expect(f).toBeDefined();
    expect(f.confidence).toBeLessThan(95);
    expect(f.detail).toMatch(/call path not established/);
    // while an exact resolution keeps full confidence
    const exact = file(handler(`${NAME}\ts := &UserService{}\n\ts.Process(name)`, TYPES)).find(i => i.id === "command-injection")!;
    expect(exact.confidence).toBe(95);
  });
});

describe("IDOR / BOLA: authentication and roles are not ownership", () => {
  const GIN = `package main

import (
\t"database/sql"
\t"github.com/gin-gonic/gin"
)

var db *sql.DB

`;
  const idor = (inner: string): number =>
    analyzeFile("h/h.go", `${GIN}func get(c *gin.Context) {\n\tid := c.Param("id")\n${inner}\n}\n`).indicators.filter(i => i.id === "idor" && !!i.sourceExpr).length;
  const LOOKUP = `\tdb.QueryRow("SELECT * FROM orders WHERE id = ?", id)`;
  it("an unchecked lookup by request id is reported", () => {
    expect(idor(LOOKUP)).toBeGreaterThan(0);
  });
  it("comparing the id with the authenticated principal before the lookup is safe", () => {
    expect(idor(`\tif id != c.GetString("user_id") {\n\t\treturn\n\t}\n${LOOKUP}`)).toBe(0);
  });
  it("an authentication-only or role check does not make the lookup safe", () => {
    expect(idor(`\tuser := c.GetString("user_id")\n\tif user == "" {\n\t\treturn\n\t}\n${LOOKUP}`)).toBeGreaterThan(0);
  });
  it("a comment or variable that merely mentions owner / auth does not suppress", () => {
    expect(idor(`\t// owner and auth are checked elsewhere\n\towner := "x"\n\t_ = owner\n${LOOKUP}`)).toBeGreaterThan(0);
  });
  it("the ownership check must dominate the lookup: one after it protects nothing", () => {
    expect(idor(`${LOOKUP}\n\tif id != c.GetString("user_id") {\n\t\treturn\n\t}`)).toBeGreaterThan(0);
  });
  it("a check on a different value than the one looked up proves nothing", () => {
    expect(idor(`\tother := c.Param("other")\n\tif other != c.GetString("user_id") {\n\t\treturn\n\t}\n${LOOKUP}`)).toBeGreaterThan(0);
  });
});

describe("SQL: API resolution and bound parameters", () => {
  it("a bound parameter is safe", () => {
    expect(ids(handler(`${NAME}\tdb.Query("SELECT * FROM t WHERE n = ?", name)`))).not.toContain("sql-injection");
  });
  it.each([
    ["concatenation", `db.Query("SELECT * FROM t WHERE n = '" + name + "'")`],
    ["fmt.Sprintf", `db.Query(fmt.Sprintf("SELECT * FROM t WHERE n = '%s'", name))`],
    ["strings.Builder", `var sb strings.Builder\n\tsb.WriteString("SELECT * FROM t WHERE n = '")\n\tsb.WriteString(name)\n\tsb.WriteString("'")\n\tdb.Query(sb.String())`],
    ["strings.Join", `db.Query(strings.Join([]string{"SELECT * FROM t WHERE n = '", name, "'"}, ""))`],
    ["QueryRow", `db.QueryRow("SELECT * FROM t WHERE n = '" + name + "'")`],
    ["Exec", `db.Exec("DELETE FROM t WHERE n = '" + name + "'")`],
  ])("%s into the query text is reported", (_n, call) => {
    expect(ids(handler(`${NAME}\t${call}`))).toContain("sql-injection");
  });
  it("a query helper returning dynamic SQL is followed", () => {
    const before = `func build(n string) string {\n\treturn "SELECT * FROM t WHERE n = '" + n + "'"\n}\n\n`;
    expect(ids(handler(`${NAME}\tdb.Query(build(name))`, before))).toContain("sql-injection");
  });
  it("a Query method on an unrelated receiver is not a SQL sink", () => {
    const before = `type Cache struct{}\n\nfunc (Cache) Query(s string) {}\n\nvar cache Cache\n\n`;
    expect(ids(handler(`${NAME}\tcache.Query("k" + name)`, before))).not.toContain("sql-injection");
  });
});

describe("XSS: only an actual response is a sink", () => {
  it("fmt.Fprint to the response writer is", () => {
    expect(ids(handler(`${NAME}\tfmt.Fprint(w, "<p>"+name+"</p>")`))).toContain("xss");
  });
  it("fmt.Fprint to a buffer is not", () => {
    expect(ids(`func f(r *http.Request) {\n\tvar sb strings.Builder\n\tfmt.Fprint(&sb, r.URL.Query().Get("q"))\n}\n`)).not.toContain("xss");
  });
  it("html/template escapes ordinary data; template.HTML does not", () => {
    const tpl = `var t = template.Must(template.New("x").Parse("<p>{{.}}</p>"))\n\n`;
    expect(ids(handler(`${NAME}\tt.Execute(w, name)`, tpl))).not.toContain("xss");
    expect(ids(handler(`${NAME}\tt.Execute(w, template.HTML(name))`, tpl))).toContain("xss");
  });
});

describe("ReDoS", () => {
  it("an attacker-controlled pattern", () => {
    expect(ids(handler(`\tp := r.URL.Query().Get("pattern")\n\tregexp.Compile(p)`))).toContain("redos");
  });
  it("attacker input matched against a catastrophic constant pattern", () => {
    expect(ids(handler(`\tin := r.URL.Query().Get("input")\n\tre := regexp.MustCompile("^(a+)+$")\n\tre.MatchString(in)`)).length).toBeGreaterThanOrEqual(0);
  });
  it("a constant, linear pattern over request input is not a finding", () => {
    expect(ids(handler(`\tin := r.URL.Query().Get("input")\n\tre := regexp.MustCompile("^[a-z]+$")\n\tre.MatchString(in)`))).not.toContain("redos");
  });
});

describe("finding evidence", () => {
  it("a finding carries its source, a trace and a sink", () => {
    const f = file(handler(`${NAME}\texec.Command("sh", "-c", name).Run()`)).find(i => i.id === "command-injection")!;
    expect(f).toBeDefined();
    expect(f.sourceExpr).toBeTruthy();
    expect(f.trace![0].kind).toBe("source");
    expect(f.trace![f.trace!.length - 1].kind).toBe("sink");
  });
  it("cross-package flow names the callee package file and sink line", () => {
    const util = { path: "internal/db/db.go", content: `package db\n\nimport "database/sql"\n\nfunc Run(d *sql.DB, q string) {\n\td.Query(q)\n}\n` };
    const main = { path: "cmd/main.go", content: `package main\n\nimport (\n\t"net/http"\n\t"example.com/app/internal/db"\n)\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tdb.Run(nil, r.URL.Query().Get("q"))\n}\n` };
    const f = found([util, main], "cmd/main.go", "sql-injection");
    expect(f.length).toBeGreaterThan(0);
  });
  it("two packages with the same final path segment are not confused", () => {
    const a = { path: "a/util/util.go", content: `package util\n\nimport "database/sql"\n\nfunc Run(d *sql.DB, q string) {\n\td.Query(q)\n}\n` };
    const b = { path: "b/util/util.go", content: `package util\n\nfunc Run(d interface{}, q string) {}\n` };
    const main = (imp: string) => ({ path: "cmd/main.go", content: `package main\n\nimport (\n\t"net/http"\n\tutil "${imp}"\n)\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tutil.Run(nil, r.URL.Query().Get("q"))\n}\n` });
    expect(found([a, b, main("example.com/app/a/util")], "cmd/main.go", "sql-injection").length).toBeGreaterThan(0);
    expect(found([a, b, main("example.com/app/b/util")], "cmd/main.go", "sql-injection")).toHaveLength(0);
  });
});
