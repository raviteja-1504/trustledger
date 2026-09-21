import { scanAstTaintGo, warmGoTaintEngine } from "@/lib/astTaintGo";

// Recall + precision for the Go AST engine: request-variable naming, stdlib passthroughs, out-parameters
// (Decode(&v)), container writes, channels, closures, package-level memory, and the sinks/structural checks
// added with them.

beforeAll(async () => { await warmGoTaintEngine(); }, 30000);

const ids = (code: string): string[] => scanAstTaintGo(code, "x.go").map(f => f.id);
const has = (code: string, id: string) => ids(code).includes(id);

const HEAD = `package main
import ("database/sql"; "encoding/json"; "fmt"; "net/http"; "os"; "os/exec"; "path/filepath"; "regexp"; "strings"; "net/url")
var db *sql.DB
`;
const handler = (body: string, top = "", reqName = "r") =>
  `${HEAD}\n${top}\nfunc h(w http.ResponseWriter, ${reqName} *http.Request) {\n${body}\n}\n`;
const SRC = (n = "r") => `${n}.URL.Query().Get("q")`;
const sql = (expr: string) => handler(`x := ${SRC()}\n\tdb.Query("SELECT " + ${expr})`);

describe("request variables and sources", () => {
  it.each(["r", "req", "request", "rq", "httpReq"])("a *http.Request parameter named %s is a source", (name) => {
    expect(has(handler(`db.Query("S " + ${SRC(name)})`, "", name), "sql-injection")).toBe(true);
  });
  it.each([
    ["URL.Query()[k]", `r.URL.Query()["q"][0]`],
    ["URL.Path", `r.URL.Path`],
    ["FormValue", `r.FormValue("q")`],
    ["PostFormValue", `r.PostFormValue("q")`],
    ["Header.Get", `r.Header.Get("X")`],
    ["Cookie", `r.Referer()`],
    ["Form map", `r.Form["q"][0]`],
  ])("%s", (_l, expr) => {
    expect(has(handler(`db.Query("S " + ${expr})`), "sql-injection")).toBe(true);
  });
  it("a body decoded with json fills its target with attacker data (and is NOT a deserialization finding)", () => {
    const code = handler(`var m map[string]string\n\tjson.NewDecoder(r.Body).Decode(&m)\n\tdb.Query("S " + m["k"])`);
    expect(has(code, "sql-injection")).toBe(true);
    expect(has(code, "insecure-deserialization")).toBe(false);
  });
  it("json.Unmarshal of tainted bytes fills its target", () => {
    const code = handler(`var m map[string]string\n\tjson.Unmarshal([]byte(r.FormValue("j")), &m)\n\tdb.Query("S " + m["k"])`);
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("gob decoding of a request body IS insecure deserialization", () => {
    const code = `${HEAD.replace('"encoding/json"', '"encoding/json"; "encoding/gob"')}\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tvar v interface{}\n\tgob.NewDecoder(r.Body).Decode(&v)\n}\n`;
    expect(has(code, "insecure-deserialization")).toBe(true);
  });
  it("a value that is not from the request is not a source", () => {
    expect(has(handler(`db.Query("S " + os.Getenv("X"))`), "sql-injection")).toBe(false);
  });
});

describe("propagation through the stdlib", () => {
  it.each([
    ["strings.TrimSpace", "strings.TrimSpace(x)"],
    ["strings.ReplaceAll", `strings.ReplaceAll(x, "a", "b")`],
    ["strings.Join", `strings.Join([]string{"a", x}, ",")`],
    ["url.QueryUnescape", "func() string { d, _ := url.QueryUnescape(x); return d }()"],
    ["string([]byte(x))", "string([]byte(x))"],
    ["fmt.Sprintf", `fmt.Sprintf("%s", x)`],
    ["append + Join", `strings.Join(append([]string{"a"}, x), ",")`],
    ["append with a spread argument", `strings.Join(append([]string{"a"}, strings.Split(x, ",")...), ",")`],
    ["Replacer.Replace", `strings.NewReplacer("a", "b").Replace(x)`],
  ])("%s keeps taint", (_l, expr) => {
    expect(has(sql(expr), "sql-injection")).toBe(true);
  });
  it("strconv numeric parsing neutralizes", () => {
    expect(has(handler(`n, _ := strconv.Atoi(${SRC()})\n\tdb.Query("S " + fmt.Sprint(n))`), "sql-injection")).toBe(false);
  });
  it("an opaque unknown call is untainted", () => {
    expect(has(sql("someUnknown(x)"), "sql-injection")).toBe(false);
  });
  it("a decoder re-taints what an HTML escaper cleared", () => {
    const code = handler(`x := ${SRC()}\n\td, _ := url.QueryUnescape(html.EscapeString(x))\n\tfmt.Fprint(w, "<b>"+d+"</b>")`);
    expect(has(code, "xss")).toBe(true);
  });
});

describe("containers, channels, closures, package-level memory", () => {
  it("assigning into a map by key taints the map", () => {
    expect(has(handler(`m := map[string]string{}\n\tm["k"] = ${SRC()}\n\tdb.Query("S " + m["k"])`), "sql-injection")).toBe(true);
  });
  it("strings.Builder.WriteString then String()", () => {
    expect(has(handler(`var b strings.Builder\n\tb.WriteString(${SRC()})\n\tdb.Query("S " + b.String())`), "sql-injection")).toBe(true);
  });
  it("a value sent on a channel arrives on the other side (including from a go func)", () => {
    const code = handler(`ch := make(chan string, 1)\n\tid := ${SRC()}\n\tgo func() { ch <- "S " + id }()\n\tq := <-ch\n\tdb.Query(q)`);
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("a func literal returning a captured value carries it when called", () => {
    const code = handler(`v := ${SRC()}\n\tf := func() string { return v }\n\tdb.Query("S " + f())`);
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("an immediately-invoked literal runs in the current scope", () => {
    const code = handler(`var out string\n\tfunc() { out = ${SRC()} }()\n\tdb.Query("S " + out)`);
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("a higher-order helper propagates through its callback parameter", () => {
    const top = `func withValue(v string, cb func(string) string) string { return cb(v) }`;
    expect(has(handler(`fmt.Fprint(w, withValue(${SRC()}, func(x string) string { return "<i>" + x + "</i>" }))`, top), "xss")).toBe(true);
  });
  it("a returned closure carries what it captured", () => {
    const top = `func mk(v string) func() string { c := v; return func() string { return "<h1>" + c + "</h1>" } }`;
    expect(has(handler(`fmt.Fprint(w, mk(${SRC()})())`, top), "xss")).toBe(true);
  });
  it("a method call resolves to a local method by name", () => {
    const top = `type repo struct{ db *sql.DB }\nfunc (u *repo) findByID(id string) { u.db.Query("S " + id) }`;
    expect(has(handler(`rp := &repo{db: db}\n\trp.findByID(${SRC()})`, top), "sql-injection")).toBe(true);
  });
  it("stored XSS: a package-level slice written by one handler and read by another (either order)", () => {
    const code = `${HEAD}
var comments []string
func render(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	for _, c := range comments { b.WriteString("<li>" + c + "</li>") }
	fmt.Fprint(w, b.String())
}
func store(w http.ResponseWriter, r *http.Request) { comments = append(comments, r.FormValue("c")) }
`;
    expect(has(code, "xss")).toBe(true);
  });
  it("second-order SQL through a package-level map", () => {
    const code = `${HEAD}
var saved = map[string]string{}
func save(w http.ResponseWriter, r *http.Request) { saved[r.FormValue("u")] = r.FormValue("s") }
func run(w http.ResponseWriter, r *http.Request) { db.Query("S '" + saved[r.URL.Query().Get("u")] + "'") }
`;
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("a local that shadows the package-level container is not tainted by it", () => {
    const code = `${HEAD}
var comments []string
func store(w http.ResponseWriter, r *http.Request) { comments = append(comments, r.FormValue("c")) }
func render(w http.ResponseWriter, r *http.Request) {
	comments := []string{"a", "b"}
	fmt.Fprint(w, strings.Join(comments, ","))
}
`;
    expect(has(code, "xss")).toBe(false);
  });
});

describe("new sinks", () => {
  it("XSS: writes to the response body", () => {
    expect(has(handler(`fmt.Fprint(w, ${SRC()})`), "xss")).toBe(true);
    expect(has(handler(`fmt.Fprintf(w, "<p>%s</p>", ${SRC()})`), "xss")).toBe(true);
    expect(has(handler(`w.Write([]byte(${SRC()}))`), "xss")).toBe(true);
    expect(has(handler(`io.WriteString(w, ${SRC()})`), "xss")).toBe(true);
  });
  it("a constant response and a JSON encode are not XSS", () => {
    expect(has(handler(`fmt.Fprint(w, "ok")`), "xss")).toBe(false);
    expect(has(handler(`json.NewEncoder(w).Encode(${SRC()})`), "xss")).toBe(false);
  });
  it("header injection through w.Header().Set", () => {
    expect(has(handler(`w.Header().Set("X-A", ${SRC()})`), "header-injection")).toBe(true);
    expect(has(handler(`w.Header().Set("X-A", "const")`), "header-injection")).toBe(false);
  });
  it("path traversal across the os / filepath surface", () => {
    expect(has(handler(`os.WriteFile(filepath.Join("/b", ${SRC()}), nil, 0644)`), "path-traversal")).toBe(true);
    expect(has(handler(`os.Remove(${SRC()})`), "path-traversal")).toBe(true);
    expect(has(handler(`http.ServeFile(w, r, ${SRC()})`), "path-traversal")).toBe(true);
  });
  it("SSRF through clients and raw dialing", () => {
    expect(has(handler(`client := &http.Client{}\n\tclient.Get(${SRC()})`), "ssrf")).toBe(true);
    expect(has(handler(`net.Dial("tcp", ${SRC()})`), "ssrf")).toBe(true);
  });
  it("SQL entry points beyond Query/Exec", () => {
    expect(has(handler(`db.QueryContext(r.Context(), "S "+${SRC()})`), "sql-injection")).toBe(true);
    expect(has(handler(`db.Prepare("S " + ${SRC()})`), "sql-injection")).toBe(true);
  });
  it("a bound parameter is not SQL injection", () => {
    expect(has(handler(`db.Query("SELECT * FROM t WHERE a = ?", ${SRC()})`), "sql-injection")).toBe(false);
  });
  it("a regular expression built from input", () => {
    expect(has(handler(`regexp.MustCompile(${SRC()})`), "redos")).toBe(true);
    expect(has(handler(`regexp.MustCompile("^a+$")`), "redos")).toBe(false);
  });
  it("template text controlled by the caller", () => {
    const code = `${HEAD.replace('"regexp"', '"regexp"; "text/template"')}\nfunc h(w http.ResponseWriter, r *http.Request) {\n\ttemplate.New("x").Parse(r.FormValue("t"))\n}\n`;
    expect(has(code, "ssti")).toBe(true);
  });
  it("plugin loading and reflection-selected members", () => {
    expect(has(handler(`plugin.Open(${SRC()})`), "eval-exec")).toBe(true);
    expect(has(handler(`reflect.ValueOf(h).MethodByName(${SRC()})`), "eval-exec")).toBe(true);
    expect(has(handler(`reflect.ValueOf(&cfg{}).Elem().FieldByName(${SRC()})`), "mass-assignment")).toBe(true);
  });
  it("NoSQL find/update with a request-derived filter", () => {
    expect(has(handler(`coll.FindOne(map[string]interface{}{"u": ${SRC()}})`), "nosql-injection")).toBe(true);
  });
  it("LDAP and XPath", () => {
    expect(has(handler(`ldap.NewSearchRequest("dc=x", 2, 0, 0, 0, false, "(uid="+${SRC()}+")", nil, nil)`), "ldap-injection")).toBe(true);
    expect(has(handler(`xmlquery.Find(doc, "//u[@n='"+${SRC()}+"']")`), "xpath-injection")).toBe(true);
    expect(has(handler(`xmlquery.Find(doc, "//u")`), "xpath-injection")).toBe(false);
  });
  it("string shapes: SQL / LDAP / XPath built around input by concat or Sprintf", () => {
    expect(has(handler(`x := ${SRC()}\n\t_ = fmt.Sprintf("SELECT * FROM t WHERE id = '%s'", x)`), "sql-injection")).toBe(true);
    expect(has(handler(`x := ${SRC()}\n\t_ = "(&(objectClass=person)(uid=" + x + "))"`), "ldap-injection")).toBe(true);
    expect(has(handler(`x := ${SRC()}\n\t_ = "/users/user[name/text()='" + x + "']"`), "xpath-injection")).toBe(true);
    expect(has(handler(`x := ${SRC()}\n\t_ = "Hello " + x`), "sql-injection")).toBe(false);
  });
  it("a secret compared with ==, but not a literal comparison", () => {
    expect(has(`${HEAD}\nconst appSecret = "s"\nfunc h(w http.ResponseWriter, r *http.Request) { if r.URL.Query().Get("t") == appSecret { } }`, "timing-attack")).toBe(true);
    expect(has(handler(`if ${SRC()} == "admin" { }`), "timing-attack")).toBe(false);
  });
  it("weak digests", () => {
    expect(has(handler(`_ = md5.Sum([]byte("x"))`), "weak-crypto")).toBe(true);
    expect(has(handler(`_ = sha256.Sum256([]byte("x"))`), "weak-crypto")).toBe(false);
  });
  it("hand-rolled JWT payload decode in a file with no verification", () => {
    const code = `${HEAD}\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tparts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")\n\tp, _ := base64.RawURLEncoding.DecodeString(parts[1])\n\tvar c map[string]interface{}\n\tjson.Unmarshal(p, &c)\n}\n`;
    expect(has(code, "jwt-none-alg")).toBe(true);
    expect(has(code.replace('"strings"', '"strings"; "github.com/golang-jwt/jwt/v5"'), "jwt-none-alg")).toBe(false);
  });
  it("decoding a request into a struct with role/admin-like fields", () => {
    const top = `type account struct { Email string; Role string }`;
    expect(has(handler(`var a account\n\tjson.NewDecoder(r.Body).Decode(&a)`, top), "mass-assignment")).toBe(true);
    const safe = `type dto struct { Email string; Name string }`;
    expect(has(handler(`var a dto\n\tjson.NewDecoder(r.Body).Decode(&a)`, safe), "mass-assignment")).toBe(false);
    const tagged = "type acct struct { Email string; Role string `json:\"-\"` }";
    expect(has(handler(`var a acct\n\tjson.NewDecoder(r.Body).Decode(&a)`, tagged), "mass-assignment")).toBe(false);
  });
  it("copying every entry of an attacker map, but not a counting loop", () => {
    const merge = `func merge(t, s map[string]interface{}) { for k, v := range s { t[k] = v } }`;
    expect(has(handler(`var in map[string]interface{}\n\tjson.NewDecoder(r.Body).Decode(&in)\n\tmerge(map[string]interface{}{}, in)`, merge), "mass-assignment")).toBe(true);
    const counting = handler(`counts := map[string]int{}\n\tfor _, w2 := range strings.Fields(${SRC()}) { counts[w2] = 1 }`);
    expect(has(counting, "mass-assignment")).toBe(false);
  });
});

describe("escaping", () => {
  const esc = `func escapeHTML(v string) string { return strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(v) }`;
  it("a local function that replaces < with an entity is an HTML escaper", () => {
    expect(has(handler(`fmt.Fprint(w, "<div>"+escapeHTML(${SRC()})+"</div>")`, esc), "xss")).toBe(false);
  });
  it("escape-then-append re-taints", () => {
    expect(has(handler(`fmt.Fprint(w, "<div>"+escapeHTML(${SRC()})+r.FormValue("s")+"</div>")`, esc), "xss")).toBe(true);
  });
  it("an escaped value inside <script> is still XSS; in a quoted attribute it is not", () => {
    expect(has(handler(`fmt.Fprintf(w, "<script>const x = '%s';</script>", escapeHTML(${SRC()}))`, esc), "xss")).toBe(true);
    expect(has(handler(`fmt.Fprintf(w, "<div data-v=\\"%s\\"></div>", escapeHTML(${SRC()}))`, esc), "xss")).toBe(false);
  });
});
