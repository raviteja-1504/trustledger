/**
 * @jest-environment node
 *
 * Go engine guards and value tracking ported from the Python/Java/Rust work (found scoring the 0llino sast-benchmark
 * Go suite): prepared statements, literal-map / URL-host / substring / prefix / regex / HMAC guards, constant-folded
 * `if`, literal-key map and struct-literal field slots, the proven-constant veto of the regex layer, string-typed
 * mongo values, net.ParseIP, and argument injection that respects validation.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmGoTaintEngine } from "@/lib/astTaintGo";

beforeAll(async () => { await warmGoTaintEngine(); }, 120000);

/** A net/http handler with the given body (plus optional package-level declarations). */
const handler = (body: string, decls = "") =>
  `package handlers\n\nimport (\n\t"net/http"\n)\n\n${decls}\nfunc Handle(w http.ResponseWriter, r *http.Request) {\n${body}\n}\n`;
const lines = (code: string, id: string) =>
  analyzeFile("handlers/h.go", code).indicators.filter(i => i.id === id).map(i => i.line);
const has = (code: string, id: string) => lines(code, id).length > 0;

describe("SQL", () => {
  it("arguments of a prepared statement are bind values, not query text", () => {
    const body = (exec: string) => `\tid := r.URL.Query().Get("id")\n\tstmt, _ := DB.Prepare("DELETE FROM users WHERE id = ?")\n\t${exec}`;
    expect(has(handler(body(`stmt.Exec(id)`)), "sql-injection")).toBe(false);
    expect(has(handler(body(`DB.Exec("DELETE FROM users WHERE id = " + id)`)), "sql-injection")).toBe(true);
    const param = (t: string) => `package handlers\n\nimport (\n\t"database/sql"\n\t"net/http"\n)\n\nfunc Handle(w http.ResponseWriter, r *http.Request, stmt ${t}) {\n\tid := r.URL.Query().Get("id")\n\tstmt.QueryRow(id)\n}\n`;
    expect(lines(param("*sql.Stmt"), "sql-injection").length).toBe(0);
    expect(lines(param("*sql.DB"), "sql-injection").length).toBeGreaterThan(0);
  });

  it("a constant query with a concatenated bind value is not interpolation", () => {
    expect(has(handler(`\tq := r.URL.Query().Get("q")\n\trows, _ := DB.Query("SELECT * FROM p WHERE name LIKE ?", "%"+q+"%")\n\t_ = rows`), "sql-injection")).toBe(false);
  });

  it("a value overwritten on the only path that runs is a proven constant", () => {
    const body = (cond: string) => `\tparam := r.URL.Query().Get("id")\n\tbar := param\n\tif ${cond} {\n\t\tbar = "1"\n\t}\n\trows, _ := DB.Query("SELECT * FROM users WHERE id = " + bar)\n\t_ = rows`;
    expect(has(handler(body("7*42 > 200")), "sql-injection")).toBe(false);
    expect(has(handler(body("7*42 < 200")), "sql-injection")).toBe(true);
    // a constant-false condition never runs its arm
    expect(has(handler(`\tparam := r.URL.Query().Get("id")\n\tif 1 > 2 {\n\t\trows, _ := DB.Query("SELECT * FROM users WHERE id = " + param)\n\t\t_ = rows\n\t}`), "sql-injection")).toBe(false);
    // a local that is modified (num++) is not the constant it was bound to
    expect(has(handler(`\tparam := r.URL.Query().Get("id")\n\tnum := 5\n\tnum++\n\tbar := param\n\tif num == 5 {\n\t\tbar = "1"\n\t}\n\trows, _ := DB.Query("SELECT * FROM users WHERE id = " + bar)\n\t_ = rows`), "sql-injection")).toBe(true);
    // len of a literal folds too
    expect(has(handler(`\tparam := r.URL.Query().Get("id")\n\tnum := len("abcdefghij")\n\tbar := param\n\tif num > 5 {\n\t\tbar = "1"\n\t}\n\trows, _ := DB.Query("SELECT * FROM users WHERE id = " + bar)\n\t_ = rows`), "sql-injection")).toBe(false);
  });

  it("a column read from a literal-valued map (with a literal fallback) is a proven constant", () => {
    const decls = `var sortCols = map[string]string{"name": "name", "date": "created_at"}\n`;
    const body = `\tkey := r.URL.Query().Get("sort")\n\tcol, ok := sortCols[key]\n\tif !ok {\n\t\tcol = "id"\n\t}\n\trows, _ := DB.Query("SELECT * FROM t ORDER BY " + col)\n\t_ = rows`;
    expect(has(handler(body, decls), "sql-injection")).toBe(false);
    expect(has(handler(body.replace(`col = "id"`, `col = key`), decls), "sql-injection")).toBe(true);
    // a map whose values aren't all literals proves nothing about what it returns
    expect(has(handler(body, `var sortCols = map[string]string{"name": os.Getenv("SORT_COL")}\n`), "sql-injection")).toBe(true);
  });

  it("a trailing target of a multi-value assignment is no longer the constant it held", () => {
    const body = `\tparam := r.URL.Query().Get("id")\n\tname := "guest"\n\tid, name := lookup(param)\n\t_ = id\n\trows, _ := DB.Query("SELECT * FROM users WHERE name = '" + name + "'")\n\t_ = rows`;
    expect(has(handler(body), "sql-injection")).toBe(true);
  });

  it("a map read under a literal key carries only what was stored there", () => {
    const body = (key: string) => `\tparam := r.URL.Query().Get("id")\n\tm := make(map[string]string)\n\tm["tainted"] = param\n\tm["default"] = "guest"\n\tbar := m["${key}"]\n\trows, _ := DB.Query("SELECT * FROM users WHERE name = '" + bar + "'")\n\t_ = rows`;
    expect(has(handler(body("default")), "sql-injection")).toBe(false);
    expect(has(handler(body("tainted")), "sql-injection")).toBe(true);
  });

  it("a struct-literal field overwritten with a constant no longer carries the input", () => {
    const decls = `type fileReq struct{ ID string; Name string }\n`;
    const body = (overwrite: string) => `\tparam := r.URL.Query().Get("id")\n\treq := fileReq{ID: param}\n\t${overwrite}\n\trows, _ := DB.Query("SELECT * FROM users WHERE id = " + req.ID)\n\t_ = rows`;
    expect(has(handler(body(`req.ID = "1"`), decls), "sql-injection")).toBe(false);
    expect(has(handler(body(`req.Name = "x"`), decls), "sql-injection")).toBe(true);
  });
});

describe("guards", () => {
  it("membership in a literal map[string]bool allowlist", () => {
    const decls = `var allowedTables = map[string]bool{"users": true, "orders": true}\n`;
    const body = (cond: string) => `\ttable := r.URL.Query().Get("table")\n\tif ${cond} {\n\t\treturn\n\t}\n\trows, _ := DB.Query("SELECT COUNT(*) FROM " + table)\n\t_ = rows`;
    expect(has(handler(body("!allowedTables[table]"), decls), "sql-injection")).toBe(false);
    expect(has(handler(body("allowedTables[table]"), decls), "sql-injection")).toBe(true);
  });

  it("an allowlisted parsed host vets the URL and the string it was parsed from", () => {
    const decls = `var allowedHosts = map[string]bool{"example.com": true}\n`;
    const body = (key: string, sink: string) => `\ttarget := r.URL.Query().Get("url")\n\tparsed, err := url.Parse(target)\n\tif err != nil {\n\t\treturn\n\t}\n\tif !allowedHosts[${key}] {\n\t\treturn\n\t}\n\t${sink}`;
    expect(has(handler(body("parsed.Host", `http.Redirect(w, r, parsed.String(), http.StatusFound)`), decls), "open-redirect")).toBe(false);
    expect(has(handler(body("parsed.Hostname()", `resp, _ := http.Get(target)\n\t_ = resp`), decls), "ssrf")).toBe(false);
    expect(has(handler(body("parsed.Path", `http.Redirect(w, r, parsed.String(), http.StatusFound)`), decls), "open-redirect")).toBe(true);
  });

  it("strings.Contains(x, \"..\") rules out traversal, not SQL", () => {
    const guard = `\tname := r.URL.Query().Get("file")\n\tif strings.Contains(name, "..") {\n\t\treturn\n\t}\n`;
    expect(has(handler(`${guard}\tdata, _ := os.ReadFile("/data/" + name)\n\t_ = data`), "path-traversal")).toBe(false);
    expect(has(handler(`${guard}\trows, _ := DB.Query("SELECT * FROM f WHERE n = '" + name + "'")\n\t_ = rows`), "sql-injection")).toBe(true);
    expect(has(handler(`\tname := r.URL.Query().Get("file")\n\tif strings.Contains(name, "x") {\n\t\treturn\n\t}\n\tdata, _ := os.ReadFile("/data/" + name)\n\t_ = data`), "path-traversal")).toBe(true);
  });

  it("strings.HasPrefix on a cleaned/absolute path confines it", () => {
    const body = (wrap: string) => `\tname := r.URL.Query().Get("file")\n\tbase := "/var/data"\n\tp := ${wrap}\n\tif !strings.HasPrefix(p, base) {\n\t\treturn\n\t}\n\tdata, _ := os.ReadFile(p)\n\t_ = data`;
    expect(has(handler(body(`filepath.Clean(filepath.Join(base, name))`)), "path-traversal")).toBe(false);
    expect(has(handler(body(`base + "/" + name`)), "path-traversal")).toBe(true);
  });

  it("a bound filepath.Join is judged where the path is used; an inline one is still a finding", () => {
    expect(has(handler(`\tname := r.URL.Query().Get("file")\n\tp := filepath.Join("/var/data", name)\n\tif strings.Contains(p, "..") {\n\t\treturn\n\t}\n\tdata, _ := os.ReadFile(p)\n\t_ = data`), "path-traversal")).toBe(false);
    expect(has(handler(`\tname := r.URL.Query().Get("file")\n\tsave(filepath.Join("/var/data", name))`), "path-traversal")).toBe(true);
  });

  it("an anchored regexp character class, local or package-level", () => {
    const local = (cls: string) => `\tname := r.URL.Query().Get("file")\n\tvalid := regexp.MustCompile(\`^[${cls}]+$\`)\n\tif !valid.MatchString(name) {\n\t\treturn\n\t}\n\thttp.ServeFile(w, r, "./static/"+name)`;
    expect(has(handler(local("a-zA-Z0-9_.-")), "path-traversal")).toBe(false);
    expect(has(handler(local("a-zA-Z0-9_./")), "path-traversal")).toBe(true);
    const pkg = `var validName = regexp.MustCompile(\`^[a-z0-9]+$\`)\n`;
    expect(has(handler(`\tname := r.URL.Query().Get("file")\n\tif !validName.MatchString(name) {\n\t\treturn\n\t}\n\thttp.ServeFile(w, r, "./static/"+name)`, pkg), "path-traversal")).toBe(false);
  });

  it("a literal own-origin prefix makes a redirect target relative", () => {
    const body = (prefix: string) => `\tnext := r.URL.Query().Get("next")\n\tif !strings.HasPrefix(next, "${prefix}") {\n\t\tnext = "/app/"\n\t}\n\thttp.Redirect(w, r, next, http.StatusFound)`;
    expect(has(handler(body("/app/")), "open-redirect")).toBe(false);
    // "/" alone still admits "//evil.com" and "/\\evil.com"
    expect(has(handler(body("/")), "open-redirect")).toBe(true);
  });

  it("a target whose HMAC the server verified is not attacker-chosen", () => {
    const body = (verify: string) => `\tdest := r.URL.Query().Get("dest")\n\tsig := r.URL.Query().Get("sig")\n\tmac := hmac.New(sha256.New, secret)\n\tmac.Write([]byte(dest))\n\texpected := hex.EncodeToString(mac.Sum(nil))\n\tif ${verify} {\n\t\treturn\n\t}\n\thttp.Redirect(w, r, dest, http.StatusFound)`;
    expect(has(handler(body(`!hmac.Equal([]byte(sig), []byte(expected))`)), "open-redirect")).toBe(false);
    expect(has(handler(body(`sig == ""`)), "open-redirect")).toBe(true);
  });
});

describe("NoSQL", () => {
  const find = (filter: string, prep = "") => handler(`\tname := r.URL.Query().Get("name")\n\tfield := r.URL.Query().Get("field")\n${prep}\tcursor, _ := MongoCollection.Find(r.Context(), ${filter})\n\t_ = cursor\n\t_ = field`);

  it("a string from the query string is matched literally", () => {
    expect(has(find(`bson.M{"username": name}`), "nosql-injection")).toBe(false);
    expect(has(find("filter", `\tfilter := bson.M{"role": bson.M{"$ne": name}}\n`), "nosql-injection")).toBe(false);
    // bson.D's positional {Key, Value} form, with a string parameter (crAPI's models.GetPostByID)
    const byId = (t: string) => `package handlers\n\nimport "net/http"\n\nfunc getPostByID(client *mongo.Client, ID ${t}) error {\n\tfilter := bson.D{{Key: "id", Value: ID}}\n\treturn client.Database("c").Collection("post").FindOne(context.TODO(), filter).Err()\n}\n\nfunc Handle(w http.ResponseWriter, r *http.Request) {\n\tvars := mux.Vars(r)\n\tgetPostByID(Client, vars["postID"])\n}\n`;
    expect(has(byId("string"), "nosql-injection")).toBe(false);
    // an untyped value (decoded JSON) can be an operator document
    expect(has(byId("interface{}"), "nosql-injection")).toBe(true);
  });

  it("code/pattern operators, caller-chosen keys and regex patterns are injectable", () => {
    expect(has(find(`bson.M{"name": bson.M{"$regex": name}}`), "nosql-injection")).toBe(true);
    expect(has(find("filter", `\tfilter := bson.M{"$where": "this.name == '" + name + "'"}\n`), "nosql-injection")).toBe(true);
    expect(has(find(`bson.M{field: name}`), "nosql-injection")).toBe(true);
    expect(has(find(`bson.M{"name": primitive.Regex{Pattern: name, Options: "i"}}`), "nosql-injection")).toBe(true);
  });

  it("a decoded request body can carry operators", () => {
    expect(has(handler(`\tbody, _ := io.ReadAll(r.Body)\n\tvar filter bson.M\n\tjson.Unmarshal(body, &filter)\n\tcursor, _ := MongoCollection.Find(r.Context(), filter)\n\t_ = cursor`), "nosql-injection")).toBe(true);
  });
});

describe("commands", () => {
  it("argv: a number or a parsed IP can't be an option; a raw value can", () => {
    const run = (prep: string, arg: string) => handler(`\thost := r.URL.Query().Get("host")\n${prep}\tout, _ := exec.Command("ping", "-c", "1", ${arg}).Output()\n\tw.Write(out)`);
    expect(has(run("", "host"), "argument-injection")).toBe(true);
    expect(has(run(`\tip := net.ParseIP(host)\n\tif ip == nil {\n\t\treturn\n\t}\n`, "ip.String()"), "argument-injection")).toBe(false);
    expect(has(run(`\tn, err := strconv.Atoi(host)\n\tif err != nil {\n\t\treturn\n\t}\n`, "strconv.Itoa(n)"), "argument-injection")).toBe(false);
  });

  it("a regexp alphabet guards argv only when it has no literal '-'", () => {
    const run = (cls: string) => handler(`\thost := r.URL.Query().Get("host")\n\tvalid := regexp.MustCompile(\`^[${cls}]+$\`)\n\tif !valid.MatchString(host) {\n\t\treturn\n\t}\n\tout, _ := exec.Command("ping", "-c", "1", host).Output()\n\tw.Write(out)`);
    expect(has(run("a-zA-Z0-9."), "argument-injection")).toBe(false);
    expect(has(run("a-zA-Z0-9.\\\\-"), "argument-injection")).toBe(true);
  });

  it("the regex layer's argv finding is dropped when the engine proves the value is a number or an IP", () => {
    expect(has(handler(`\tnStr := r.URL.Query().Get("lines")\n\tn, err := strconv.Atoi(nStr)\n\tif err != nil {\n\t\treturn\n\t}\n\tout, _ := exec.Command("head", "-n", strconv.Itoa(n), "/var/log/syslog").Output()\n\tw.Write(out)`), "command-injection")).toBe(false);
  });

  it("a parsed IP is still a network destination", () => {
    expect(has(handler(`\thost := r.URL.Query().Get("host")\n\tip := net.ParseIP(host)\n\tresp, _ := http.Get("http://" + ip.String() + "/x")\n\t_ = resp`), "ssrf")).toBe(true);
  });

  it("echo takes no harmful option", () => {
    expect(has(handler(`\tmsg := r.URL.Query().Get("msg")\n\tout, _ := exec.Command("echo", msg).Output()\n\tw.Write(out)`), "argument-injection")).toBe(false);
  });

  it("an argument proven constant on the only path that runs is not reported by either layer", () => {
    const body = (cond: string) => `\tparam := r.URL.Query().Get("flag")\n\targ := param\n\tif ${cond} {\n\t\targ = "-la"\n\t}\n\tout, _ := exec.Command("ls", arg).Output()\n\tw.Write(out)`;
    expect(has(handler(body("2*2 == 4")), "command-injection") || has(handler(body("2*2 == 4")), "argument-injection")).toBe(false);
    expect(has(handler(body("2*2 == 5")), "argument-injection")).toBe(true);
  });
});
