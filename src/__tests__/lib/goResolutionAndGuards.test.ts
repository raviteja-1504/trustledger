/**
 * @jest-environment node
 *
 * Go engine precision checks from an external review, each with a twin:
 *  - a method call runs the method of ITS receiver type (two types' `Build`), through a composite literal, a variable
 *    built as one, or a pointer -- and a sink inside that method is reached;
 *  - `a, b := f(x)` binds each target from its own return value;
 *  - os.Rename / os.Link / os.Symlink take a path in both arguments;
 *  - a handler's framework context is recognised by its type, whatever it is called, and only then;
 *  - a cleaned path's HasPrefix confines it only when the base ends at a directory.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmGoTaintEngine } from "@/lib/astTaintGo";

beforeAll(async () => { await warmGoTaintEngine(); }, 120000);

const engine = (code: string) => analyzeFile("handlers/h.go", code).indicators.filter(i => !!i.sourceExpr).map(i => i.id);
const hdr = `package main\n\nimport (\n\t"database/sql"\n\t"net/http"\n\t"os"\n\t"os/exec"\n\t"path/filepath"\n\t"strings"\n)\n\nvar db *sql.DB\n\n`;
const handler = (body: string, before = "") => `${hdr}${before}func handler(w http.ResponseWriter, r *http.Request) {\n${body}\n}\n`;
const sqlAt = (code: string) => analyzeFile("handlers/h.go", code).indicators.filter(i => !!i.sourceExpr && i.id === "sql-injection").map(i => i.line);

describe("a method call runs its receiver type's method", () => {
  const SU = `type Safe struct{}\ntype Unsafe struct{}\n\nfunc (Safe) Build(x string) string {\n\treturn "fixed"\n}\n\nfunc (Unsafe) Build(x string) string {\n\treturn "SELECT * FROM users WHERE name='" + x + "'"\n}\n\n`;
  const queryLine = (code: string) => code.split("\n").findIndex(l => l.includes("db.Query(")) + 1;
  it("Unsafe's Build carries the input; Safe's doesn't -- by literal, variable or pointer", () => {
    for (const [recv, setup] of [["Unsafe{}", ""], ["s", "\ts := Unsafe{}\n"], ["s", "\ts := &Unsafe{}\n"], ["s", "\tvar s Unsafe\n"]] as const) {
      const code = handler(`${setup}\tdb.Query(${recv}.Build(r.URL.Query().Get("name")))`, SU);
      expect(sqlAt(code)).toContain(queryLine(code));
      const safe = code.replace(/Unsafe\{\}|var s Unsafe/, m => m.replace("Unsafe", "Safe"));
      expect(sqlAt(safe)).not.toContain(queryLine(safe));
    }
  });
  it("a sink inside the method of the receiver's type is reached; the other type's isn't", () => {
    const RN = `type Safe struct{}\ntype Unsafe struct{}\n\nfunc (Safe) Run(x string) {\n\t_ = x\n}\n\nfunc (u *Unsafe) Run(x string) {\n\texec.Command("sh", "-c", x).Run()\n}\n\n`;
    expect(engine(handler(`\tu := &Unsafe{}\n\tu.Run(r.URL.Query().Get("c"))`, RN))).toContain("command-injection");
    expect(engine(handler(`\ts := Safe{}\n\ts.Run(r.URL.Query().Get("c"))`, RN))).not.toContain("command-injection");
  });
  it("a method calling a sibling through its own receiver resolves to its own type", () => {
    const own = `type Svc struct{}\ntype Other struct{}\n\nfunc (s *Svc) wrap(x string) string {\n\treturn "k"\n}\n\nfunc (o *Other) wrap(x string) string {\n\treturn x\n}\n\nfunc (s *Svc) Run(r *http.Request) {\n\texec.Command("sh", "-c", s.wrap(r.URL.Query().Get("c"))).Run()\n}\n\n`;
    expect(engine(hdr + own)).not.toContain("command-injection");
  });
});

describe("multiple return values", () => {
  const parse = `func parse(s string) (string, string) {\n\treturn "fixed", s\n}\n\n`;
  it("each target takes its own value: the tainted second is reported, the constant first is not", () => {
    expect(engine(handler(`\t_, password := parse(r.URL.Query().Get("p"))\n\tdb.Query("SELECT * FROM users WHERE password='" + password + "'")`, parse))).toContain("sql-injection");
    expect(engine(handler(`\tuser, _ := parse(r.URL.Query().Get("p"))\n\tdb.Query("SELECT * FROM users WHERE u='" + user + "'")`, parse))).not.toContain("sql-injection");
  });
  it("a value the function reads from the request itself, at its position", () => {
    const own = `func creds(r *http.Request) (string, error) {\n\treturn r.URL.Query().Get("u"), nil\n}\n\n`;
    expect(engine(handler(`\tu, err := creds(r)\n\t_ = err\n\tdb.Query("SELECT * FROM t WHERE u='" + u + "'")`, own))).toContain("sql-injection");
  });
});

describe("filesystem calls that take two paths", () => {
  it("os.Rename / os.Link / os.Symlink: a request-chosen destination is reported", () => {
    expect(engine(handler(`\tdst := filepath.Join("/tmp/uploads", r.URL.Query().Get("f"))\n\tos.Rename("/tmp/temp", dst)`))).toContain("path-traversal");
    expect(engine(handler(`\tos.Symlink("/etc/app.conf", r.URL.Query().Get("p"))`))).toContain("path-traversal");
    expect(engine(handler(`\tos.Link("/tmp/a", r.URL.Query().Get("p"))`))).toContain("path-traversal");
    expect(engine(handler(`\tos.Rename("/tmp/a", "/tmp/b")`))).not.toContain("path-traversal");
  });
});

describe("a framework context, by type", () => {
  const sql = (sig: string, read: string, imp: string) => `package main\n\nimport (\n\t"database/sql"\n${imp}\n)\n\nvar db *sql.DB\n\nfunc search(${sig}) {\n\tq := ${read}\n\tdb.Query("SELECT * FROM t WHERE a = '" + q + "'")\n}\n`;
  it("whatever the parameter is called, and through an import alias", () => {
    expect(engine(sql(`ctx *gin.Context`, `ctx.Query("q")`, `\t"github.com/gin-gonic/gin"`))).toContain("sql-injection");
    expect(engine(sql(`ec echo.Context`, `ec.QueryParam("q")`, `\t"github.com/labstack/echo/v4"`))).toContain("sql-injection");
    expect(engine(sql(`req *g.Context`, `req.Query("q")`, `\tg "github.com/gin-gonic/gin"`))).toContain("sql-injection");
  });
  it("a parameter of another type with the same method is not request input", () => {
    expect(engine(`package main\n\nimport "database/sql"\n\nvar db *sql.DB\n\ntype Cfg struct{}\n\nfunc (Cfg) Query(k string) string { return "fixed" }\n\nfunc run(c Cfg) {\n\tq := c.Query("q")\n\tdb.Query("SELECT * FROM t WHERE a = '" + q + "'")\n}\n`)).not.toContain("sql-injection");
  });
});

describe("a cleaned path confined by HasPrefix", () => {
  const read = (clean: string, check: string) => handler(`\tp := ${clean}\n\tif !${check} {\n\t\treturn\n\t}\n\tos.ReadFile(p)`);
  const name = `r.URL.Query().Get("f")`;
  it("a base ending at a directory confines it", () => {
    expect(engine(read(`filepath.Clean(${name})`, `strings.HasPrefix(p, "/srv/uploads/")`))).not.toContain("path-traversal");
    expect(engine(read(`filepath.Join("/srv/uploads", ${name})`, `strings.HasPrefix(p, "/srv/uploads/")`))).not.toContain("path-traversal");
    expect(engine(read(`filepath.Join("/srv/uploads", ${name})`, `strings.HasPrefix(p, "/srv/uploads"+string(os.PathSeparator))`))).not.toContain("path-traversal");
  });
  it("otherwise the sibling /srv/uploads_evil passes too", () => {
    expect(engine(read(`filepath.Clean(${name})`, `strings.HasPrefix(p, "/srv/uploads")`))).toContain("path-traversal");
    expect(engine(read(`filepath.Join("/srv/uploads", ${name})`, `strings.HasPrefix(p, filepath.Clean("/srv/uploads"))`))).toContain("path-traversal");
  });
});
