import { scanAstTaint } from "@/lib/astTaint";
import { scanAstTaintPHP, warmPhpTaintEngine, parsePhpSourceSync } from "@/lib/astTaintPHP";
import { analyzeFile } from "@/lib/scanner";

// Taint-engine completeness gaps found by measuring recall against OWASP Juice Shop and DVWA (known-vulnerable
// apps with ground truth). Each case reproduces the real-world code shape that was missed or misreported.

beforeAll(async () => { await warmPhpTaintEngine(); }, 60000);

const js = (src: string) => scanAstTaint(src, "x.ts").map(f => `${f.id}@${f.line}`);
const php = (src: string) => {
  const root = parsePhpSourceSync(src, "x.php")!;
  return scanAstTaintPHP(src, "x.php", root);
};
const phpIds = (src: string) => php(src).map(f => `${f.id}@${f.line}`);

describe("JS: handlers returned from a factory function (Juice Shop's `export function x() { return (req, res) => ... }`)", () => {
  it("taint through a local variable inside the returned handler is kept", () => {
    expect(js(`export function r() { return (req, res) => { const t = req.query.to; res.redirect(t) } }`)).toEqual(["open-redirect@1"]);
  });
  it("same for a curried arrow's expression body", () => {
    expect(js(`export const r = () => (req, res) => { const t = req.query.to; res.redirect(t) }`)).toEqual(["open-redirect@1"]);
  });
});

describe("JS: destructured request parameter", () => {
  it("typed as Request", () => {
    expect(js(`export function r() { return ({ query }: Request, res: Response) => { const t = query.to as string; res.redirect(t) } }`)).toEqual(["open-redirect@1"]);
  });
  it("untyped, next to a response-named parameter; renamed binding", () => {
    expect(js(`app.get("/r", ({ query: q }, res) => { res.redirect(q.to) })`)).toEqual(["open-redirect@1"]);
  });
  it("no evidence the first parameter is a request -> not a source", () => {
    expect(js(`items.forEach(({ query }, idx) => { res.redirect(query.to) })`)).toEqual([]);
  });
});

describe("JS: a ternary whose condition proves the chosen arm is a literal", () => {
  it("`[...literals].includes(E) ? E : 'default'` is clean", () => {
    expect(js(`app.get("/r", (req, res) => { const e = ['a','b'].includes(req.query.x) ? req.query.x : 'a'; fs.readFileSync("/d/" + e) })`)).toEqual([]);
  });
  it("a non-literal list, or a different expression in the arm, still reports", () => {
    expect(js(`app.get("/r", (req, res) => { const e = allowed.includes(req.query.x) ? req.query.x : 'a'; fs.readFileSync("/d/" + e) })`)).toEqual(["path-traversal@1"]);
    expect(js(`app.get("/r", (req, res) => { const e = ['a'].includes(req.query.x) ? req.query.y : 'a'; fs.readFileSync("/d/" + e) })`)).toEqual(["path-traversal@1"]);
  });
});

describe("JS: MongoDB framework modeling", () => {
  it("the Node driver's db.collection(name).<verb>(filter) shape", () => {
    expect(js(`app.get("/u", (req, res) => { db.collection("users").find({ name: req.query.n }) })`)).toEqual(["nosql-injection@1"]);
    expect(js(`app.post("/u", (req, res) => { client.db("app").collection("users").deleteOne({ _id: req.body.id }) })`)).toEqual(["nosql-injection@1"]);
  });
  it("legacy update/remove/count on an unmistakable collection receiver", () => {
    expect(js(`app.patch("/r", (req, res) => { db.reviewsCollection.update({ _id: req.body.id }, { $set: { m: 1 } }) })`)).toEqual(["nosql-injection@1"]);
  });
  it("an ORM instance's .update() is not a NoSQL query", () => {
    expect(js(`app.patch("/r", async (req, res) => { const user = await UserModel.findByPk(1); await user.update({ username: req.body.username }) })`)).toEqual([]);
  });
});

describe("dedup: a regex finding tied on confidence doesn't hide the AST data flow", () => {
  it("the merged finding keeps sourceExpr and trace", () => {
    const a = analyzeFile("routes/avatar.ts", `app.post("/avatar", async (req, res) => {\n  const url = req.body.imageUrl;\n  const r = await fetch(url);\n  res.json({ ok: r.ok });\n});\n`);
    const ssrf = a.indicators.find(i => i.id === "ssrf");
    expect(ssrf?.sourceExpr).toBe("url");
    expect(ssrf?.trace?.length).toBeGreaterThan(1);
  });
});

describe("PHP: escaping is a defence only inside a quoted SQL literal", () => {
  it("mysqli_real_escape_string($link, $x) in an unquoted position reports, with the reason", () => {
    const f = php(`<?php\n$id = mysqli_real_escape_string($c, $_POST['id']);\n$q = "SELECT * FROM u WHERE id = $id";\nmysqli_query($c, $q);\n`);
    expect(f.map(x => `${x.id}@${x.line}`)).toEqual(["sql-injection@4"]);
    expect(f[0].detail).toMatch(/outside a quoted string literal/);
  });
  it("the same value inside quotes, an intval(), or PDO::quote() is safe", () => {
    expect(phpIds(`<?php\n$id = mysqli_real_escape_string($c, $_POST['id']);\n$q = "SELECT * FROM u WHERE id = '$id'";\nmysqli_query($c, $q);\n`)).toEqual([]);
    expect(phpIds(`<?php\n$id = intval($_POST['id']);\n$q = "SELECT * FROM u WHERE id = $id";\nmysqli_query($c, $q);\n`)).toEqual([]);
    expect(phpIds(`<?php\n$id = $pdo->quote($_POST['id']);\n$pdo->query("SELECT * FROM u WHERE id = " . $id);\n`)).toEqual([]);
  });
  it("the method form ($db->real_escape_string) concatenated unquoted reports", () => {
    expect(phpIds(`<?php\n$id = $db->real_escape_string($_GET['id']);\n$db->query("SELECT * FROM u WHERE id = " . $id);\n`)).toEqual(["sql-injection@3"]);
  });
  it("the escaped value is the SECOND argument of mysqli_real_escape_string -- the first is the connection", () => {
    // Plainly reaching the sink UNESCAPED alongside, to prove the escape was applied to the right argument:
    // if the connection were treated as the value, $id would lose its taint entirely and this quoted
    // placement would record no suppression.
    const root = parsePhpSourceSync(`<?php\n$id = mysqli_real_escape_string($c, $_POST['id']);\nmysqli_query($c, "SELECT * FROM u WHERE n = '$id'");\n`, "x.php")!;
    const suppressed: { id: string; line: number }[] = [];
    scanAstTaintPHP(`<?php\n$id = mysqli_real_escape_string($c, $_POST['id']);\nmysqli_query($c, "SELECT * FROM u WHERE n = '$id'");\n`, "x.php", root, suppressed);
    expect(suppressed).toEqual([{ id: "sql-injection", line: 3 }]);
  });
});

describe("PHP: numeric checks on literal-indexed array elements (DVWA exec/impossible.php)", () => {
  const ex = (cond: string, rebuild: string) =>
    `<?php\n$target = $_REQUEST['ip'];\n$octet = explode(".", $target);\nif (${cond}) {\n$target = ${rebuild};\n$cmd = shell_exec('ping ' . $target);\n}\n`;
  it("every element checked and only checked elements used -> safe", () => {
    expect(phpIds(ex("is_numeric($octet[0]) && is_numeric($octet[1]) && is_numeric($octet[2]) && is_numeric($octet[3])",
      "$octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3]"))).toEqual([]);
  });
  it("one element unchecked, || instead of &&, or the whole value used -> still reported", () => {
    expect(phpIds(ex("is_numeric($octet[0]) && is_numeric($octet[1]) && is_numeric($octet[2])",
      "$octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3]"))).toEqual(["command-injection@6"]);
    expect(phpIds(ex("is_numeric($octet[0]) || is_numeric($octet[1])", "$octet[0] . '.' . $octet[1]"))).toEqual(["command-injection@6"]);
    expect(phpIds(ex("is_numeric($octet[0])", "$target"))).toEqual(["command-injection@6"]);
  });
  it("the arm where the check FAILED is not protected", () => {
    expect(phpIds(`<?php\n$o = explode(".", $_GET['ip']);\nif (!is_numeric($o[0])) { $t = $o[0]; shell_exec('ping ' . $t); }\n`)).toEqual(["command-injection@3"]);
  });
});
