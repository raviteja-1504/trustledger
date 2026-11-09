/**
 * @jest-environment node
 *
 * PHP AST taint engine accuracy: namespace-aware identity, fully-qualified function names, named arguments, reaching
 * definitions, sink-specific sanitizer suppression, token-specific JWT evidence, resource-specific BOLA, SQL prepared
 * statements, path / filesystem sinks, finding identity, cross-file namespace resolution.
 */
import { analyzeFile, runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";

beforeAll(async () => { await warmPhpTaintEngine(); }, 120000);

/** Findings from the data-flow engine itself (it sets sourceExpr), not the line-pattern layer. */
const flow = (code: string, path = "src/h.php"): ScanIndicator[] => analyzeFile(path, `<?php\n${code}\n`).indicators.filter(i => !!i.sourceExpr);
const ids = (code: string) => flow(code).map(i => i.id);
/** every indicator, engine and line-pattern layer both -- for suppression tests, where the veto of the pattern layer is the point */
const anyIds = (code: string) => analyzeFile("src/h.php", `<?php\n${code}\n`).indicators.map(i => i.id);
const fn = (body: string, params = "") => `function h(${params}) {\n${body}\n}`;

describe("fully qualified and namespaced function names", () => {
  it("\\system() is the same sink as system()", () => {
    expect(ids(fn(`  $c = $_GET['cmd'];\n  \\system($c);`))).toContain("command-injection");
    expect(ids(fn(`  $c = $_GET['cmd'];\n  \\shell_exec($c);`))).toContain("command-injection");
    expect(ids(fn(`  $c = $_GET['cmd'];\n  \\mysqli_query($link, "SELECT * FROM t WHERE n = '" . $c . "'");`))).toContain("sql-injection");
  });
  it("a sanitizer called by its fully qualified name still sanitizes", () => {
    expect(ids(fn(`  $c = \\escapeshellarg($_GET['cmd']);\n  system("ls " . $c);`))).not.toContain("command-injection");
  });
  it("a namespaced user function named like a built-in is the user's function, not the built-in sink", () => {
    const code = `namespace App;\nfunction system($x) { return 'ok'; }\n${fn(`  system($_GET['c']);`)}`;
    expect(ids(code)).not.toContain("command-injection");
  });
  it("...and the global built-in is still reached when the namespace defines no such function", () => {
    expect(ids(`namespace App;\n${fn(`  system($_GET['c']);`)}`)).toContain("command-injection");
    expect(ids(`namespace App;\n${fn(`  \\system($_GET['c']);`)}`)).toContain("command-injection");
  });
  it("two namespaces' same-named functions are separate", () => {
    const code = (ns: string) => `namespace A { function run($x) { system($x); } }\nnamespace B { function run($x) { return 1; } }\nnamespace ${ns} {\n${fn(`  run($_GET['c']);`)}\n}`;
    expect(ids(code("A"))).toContain("command-injection");
    expect(ids(code("B"))).not.toContain("command-injection");
  });
});

describe("named arguments", () => {
  const def = `function buildQuery(string $table, string $filter): string {\n  return "SELECT * FROM $table WHERE id = '$filter'";\n}\n`;
  it("a reordered named argument binds to its own parameter", () => {
    expect(ids(def + fn(`  $q = buildQuery(filter: $_GET['id'], table: 'users');\n  mysqli_query($link, $q);`))).toContain("sql-injection");
    expect(ids(def + fn(`  $q = buildQuery(filter: 'x', table: 'users');\n  mysqli_query($link, $q);`))).not.toContain("sql-injection");
  });
  it("a named argument to a function that sinks one parameter", () => {
    const sink = `function run(string $label, string $cmd) { system($cmd); }\n`;
    expect(ids(sink + fn(`  run(cmd: $_GET['c'], label: 'x');`))).toContain("command-injection");
    expect(ids(sink + fn(`  run(label: $_GET['c'], cmd: 'ls');`))).not.toContain("command-injection");
  });
  it("an optional parameter the call leaves out is the callee's constant", () => {
    const sink = `function run(string $label, string $cmd = 'ls') { system($cmd); }\n`;
    expect(ids(sink + fn(`  run($_GET['c']);`))).not.toContain("command-injection");
    expect(ids(sink + fn(`  run('x', $_GET['c']);`))).toContain("command-injection");
  });
  it("a variadic parameter takes every trailing argument", () => {
    const sink = `function run(...$parts) { system(implode(' ', $parts)); }\n`;
    expect(ids(sink + fn(`  run('a', $_GET['c']);`))).toContain("command-injection");
  });
  it("named arguments on a method call and a constructor", () => {
    const cls = `class R { function run(string $label, string $cmd) { system($cmd); } }\n`;
    expect(ids(cls + fn(`  $r = new R();\n  $r->run(cmd: $_GET['c'], label: 'x');`))).toContain("command-injection");
    expect(ids(cls + fn(`  $r = new R();\n  $r->run(label: $_GET['c'], cmd: 'ls');`))).not.toContain("command-injection");
  });
});

describe("reaching definitions", () => {
  it("a later overwrite by a constant removes the taint", () => {
    expect(ids(fn(`  $q = $_GET['q'];\n  $q = 'SELECT 1';\n  mysqli_query($link, $q);`))).not.toContain("sql-injection");
  });
  it("an assignment in only one branch leaves the other definition live", () => {
    expect(ids(fn(`  $q = 'SELECT 1';\n  if ($flag) { $q = $_GET['q']; }\n  mysqli_query($link, $q);`))).toContain("sql-injection");
  });
  it("a null-coalesce that falls back to the old value keeps both definitions", () => {
    expect(ids(fn(`  if ($isAdmin) { $query = 'SELECT * FROM users'; }\n  $query = $_GET['query'] ?? $query;\n  mysqli_query($link, $query);`))).toContain("sql-injection");
  });
  it("a loop-carried assignment", () => {
    expect(ids(fn(`  $q = 'SELECT 1';\n  foreach ($_GET['ids'] as $id) { $q .= ' OR id = ' . $id; }\n  mysqli_query($link, $q);`))).toContain("sql-injection");
  });
  it("an early return leaves only the surviving path", () => {
    expect(ids(fn(`  $q = $_GET['q'];\n  if (!ctype_digit($q)) { return; }\n  mysqli_query($link, "SELECT * FROM t WHERE id = " . $q);`))).not.toContain("sql-injection");
  });
  it("a variable of the same name inside a closure is not the outer one", () => {
    expect(ids(fn(`  $q = $_GET['q'];\n  $f = function () { $q = 'SELECT 1'; mysqli_query($GLOBALS['link'], $q); };\n  $f();`))).not.toContain("sql-injection");
  });
});

describe("sanitizer suppression is tied to the flow and the vulnerability class", () => {
  it("only one branch sanitized: the other path still reaches the sink", () => {
    expect(anyIds(fn(`  $x = $_GET['x'];\n  if ($flag) { $x = escapeshellarg($x); }\n  system("ls " . $x);`))).toContain("command-injection");
  });
  it("a sanitized variable that is overwritten with the raw value", () => {
    expect(anyIds(fn(`  $x = escapeshellarg($_GET['x']);\n  $x = $_GET['x'];\n  system("ls " . $x);`))).toContain("command-injection");
  });
  it("a different variable was sanitized", () => {
    expect(anyIds(fn(`  $a = escapeshellarg($_GET['a']);\n  $b = $_GET['b'];\n  system("ls " . $b);`))).toContain("command-injection");
  });
  it("a sanitizer called but its return value ignored", () => {
    expect(anyIds(fn(`  $x = $_GET['x'];\n  escapeshellarg($x);\n  system("ls " . $x);`))).toContain("command-injection");
  });
  it("an HTML escape does not protect a query, a shell escape does not protect output", () => {
    expect(ids(fn(`  $x = htmlspecialchars($_GET['x']);\n  mysqli_query($link, "SELECT * FROM t WHERE n = " . $x);`))).toContain("sql-injection");
    expect(ids(fn(`  $x = escapeshellarg($_GET['x']);\n  echo "<p>" . $x . "</p>";`))).toContain("xss");
  });
  it("two sources reach one sink and only one is sanitized", () => {
    expect(anyIds(fn(`  $a = escapeshellarg($_GET['a']);\n  $b = $_GET['b'];\n  system("ls " . $a . " " . $b);`))).toContain("command-injection");
  });
  it("the sanitizer applied to the value that reaches the sink is proven", () => {
    expect(anyIds(fn(`  $x = escapeshellarg($_GET['x']);\n  system("ls " . $x);`))).not.toContain("command-injection");
  });
  it("a decode after the sanitizer reintroduces the danger", () => {
    expect(anyIds(fn(`  $x = urlencode($_GET['x']);\n  $y = urldecode($x);\n  system("ls " . $y);`))).toContain("command-injection");
  });
});

describe("JWT verification is about the same token", () => {
  const decode = (extra: string) => `function authenticate($token) {\n${extra}  $parts = explode('.', $token);\n  $payload = base64_decode($parts[1]);\n  return json_decode($payload, true);\n}`;
  it("an unrelated hash_equals() in the function does not excuse the decode", () => {
    expect(ids(decode(`  $unrelated = hash_equals('abc', 'abc');\n`))).toContain("jwt-none-alg");
  });
  it("a signature check over the same token does", () => {
    const ok = `function authenticate($token) {\n  $parts = explode('.', $token);\n  $sig = hash_hmac('sha256', $parts[0] . '.' . $parts[1], KEY, true);\n  if (!hash_equals($sig, base64_decode($parts[2]))) { return null; }\n  return json_decode(base64_decode($parts[1]), true);\n}`;
    expect(ids(ok)).not.toContain("jwt-none-alg");
  });
  it("a verifier for a different token variable does not", () => {
    const other = `function authenticate($token, $other) {\n  $o = explode('.', $other);\n  hash_equals(hash_hmac('sha256', $o[0] . '.' . $o[1], KEY), $o[2]);\n  $parts = explode('.', $token);\n  return json_decode(base64_decode($parts[1]), true);\n}`;
    expect(ids(other)).toContain("jwt-none-alg");
  });
});

describe("BOLA: authentication and roles are not ownership", () => {
  const b = (body: string) => `class OrderController {\n  public function show(Request $request, $id) {\n${body}\n  }\n}`;
  const bola = (code: string) => ids(code).includes("bola-missing-ownership-check");
  it("an unchecked lookup by request id is reported", () => {
    expect(bola(b(`    $order = Order::findOrFail($id);\n    return view('order', ['order' => $order]);`))).toBe(true);
  });
  it("a custom-named lookup is still a lookup by the request id", () => {
    expect(bola(b(`    $order = $this->orders->loadOrderRecord($id);\n    return view('order', ['order' => $order]);`))).toBe(true);
  });
  it("a method that merely looks like a lookup but takes no id is not", () => {
    expect(bola(b(`    $list = $this->fetchHeaders();\n    return $list;`))).toBe(false);
  });
  it("an ownership comparison on the loaded record is safe", () => {
    expect(bola(b(`    $order = Order::findOrFail($id);\n    if ($order->user_id !== auth()->id()) { abort(403); }\n    return view('order', ['order' => $order]);`))).toBe(false);
  });
  it("abort_unless on the record's owner is safe", () => {
    expect(bola(b(`    $order = Order::findOrFail($id);\n    abort_unless($order->user_id === auth()->id(), 403);\n    return view('order', ['order' => $order]);`))).toBe(false);
  });
  it("Gate::authorize on the loaded record is safe", () => {
    expect(bola(b(`    $order = Order::findOrFail($id);\n    Gate::authorize('view', $order);\n    return view('order', ['order' => $order]);`))).toBe(false);
  });
  it("a query scoped to the authenticated user is safe", () => {
    expect(bola(b(`    $order = Order::where('user_id', auth()->id())->findOrFail($id);\n    return view('order', ['order' => $order]);`))).toBe(false);
  });
  it("an admin-role check is not ownership", () => {
    expect(bola(b(`    if (!auth()->user()->isAdmin()) { abort(403); }\n    $order = Order::findOrFail($id);\n    return view('order', ['order' => $order]);`))).toBe(true);
  });
  it("an authentication check is not ownership", () => {
    expect(bola(b(`    if (!auth()->check()) { abort(401); }\n    $order = Order::findOrFail($id);\n    return view('order', ['order' => $order]);`))).toBe(true);
  });
  it("a check on some other record does not protect this one", () => {
    expect(bola(b(`    $mine = Order::where('user_id', auth()->id())->first();\n    $order = Order::findOrFail($id);\n    if ($mine->user_id !== auth()->id()) { abort(403); }\n    return view('order', ['order' => $order]);`))).toBe(true);
  });
});

describe("SQL: prepared statements and bound parameters", () => {
  it("PDO prepare with a placeholder and a bound value is safe", () => {
    expect(ids(fn(`  $s = $pdo->prepare("SELECT * FROM t WHERE id = ?");\n  $s->execute([$_GET['id']]);`))).not.toContain("sql-injection");
    expect(ids(fn(`  $s = $pdo->prepare("SELECT * FROM t WHERE id = :id");\n  $s->bindValue(':id', $_GET['id']);\n  $s->execute();`))).not.toContain("sql-injection");
  });
  it("PDO prepare of a concatenated statement is not", () => {
    expect(ids(fn(`  $s = $pdo->prepare("SELECT * FROM t WHERE id = '" . $_GET['id'] . "'");\n  $s->execute();`))).toContain("sql-injection");
  });
  it("a dynamic identifier cannot be bound", () => {
    expect(ids(fn(`  $s = $pdo->prepare("SELECT * FROM " . $_GET['table'] . " WHERE id = ?");\n  $s->execute([1]);`))).toContain("sql-injection");
  });
  it("mysqli prepared statements", () => {
    expect(ids(fn(`  $s = $mysqli->prepare("SELECT * FROM t WHERE id = ?");\n  $s->bind_param('s', $_GET['id']);\n  $s->execute();`))).not.toContain("sql-injection");
  });
});

describe("filesystem sinks and path containment", () => {
  it("building a path alone is not a finding; the file call is", () => {
    expect(ids(fn(`  $p = '/srv/files/' . $_GET['f'];`))).not.toContain("path-traversal");
    expect(ids(fn(`  $p = '/srv/files/' . $_GET['f'];\n  file_get_contents($p);`))).toContain("path-traversal");
  });
  it.each([
    ["fopen", `fopen($p, 'r');`], ["file_put_contents", `file_put_contents($p, 'x');`], ["readfile", `readfile($p);`],
    ["unlink", `unlink($p);`], ["SplFileObject", `new SplFileObject($p);`], ["DirectoryIterator", `new DirectoryIterator($p);`],
    ["scandir", `scandir($p);`], ["include", `include $p;`],
  ])("a tainted path reaching %s is reported", (_n, call) => {
    expect(flow(fn(`  $p = $_GET['f'];\n  ${call}`)).length).toBeGreaterThan(0);
  });
  it("a '..' check does not stop an absolute path", () => {
    expect(ids(fn(`  $p = $_GET['f'];\n  if (strpos($p, '..') !== false) { return; }\n  file_get_contents($p);`))).toContain("path-traversal");
  });
  it("realpath followed by a directory-anchored prefix check is containment; a bare prefix is not", () => {
    const body = (prefix: string) => `  $p = realpath('/srv/files/' . $_GET['f']);\n  if (strpos($p, '${prefix}') !== 0) { return; }\n  file_get_contents($p);`;
    expect(ids(fn(body("/srv/files/")))).not.toContain("path-traversal");
    expect(ids(fn(body("/srv/files")))).toContain("path-traversal");
  });
  it("proc_open with an argv array is not a shell string", () => {
    expect(ids(fn(`  proc_open(['ls', '-l', $_GET['d']], [], $pipes);`))).not.toContain("command-injection");
    expect(ids(fn(`  proc_open('ls -l ' . $_GET['d'], [], $pipes);`))).toContain("command-injection");
  });
});

describe("finding identity", () => {
  it("two different flows on the same line are two findings in the engine", () => {
    const hits = flow(fn(`  system($_GET['a']); file_get_contents($_GET['b']);`));
    expect(hits.filter(i => i.id === "command-injection")).toHaveLength(1);
    expect(hits.filter(i => i.id === "path-traversal")).toHaveLength(1);
  });
  it("a finding names source, sink and a trace from the source to the sink", () => {
    const f = flow(fn(`  $c = $_GET['c'];\n  system($c);`)).find(i => i.id === "command-injection")!;
    expect(f.sourceExpr).toBeTruthy();
    expect(f.trace![0].kind).toBe("source");
    expect(f.trace![f.trace!.length - 1].kind).toBe("sink");
  });
});

describe("cross-file resolution uses namespace identity", () => {
  type F = { path: string; content: string };
  const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
  const found = (files: F[], path: string, id: string) => scan(files).files.find(f => f.file_path === path)!.indicators.filter(i => i.sourceExpr !== undefined && i.id === id);
  const repo = (ns: string, body: string): F => ({ path: `src/${ns.replace(/\\/g, "/")}/Repo.php`, content: `<?php\nnamespace ${ns};\nclass Repo {\n  public function find($x) {\n    ${body}\n  }\n}\n` });
  const ctl = (use: string): F => ({ path: "src/Http/Ctl.php", content: `<?php\nnamespace App\\Http;\n${use}\nclass Ctl {\n  public function show() {\n    $r = new Repo();\n    $r->find($_GET['x']);\n  }\n}\n` });
  it("two classes of the same short name in different namespaces: the use statement picks one", () => {
    const files = (use: string): F[] => [repo("App\\Danger", "system($x);"), repo("App\\Safe", "return strlen($x);"), ctl(use)];
    expect(found(files("use App\\Danger\\Repo;"), "src/Http/Ctl.php", "command-injection").length).toBeGreaterThan(0);
    expect(found(files("use App\\Safe\\Repo;"), "src/Http/Ctl.php", "command-injection")).toHaveLength(0);
  });
  it("an ambiguous short name with no use statement is unknown, not a guess", () => {
    const files: F[] = [repo("App\\Danger", "system($x);"), repo("App\\Safe", "return strlen($x);"), ctl("")];
    expect(found(files, "src/Http/Ctl.php", "command-injection")).toHaveLength(0);
  });
  it("an aliased import resolves to the class it names", () => {
    const files: F[] = [repo("App\\Danger", "system($x);"), repo("App\\Safe", "return strlen($x);"), { ...ctl("use App\\Danger\\Repo as Repo;") }];
    expect(found(files, "src/Http/Ctl.php", "command-injection").length).toBeGreaterThan(0);
  });
});

describe("parser failures", () => {
  it("source that does not parse does not throw", () => {
    expect(() => analyzeFile("src/broken.php", "<?php function ( { $x = ;")).not.toThrow();
  });
});
