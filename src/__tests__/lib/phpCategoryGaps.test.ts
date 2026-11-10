/**
 * @jest-environment node
 *
 * PHP checks for the sast-benchmark categories that scored zero: extract() and $$name driven by the request
 * (variable overwrite), loose comparison of input with a number / hash / strcmp result (type juggling), and an upload
 * saved under the client's file name. Each has a twin that stays silent.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";

beforeAll(async () => { await warmPhpTaintEngine(); }, 120000);

const fn = (body: string) => `<?php\nfunction handler() {\n${body}\n}\n`;
const ids = (code: string) => analyzeFile("src/handler.php", code).indicators.filter(i => !!i.sourceExpr).map(i => i.id);

describe("CSRF", () => {
  const allIds = (code: string) => analyzeFile("src/handler.php", code).indicators.map(i => i.id);
  const page = (body: string) => `<?php\nrequire_once 'db.php';\n\nfunction updateEmail() {\n    session_start();\n    $userId = $_SESSION['user_id'];\n${body}\n}\n\nfunction showProfile() {\n    echo "profile";\n}\n`;
  const update = `    $pdo = getDb();\n    $stmt = $pdo->prepare("UPDATE users SET email = ? WHERE id = ?");\n    $stmt->execute([$_POST['email'], $userId]);`;
  it("a session-authenticated update with no token; with a token check, or with no session at all, it is not", () => {
    expect(allIds(page(update))).toContain("csrf");
    // one finding, at the function: its body is not counted again as the script's top-level code
    expect(analyzeFile("src/handler.php", page(update)).indicators.filter(i => i.id === "csrf").map(i => i.line)).toEqual([4]);
    expect(allIds(page(`    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) { http_response_code(403); return; }\n${update}`))).not.toContain("csrf");
    // a bearer-token API: no session or cookie, nothing a browser sends on its own
    expect(allIds(page(update).replace("    session_start();\n    $userId = $_SESSION['user_id'];", "    $userId = verifyBearer($_SERVER['HTTP_AUTHORIZATION']);"))).not.toContain("csrf");
    // a session read that changes nothing
    expect(allIds(page(`    echo htmlspecialchars($userId);`))).not.toContain("csrf");
  });
  it("a top-level page that updates the current user's row; with a token it is not", () => {
    const script = (check: string) => `<?php\nrequire_once 'auth.php';\n\nif (isset($_GET['Change'])) {\n${check}    $user = currentUser();\n    $sql = "UPDATE users SET password = '" . md5($_GET['password_new']) . "' WHERE user = '" . $user . "'";\n    mysqli_query($db, $sql);\n    echo "<pre>Password Changed.</pre>";\n}\n`;
    expect(allIds(script(""))).toContain("csrf");
    expect(allIds(script(`    checkToken($_REQUEST['user_token'], $_SESSION['session_token'], 'index.php');\n`))).not.toContain("csrf");
    // an install routine that rebuilds the schema
    expect(allIds(script(`    mysqli_query($db, "DROP TABLE IF EXISTS users");\n    mysqli_query($db, "CREATE TABLE users (id INT)");\n`))).not.toContain("csrf");
  });
});

describe("template chosen by the request", () => {
  it("Twig render / Latte renderToString / Smarty display of a request-named template; a fixed template with request data is not", () => {
    expect(ids(fn(`    $latte = new Latte\\Engine();\n    echo $latte->renderToString($_POST['tpl'], []);`))).toContain("ssti");
    expect(ids(fn(`    $twig = new Twig\\Environment(new Twig\\Loader\\FilesystemLoader('/views'));\n    echo $twig->render('../' . $_GET['path']);`))).toContain("ssti");
    expect(ids(fn(`    $view = new Smarty();\n    $view->display($_GET['page']);`))).toContain("ssti");
    expect(ids(fn(`    $twig = new Twig\\Environment(new Twig\\Loader\\FilesystemLoader('/views'));\n    echo $twig->render('profile.html', ['name' => $_GET['name']]);`))).not.toContain("ssti");
    // an engine from a factory: known only by its conventional name
    expect(ids(fn(`    $twig = app_twig();\n    echo $twig->render($_GET['page']);`))).toContain("ssti");
    // ->render() on something that is not a template engine
    expect(ids(fn(`    $chart = new Chart();\n    echo $chart->render($_GET['type']);`))).not.toContain("ssti");
  });
});

describe("variable overwrite", () => {
  it("extract() of request data; with EXTR_PREFIX_ALL it is not", () => {
    expect(ids(fn(`    $isAdmin = false;\n    extract($_POST);\n    if ($isAdmin) { echo "admin"; }`))).toContain("variable-overwrite");
    expect(ids(fn(`    extract($_POST, EXTR_PREFIX_ALL, 'usr_');\n    echo htmlspecialchars($usr_lang ?? 'en');`))).not.toContain("variable-overwrite");
  });
  it("$$k = $v over the request's keys; an array keyed by them is not", () => {
    expect(ids(fn(`    foreach ($_POST as $k => $v) {\n        $$k = $v;\n    }`))).toContain("variable-overwrite");
    expect(ids(fn(`    $config = [];\n    foreach ($_POST as $k => $v) {\n        $config[$k] = $v;\n    }\n    return $config;`))).not.toContain("variable-overwrite");
  });
  it("a name checked against an allowlist or an anchored pattern, or made numeric, can't name any variable", () => {
    expect(ids(fn(`    $name = $_GET['name'];\n    if (!in_array($name, ['color', 'font'], true)) return;\n    $$name = $_GET['value'];`))).not.toContain("variable-overwrite");
    expect(ids(fn(`    $varName = 'field_' . intval($_GET['id']);\n    $$varName = $_GET['val'];`))).not.toContain("variable-overwrite");
  });
  it("extract() of request data replaces a variable set before it, unless EXTR_SKIP / EXTR_PREFIX_* keep it", () => {
    const flow = (call: string) => ids(fn(`    $cmd = 'ls';\n    ${call};\n    system($cmd);`));
    expect(flow(`extract($_GET)`)).toContain("command-injection");
    expect(flow(`extract($_GET, EXTR_IF_EXISTS)`)).toContain("command-injection");
    expect(flow(`extract($_GET, EXTR_SKIP)`)).not.toContain("command-injection");
    expect(flow(`extract($_GET, EXTR_PREFIX_ALL, 'u')`)).not.toContain("command-injection");
    expect(flow(`extract(['color' => $_GET['c']])`)).not.toContain("command-injection");
    // set again after the extract: the request's value is gone
    expect(ids(fn(`    extract($_GET);\n    $cmd = 'ls';\n    system($cmd);`))).not.toContain("command-injection");
  });
  it("extract() of an array with fixed keys sets only those keys", () => {
    expect(ids(fn(`    $displayVars = ['color' => $_GET['color']];\n    extract($displayVars);\n    echo htmlspecialchars($color);`))).not.toContain("variable-overwrite");
  });
});

describe("Laravel accessors are request input only on a request", () => {
  const sink = (recv: string, params = "") => ids(`<?php\nfunction handler(${params}) {\n    $v = ${recv}('x');\n    system($v);\n}\n`);
  it("$request / a typed request / request() / $this->request", () => {
    expect(sink("$request->input")).toContain("command-injection");
    expect(sink("$r->get", "Request $r")).toContain("command-injection");
    expect(sink("request()->query")).toContain("command-injection");
    expect(sink("$this->request->post")).toContain("command-injection");
  });
  it("not a cache, repository or database handle with the same method names", () => {
    expect(sink("$cache->get")).not.toContain("command-injection");
    expect(sink("$repo->all")).not.toContain("command-injection");
    expect(sink("$pdo->query")).not.toContain("command-injection");
    // named like a request but typed as something else
    expect(sink("$request->get", "CacheItem $request")).not.toContain("command-injection");
  });
});

describe("mass assignment over a loop's keys, and a class picked by the request", () => {
  const allMass = (code: string) => analyzeFile("src/handler.php", code).indicators.filter(i => i.id === "mass-assignment");
  const loop = (src: string) => fn(`    $data = ${src};\n    $m = new stdClass();\n    foreach ($data as $k => $v) {\n        $m->$k = $v;\n    }`);
  it("the request's own keys are reported", () => {
    expect(allMass(loop(`$_POST`)).length).toBeGreaterThan(0);
    // intersected with a request-derived array: still the request's keys
    expect(allMass(loop(`array_intersect_key($_POST, $_GET)`)).length).toBeGreaterThan(0);
  });
  it("keys the code fixed -- literal keys, or intersected with a literal allow-list -- are not, by either layer", () => {
    expect(allMass(loop(`['name' => $_POST['name'], 'email' => $_POST['email']]`))).toEqual([]);
    expect(allMass(loop(`array_intersect_key($_POST, array_flip(['name', 'email']))`))).toEqual([]);
    expect(allMass(fn(`    $rules = ['name' => 'required', 'email' => 'email'];\n    $data = array_intersect_key($_POST, $rules);\n    $m = new stdClass();\n    foreach ($data as $k => $v) {\n        $m->$k = $v;\n    }`))).toEqual([]);
  });
  it("new $class() after an allow-list check is not reported; without one it is", () => {
    const pick = (check: string) => fn(`    $c = $_GET['handler'];\n${check}    $o = new $c();`);
    expect(ids(pick(""))).toContain("eval-exec");
    expect(ids(pick(`    if (!in_array($c, ['PdfHandler', 'CsvHandler'], true)) { return; }\n`))).not.toContain("eval-exec");
    // a check that doesn't hold on the path to the call
    expect(ids(pick(`    if (in_array($c, ['PdfHandler', 'CsvHandler'], true)) { log_it($c); }\n`))).toContain("eval-exec");
  });
});

describe("type juggling", () => {
  it("input loosely compared with a number, a hash, or strcmp's result; strict comparison is not", () => {
    expect(ids(fn(`    $id = $_GET['id'];\n    if ($id + 0 == 1) { echo "one"; }`))).toContain("type-juggling");
    expect(ids(fn(`    $token = $_GET['token'];\n    if ($token == $storedHash) { echo "ok"; }`))).toContain("type-juggling");
    expect(ids(fn(`    if (strcmp($_POST['pw'], $expected) == 0) { echo "ok"; }`))).toContain("type-juggling");
    expect(ids(fn(`    $token = $_GET['token'];\n    if ($token === $storedHash) { echo "ok"; }`))).not.toContain("type-juggling");
    expect(ids(fn(`    $name = $_GET['name'];\n    if ($name == 'admin') { echo "hi"; }`))).not.toContain("type-juggling");
  });
  it("a digest of input compared loosely with a number-looking string or a stored value; a text literal and strict comparison are not", () => {
    // "0e462097431906509019562988736854" is a "magic hash": every "0e<digits>" digest equals it under ==
    expect(ids(fn(`    $in = $_POST['pw'];\n    if (md5($in) == '0e462097431906509019562988736854') { echo "ok"; }`))).toContain("type-juggling");
    expect(ids(fn(`    $in = $_POST['pw'];\n    if (md5($in) == $stored) { echo "ok"; }`))).toContain("type-juggling");
    // a literal that is not number-like compares as text; === and hash_equals are exact
    expect(ids(fn(`    $in = $_POST['pw'];\n    if (sha1($in) == '0e89100756225895e68e7ba9189a28f18fc8bcc5') { echo "ok"; }`))).not.toContain("type-juggling");
    expect(ids(fn(`    $in = $_POST['pw'];\n    if (md5($in) === $stored) { echo "ok"; }`))).not.toContain("type-juggling");
    // a digest of something the request did not choose
    expect(ids(fn(`    if (md5('static') == $stored) { echo "ok"; }`))).not.toContain("type-juggling");
  });
  it("in_array / array_search without the strict flag against a list holding numbers or booleans; strict, or an all-string list, is not", () => {
    expect(ids(fn(`    $role = $_GET['role'];\n    if (in_array($role, [1, 2, 3])) { echo "admin"; }`))).toContain("type-juggling");
    expect(ids(fn(`    $k = $_GET['k'];\n    $i = array_search($k, ['a', 0, 'b']);`))).toContain("type-juggling");
    expect(ids(fn(`    $role = $_GET['role'];\n    if (in_array($role, [1, 2, 3], true)) { echo "admin"; }`))).not.toContain("type-juggling");
    expect(ids(fn(`    $role = $_GET['role'];\n    if (in_array($role, ['viewer', 'editor'])) { echo "ok"; }`))).not.toContain("type-juggling");
    expect(ids(fn(`    if (in_array('x', [1, 2, 3])) { echo "ok"; }`))).not.toContain("type-juggling");
  });
});

describe("file upload", () => {
  it("move_uploaded_file to the client's name; a generated name is not", () => {
    expect(ids(fn(`    $file = $_FILES['f'];\n    move_uploaded_file($file['tmp_name'], '/var/www/uploads/' . $file['name']);`))).toContain("insecure-file-upload");
    expect(ids(fn(`    $file = $_FILES['f'];\n    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));\n    $dest = '/var/www/uploads/' . bin2hex(random_bytes(16)) . '.' . $ext;\n    move_uploaded_file($file['tmp_name'], $dest);`))).not.toContain("insecure-file-upload");
  });
});
