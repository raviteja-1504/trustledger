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
  it("extract() of an array with fixed keys sets only those keys", () => {
    expect(ids(fn(`    $displayVars = ['color' => $_GET['color']];\n    extract($displayVars);\n    echo htmlspecialchars($color);`))).not.toContain("variable-overwrite");
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
});

describe("file upload", () => {
  it("move_uploaded_file to the client's name; a generated name is not", () => {
    expect(ids(fn(`    $file = $_FILES['f'];\n    move_uploaded_file($file['tmp_name'], '/var/www/uploads/' . $file['name']);`))).toContain("insecure-file-upload");
    expect(ids(fn(`    $file = $_FILES['f'];\n    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));\n    $dest = '/var/www/uploads/' . bin2hex(random_bytes(16)) . '.' . $ext;\n    move_uploaded_file($file['tmp_name'], $dest);`))).not.toContain("insecure-file-upload");
  });
});
