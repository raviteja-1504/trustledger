/**
 * @jest-environment node
 *
 * PHP engine coverage found scoring the 0llino sast-benchmark PHP suite and checked against DVWA: typed request
 * wrappers as sources, response factories as sinks, URL-capable file reads (path vs SSRF by what precedes the
 * value), more file/socket sinks, callables chosen by the caller, the weak-crypto rules, and the guards and
 * sanitizers ported from the other engines (host allowlists, realpath prefixes, anchored patterns, ctype_*, HMAC,
 * literal route maps, CR/LF stripping, OR-of-equalities allowlists).
 */
import { analyzeFile } from "@/lib/scanner";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";

beforeAll(async () => { await warmPhpTaintEngine(); }, 120000);

/** A handler taking a typed request (PSR-7 / Laravel / an app's own wrapper). */
const handler = (body: string, type = "ApiRequest") =>
  `<?php\nfunction handle(${type} $req): ApiResponse {\n${body}\n    return ApiResponse::ok('');\n}\n`;
const ids = (code: string) => analyzeFile("src/handler.php", code).indicators.map(i => i.id);
const has = (code: string, id: string) => ids(code).includes(id);

describe("sources and response sinks", () => {
  it("accessors on a parameter typed as a request are request input", () => {
    expect(has(handler(`    $f = $req->param('f');\n    readfile('/data/' . $f);`), "path-traversal")).toBe(true);
    expect(has(handler(`    $f = $req->getQueryParams();\n    readfile('/data/' . $f['x']);`, "ServerRequestInterface"), "path-traversal")).toBe(true);
    // the same method on something that isn't a request reads nothing from the client
    expect(has(handler(`    $f = $req->param('f');\n    readfile('/data/' . $f);`, "Config"), "path-traversal")).toBe(false);
  });

  it("Response::html() is an HTML body; Response::redirect() a Location", () => {
    expect(has(handler(`    $n = $req->param('n');\n    return ApiResponse::html('<p>' . $n . '</p>');`), "xss")).toBe(true);
    expect(has(handler(`    $n = $req->param('n');\n    return ApiResponse::html('<p>' . htmlspecialchars($n) . '</p>');`), "xss")).toBe(false);
    expect(has(handler(`    return ApiResponse::redirect($req->param('next'));`), "open-redirect")).toBe(true);
    expect(has(handler(`    $n = $req->param('n');\n    return Helper::html($n);`), "xss")).toBe(false);
  });
});

describe("file and socket sinks", () => {
  it("a URL-capable read is SSRF after a scheme, path traversal after a local prefix, both when raw", () => {
    const read = (arg: string) => ids(handler(`    $u = $req->param('u');\n    $c = file_get_contents(${arg});`));
    expect(read(`'http://169.254.169.254/latest/' . $u`)).toContain("ssrf");
    expect(read(`'http://169.254.169.254/latest/' . $u`)).not.toContain("path-traversal");
    expect(read(`'/var/data/' . $u`)).toContain("path-traversal");
    expect(read(`'/var/data/' . $u`)).not.toContain("ssrf");
    expect(read(`$u`)).toEqual(expect.arrayContaining(["path-traversal", "ssrf"]));
    // a constant base (DVWA_ROOT . "x") is a local directory
    expect(read(`APP_ROOT . "pages/{$u}.php"`)).not.toContain("ssrf");
    // a variable holding a URL prefix
    const viaVar = ids(handler(`    $meta = 'http://169.254.169.254/';\n    $c = file_get_contents($meta . $req->param('p'));`));
    expect(viaVar).toContain("ssrf");
    expect(viaVar).not.toContain("path-traversal");
  });

  it("copy/rename/glob/stat/unlink, move_uploaded_file's destination, fsockopen", () => {
    expect(has(handler(`    copy('/tmp/a', $req->param('dest'));`), "path-traversal")).toBe(true);
    expect(has(handler(`    glob($req->param('pattern'));`), "path-traversal")).toBe(true);
    expect(has(handler(`    unlink('/up/' . $req->param('f'));`), "path-traversal")).toBe(true);
    expect(has(handler(`    move_uploaded_file($_FILES['f']['tmp_name'], '/up/' . $req->post('name'));`), "path-traversal")).toBe(true);
    // the upload's own tmp_name is chosen by PHP, not the client
    expect(has(handler(`    move_uploaded_file($_FILES['f']['tmp_name'], '/up/fixed.dat');`), "path-traversal")).toBe(false);
    expect(has(handler(`    $fp = fsockopen($req->param('host'), 80);`), "ssrf")).toBe(true);
  });
});

describe("callables and code", () => {
  it("call_user_func / callback builtins / dynamic calls run what the client names", () => {
    expect(has(handler(`    call_user_func_array($req->post('handler'), [1]);`), "eval-exec")).toBe(true);
    expect(has(handler(`    $a = [3, 1];\n    usort($a, $req->post('cmp'));`), "eval-exec")).toBe(true);
    expect(has(handler(`    $a = [3, 1];\n    usort($a, 'strcmp');`), "eval-exec")).toBe(false);
    expect(has(handler(`    $fn = $req->param('fn');\n    $fn('x');`), "eval-exec")).toBe(true);
    expect(has(handler(`    $m = $req->param('m');\n    $o = new Report();\n    $o->$m();`), "eval-exec")).toBe(true);
    expect(has(handler(`    $c = $req->param('cls');\n    $o = new $c();`), "eval-exec")).toBe(true);
  });

  it("preg_replace with /e and string assert() evaluate PHP", () => {
    expect(has(handler(`    $r = preg_replace('/(.+)/e', $req->post('r'), 'x');`), "eval-exec")).toBe(true);
    expect(has(handler(`    $r = preg_replace('/(.+)/i', $req->post('r'), 'x');`), "eval-exec")).toBe(false);
    expect(has(handler(`    assert($req->param('expr'));`), "eval-exec")).toBe(true);
  });
});

describe("weak crypto", () => {
  const crypto = (line: string) => analyzeFile("src/c.php", `<?php\nfunction f($data, $password, $key) {\n    ${line}\n}\n`).indicators.filter(i => i.id === "weak-crypto").length;
  it("MD5/SHA-1/MD4 hashing, HMAC-MD5, fast password hashes, ECB/DES/RC4", () => {
    expect(crypto(`return md5($data);`)).toBe(1);
    expect(crypto(`return hash('md4', $data);`)).toBe(1);
    expect(crypto(`return hash_hmac('md5', $data, $key);`)).toBe(1);
    expect(crypto(`return hash('sha256', 'salt' . $password);`)).toBe(1);
    expect(crypto(`return openssl_encrypt($data, 'AES-128-ECB', $key);`)).toBe(1);
    expect(crypto(`return openssl_encrypt($data, 'des-cbc', $key);`)).toBe(1);
  });
  it("SHA-256 of data, HMAC-SHA256, AES-GCM and password_hash are fine", () => {
    expect(crypto(`return hash('sha256', $data);`)).toBe(0);
    expect(crypto(`return hash_hmac('sha256', $data, $key);`)).toBe(0);
    expect(crypto(`return openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);`)).toBe(0);
    expect(crypto(`return password_hash($password, PASSWORD_DEFAULT);`)).toBe(0);
    // a method named md5 on some object is not PHP's md5()
    expect(crypto(`return $this->md5($data);`)).toBe(0);
  });
});

describe("guards and sanitizers", () => {
  it("an allowlisted parse_url host vets the URL (variable, inline and array forms)", () => {
    const allow = (check: string, sink = `file_get_contents($url)`) => ids(handler(`    $url = $req->param('url');\n    ${check}\n    $c = ${sink};`));
    expect(allow(`$host = parse_url($url, PHP_URL_HOST);\n    if (!in_array($host, ['a.example.com'], true)) { return ApiResponse::badRequest('no'); }`)).not.toContain("ssrf");
    expect(allow(`if (!in_array(parse_url($url, PHP_URL_HOST), ['a.example.com'], true)) { return ApiResponse::badRequest('no'); }`)).not.toContain("ssrf");
    expect(allow(`$p = parse_url($url);\n    if (!in_array($p['host'] ?? '', ['a.example.com'], true)) { return ApiResponse::badRequest('no'); }`, `header('Location: ' . $url)`)).not.toContain("open-redirect");
    // a scheme check doesn't vet the destination (either form)
    expect(allow(`if (!in_array(parse_url($url, PHP_URL_SCHEME), ['https'], true)) { return ApiResponse::badRequest('no'); }`)).toContain("ssrf");
    expect(allow(`$p = parse_url($url);\n    if (!in_array($p['scheme'] ?? '', ['https'], true)) { return ApiResponse::badRequest('no'); }`)).toContain("ssrf");
  });

  it("realpath + a base-prefix check confines a path (strpos === 0 and str_starts_with)", () => {
    const confine = (check: string) => ids(handler(`    $base = '/var/files';\n    $real = realpath($base . '/' . $req->param('f'));\n    if (${check}) { return ApiResponse::badRequest('no'); }\n    $c = file_get_contents($real);`));
    expect(confine(`$real === false || strpos($real, $base) !== 0`)).not.toContain("path-traversal");
    expect(confine(`$real === false || !str_starts_with($real, $base)`)).not.toContain("path-traversal");
    // without realpath, "/var/files/../etc" passes a prefix check
    const raw = (check: string) => ids(handler(`    $base = '/var/files';\n    $p = $base . '/' . $req->param('f');\n    if (${check}) { return ApiResponse::badRequest('no'); }\n    $c = file_get_contents($p);`));
    expect(raw(`!str_starts_with($p, $base)`)).toContain("path-traversal");
    expect(raw(`strpos($p, $base) !== 0`)).toContain("path-traversal");
  });

  it("str_contains / strpos for '..' rules out traversal", () => {
    const body = (check: string) => ids(handler(`    $f = $req->param('f');\n    if (${check}) { return ApiResponse::badRequest('no'); }\n    $c = file_get_contents('/files/' . $f);`));
    expect(body(`str_contains($f, '..')`)).not.toContain("path-traversal");
    expect(body(`strpos($f, '..') !== false`)).not.toContain("path-traversal");
    expect(body(`str_contains($f, 'x')`)).toContain("path-traversal");
  });

  it("anchored preg_match patterns and ctype_alnum validate", () => {
    const body = (check: string) => ids(handler(`    $f = $req->param('f');\n    if (${check}) { return ApiResponse::badRequest('no'); }\n    header('X-Token: ' . $f);\n    $c = file_get_contents('/files/' . $f);`));
    expect(body(`!preg_match('/^[a-zA-Z0-9_-]+\\.(jpg|png)$/', $f)`)).not.toContain("path-traversal");
    expect(body(`!ctype_alnum($f)`)).not.toContain("header-injection");
    expect(body(`!preg_match('/^[a-z\\/.]+$/', $f)`)).toContain("path-traversal");
    expect(body(`!preg_match('/[a-z]+/', $f)`)).toContain("path-traversal");
  });

  it("removing CR/LF leaves one header line; a negated-class preg_replace leaves its alphabet", () => {
    expect(has(handler(`    $v = str_replace(["\\r", "\\n"], '', $req->param('v'));\n    header('X-Value: ' . $v);`), "header-injection")).toBe(false);
    expect(has(handler(`    $v = preg_replace('/[\\r\\n]/', '', $req->param('v'));\n    header('X-Value: ' . $v);`), "header-injection")).toBe(false);
    expect(has(handler(`    $v = str_replace('a', '', $req->param('v'));\n    header('X-Value: ' . $v);`), "header-injection")).toBe(true);
    // a replace that removes nothing dangerous carries its replacement too
    expect(has(handler(`    $v = str_replace('x', $req->param('v'), 'static');\n    header('X-Value: ' . $v);`), "header-injection")).toBe(true);
    // replacing with something other than '' can put the dangerous character back
    expect(has(handler(`    $n = preg_replace('/[^a-zA-Z0-9_-]/', '/', $req->param('n'));\n    mkdir('/projects/' . $n);`), "path-traversal")).toBe(true);
    expect(has(handler(`    $n = preg_replace('/[^a-zA-Z0-9_-]/', '', $req->param('n'));\n    mkdir('/projects/' . $n);`), "path-traversal")).toBe(false);
    expect(has(handler(`    $n = preg_replace('/[^a-zA-Z0-9_\\/.-]/', '', $req->param('n'));\n    mkdir('/projects/' . $n);`), "path-traversal")).toBe(true);
  });

  it("basename / pathinfo extension can't climb out or include from elsewhere", () => {
    expect(has(handler(`    include 'templates/' . basename($req->param('t')) . '.php';`), "file-inclusion")).toBe(false);
    expect(has(handler(`    $ext = pathinfo($req->param('n'), PATHINFO_EXTENSION);\n    file_put_contents('/up/x.' . $ext, 'd');`), "path-traversal")).toBe(false);
    expect(has(handler(`    $d = pathinfo($req->param('n'), PATHINFO_DIRNAME);\n    file_put_contents('/up/' . $d, 'd');`), "path-traversal")).toBe(true);
  });

  it("a literal route map only yields its literals", () => {
    const body = (map: string) => ids(handler(`    $routes = ${map};\n    $url = $routes[$req->param('page')] ?? '/';\n    header('Location: ' . $url);`));
    expect(body(`['home' => '/', 'about' => '/about']`)).not.toContain("open-redirect");
    expect(body(`['home' => '/', 'next' => $req->param('n')]`)).toContain("open-redirect");
    // a container this code didn't build keeps the index's taint (it may hold anything)
    expect(body(`load_routes()`)).toContain("open-redirect");
  });

  it("a server-verified HMAC over the target", () => {
    const body = (check: string) => ids(handler(`    $url = $req->param('url');\n    if (${check}) { return ApiResponse::badRequest('sig'); }\n    header('Location: ' . $url);`));
    expect(body(`!hash_equals(hash_hmac('sha256', $url, getenv('K')), $req->param('sig'))`)).not.toContain("open-redirect");
    expect(body(`$req->param('sig') === ''`)).toContain("open-redirect");
  });

  it("an IP validated with FILTER_VALIDATE_IP is still a destination unless private/reserved ranges are refused", () => {
    const body = (flags: string) => ids(handler(`    $ip = $req->param('ip');\n    if (!filter_var($ip, FILTER_VALIDATE_IP${flags})) { return ApiResponse::badRequest('ip'); }\n    $c = file_get_contents('http://' . $ip . '/api');`));
    expect(body(`, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`)).not.toContain("ssrf");
    expect(body(``)).toContain("ssrf");
  });

  it("an OR of equalities on one (normalized) value is an allowlist", () => {
    const body = (cond: string) => ids(handler(`    $e = $req->param('ext');\n    if (${cond}) {\n        file_put_contents('/up/a.' . $e, 'd');\n    }`));
    expect(body(`strtolower($e) == 'jpg' || strtolower($e) == 'png'`)).not.toContain("path-traversal");
    expect(body(`strtolower($e) == 'jpg' || $req->param('x') == 'png'`)).toContain("path-traversal");
  });
});
