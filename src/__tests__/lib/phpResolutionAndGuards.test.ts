/**
 * @jest-environment node
 *
 * PHP engine precision checks from an external review, each with a twin:
 *  - a call runs the function / method of ITS identity -- two classes' same-named methods, a method named like a
 *    global function, a namespace-qualified call, a static method;
 *  - type juggling recognises a hash by where it came from (hash() / md5() / a helper returning one), in == / != and
 *    in a switch's cases, whatever the variables are called;
 *  - the Reflection API and `$class::method()` choosing code by request input;
 *  - a realpath() prefix check confines only when the base ends at a directory, realpath() fetches nothing remote,
 *    and a literal host allow-list leaves no local file to read.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";

beforeAll(async () => { await warmPhpTaintEngine(); }, 120000);

const engine = (code: string) => analyzeFile("src/h.php", `<?php\n${code}\n`).indicators.filter(i => !!i.sourceExpr).map(i => i.id);
const fn = (body: string) => `function h() {\n${body}\n}`;

describe("a call resolves to the function or method of its own identity", () => {
  const AB = `class A { function get($x) { return $x; } }\nclass B { function get($x) { return 'k'; } }\n`;
  it("two classes' same-named methods keep their own summaries", () => {
    expect(engine(AB + fn(`  $a = new A();\n  system($a->get($_GET['x']));`))).toContain("command-injection");
    expect(engine(AB + fn(`  $b = new B();\n  system($b->get($_GET['x']));`))).not.toContain("command-injection");
  });
  it("a method named like a global function is its own: each body is analysed", () => {
    const GC = `function clean($x) { return 'safe'; }\nclass C { function clean($x) { return $x; } }\n`;
    expect(engine(GC + fn(`  system(clean($_GET['x']));`))).not.toContain("command-injection");
    expect(engine(GC + fn(`  $c = new C();\n  system($c->clean($_GET['x']));`))).toContain("command-injection");
  });
  it("$this-> and self:: calls run the enclosing class's method", () => {
    const cls = (call: string) => `class Q { function wrap($x) { return $x; } function run() { system(${call}($_GET['x'])); } }\nclass R { function wrap($x) { return 'k'; } }\n`;
    expect(engine(cls("$this->wrap"))).toContain("command-injection");
    expect(engine(`class Q { static function wrap($x) { return $x; } function run() { system(self::wrap($_GET['x'])); } }\nclass R { static function wrap($x) { return 'k'; } }`)).toContain("command-injection");
    // ...not another class's same-named method: Q's own returns a constant
    expect(engine(`class Q { function wrap($x) { return 'k'; } function run() { system($this->wrap($_GET['x'])); } }\nclass R { function wrap($x) { return $x; } }`)).not.toContain("command-injection");
  });
  it("a namespace-qualified call, and a static method, resolve", () => {
    const ns = `namespace App;\nfunction build($x) { return "ls " . $x; }\n`;
    expect(engine(ns + fn(`  system(\\App\\build($_GET['x']));`))).toContain("command-injection");
    expect(engine(`class S { static function run($x) { system($x); } }\n` + fn(`  S::run($_GET['x']);`))).toContain("command-injection");
  });
  it("an unknown receiver may run any same-named method: their results combine", () => {
    expect(engine(AB + fn(`  system($svc->get($_GET['x']));`))).toContain("command-injection");
  });
});

describe("type juggling: a hash recognised by its origin", () => {
  it("a local assigned hash() / md5(), compared loosely with input", () => {
    expect(engine(fn(`  $expected = hash('sha256', $pw);\n  $provided = $_GET['h'];\n  if ($provided == $expected) { login(); }`))).toContain("type-juggling");
    expect(engine(fn(`  $x1 = md5($secret);\n  if ($_POST['t'] != $x1) { exit; }`))).toContain("type-juggling");
  });
  it("a helper that returns a hash", () => {
    expect(engine(`function mk($p) { return hash('sha256', $p); }\n` + fn(`  $e = mk($pw);\n  if ($_GET['h'] == $e) { login(); }`))).toContain("type-juggling");
    // a helper that returns something else -- on any path -- is no hash
    expect(engine(`function mk($p) { return trim($p); }\n` + fn(`  $e = mk($pw);\n  if ($_GET['h'] == $e) { login(); }`))).not.toContain("type-juggling");
    expect(engine(`function mk($p) { if ($p === '') { return 'guest'; } return md5($p); }\n` + fn(`  $e = mk($pw);\n  if ($_GET['h'] == $e) { login(); }`))).not.toContain("type-juggling");
  });
  it("a switch on input with a hash among its cases", () => {
    expect(engine(fn(`  $h = md5($pw);\n  switch ($_GET['h']) { case $h: login(); }`))).toContain("type-juggling");
    expect(engine(fn(`  switch ($_GET['page']) { case 'home': show(); }`))).not.toContain("type-juggling");
    expect(engine(fn(`  $h = md5($pw);\n  switch ($fixed) { case $h: login(); }`))).not.toContain("type-juggling");
  });
  it("strict comparison and hash_equals are not reported", () => {
    expect(engine(fn(`  $expected = hash('sha256', $pw);\n  if ($_GET['h'] === $expected) { login(); }`))).not.toContain("type-juggling");
    expect(engine(fn(`  $expected = hash('sha256', $pw);\n  if (hash_equals($expected, $_GET['h'])) { login(); }`))).not.toContain("type-juggling");
  });
});

describe("code chosen by the request through reflection", () => {
  it("ReflectionClass / ReflectionMethod / ReflectionFunction / $class::method()", () => {
    expect(engine(fn(`  $r = new ReflectionClass($_GET['c']);\n  $o = $r->newInstance();`))).toContain("eval-exec");
    expect(engine(fn(`  $m = new ReflectionMethod($obj, $_GET['m']);\n  $m->invoke($obj);`))).toContain("eval-exec");
    expect(engine(fn(`  $m = new ReflectionMethod($_GET['m']);`))).toContain("eval-exec");
    expect(engine(fn(`  $f = new ReflectionFunction($_GET['f']);\n  $f->invoke();`))).toContain("eval-exec");
    expect(engine(fn(`  $c = $_GET['c'];\n  $c::run();`))).toContain("eval-exec");
  });
  it("not a fixed name, the object argument, or an allow-listed name", () => {
    expect(engine(fn(`  $m = new ReflectionMethod($_GET['o'], 'render');`))).not.toContain("eval-exec");
    expect(engine(fn(`  $r = new ReflectionClass('App\\\\Report');`))).not.toContain("eval-exec");
    expect(engine(fn(`  $c = $_GET['c'];\n  if (!in_array($c, ['PdfExport', 'CsvExport'], true)) { exit; }\n  $r = new ReflectionClass($c);`))).not.toContain("eval-exec");
    expect(engine(fn(`  $c = $_GET['c'];\n  if (!in_array($c, ['PdfExport', 'CsvExport'], true)) { exit; }\n  $c::run();`))).not.toContain("eval-exec");
  });
});

describe("path and URL confinement", () => {
  const read = (check: string) => fn(`  $real = realpath('/var/www/files/' . $_GET['f']);\n  if (${check}) { readfile($real); }`);
  it("a prefix check ending at a directory confines the resolved path", () => {
    expect(engine(read(`strpos($real, '/var/www/files/') === 0`))).not.toContain("path-traversal");
    expect(engine(read(`$real !== false && str_starts_with($real, '/var/www/files/')`))).not.toContain("path-traversal");
    expect(engine(read(`strpos($real, $base . DIRECTORY_SEPARATOR) === 0`))).not.toContain("path-traversal");
  });
  it("one that doesn't also admits a sibling directory (/var/www/files-evil)", () => {
    expect(engine(read(`strpos($real, '/var/www/files') === 0`))).toContain("path-traversal");
    expect(engine(read(`str_starts_with($real, '/var/www/files')`))).toContain("path-traversal");
    expect(engine(fn(`  $base = realpath('/var/www/files');\n  $real = realpath($base . '/' . $_GET['f']);\n  if (strpos($real, $base) === 0) { readfile($real); }`))).toContain("path-traversal");
  });
  it("realpath() names a local file: no SSRF from what it returns", () => {
    expect(engine(read(`strpos($real, '/var/www/files') === 0`))).not.toContain("ssrf");
    // the same file function on the raw request value can fetch a URL
    expect(engine(fn(`  $name = $_GET['f'];\n  readfile($name);`))).toContain("ssrf");
  });
  it("a literal host allow-list leaves no local file to read; a suffix check vets nothing", () => {
    const fetch = (check: string) => fn(`  $u = $_GET['u'];\n  if (${check}) { echo file_get_contents($u); }`);
    expect(engine(fetch(`in_array(parse_url($u, PHP_URL_HOST), ['api.example.com'], true)`))).toEqual([]);
    const ends = engine(fetch(`str_ends_with(parse_url($u, PHP_URL_HOST), 'example.com')`));
    expect(ends).toContain("ssrf");
    expect(ends).toContain("path-traversal");
  });
});
