import { warmPhpTaintEngine, parsePhpSourceSync, scanAstTaintPHP } from "@/lib/astTaintPHP";

// Recall + precision for the PHP AST engine: stdlib passthroughs/decoders, dynamic property/function
// calls, generators, global-shared state, and the sinks/structural checks added with them.

beforeAll(async () => { await warmPhpTaintEngine(); }, 30000);

function ids(code: string): string[] {
  const root = parsePhpSourceSync(code, "x.php");
  if (!root) throw new Error("parse failed");
  return scanAstTaintPHP(code, "x.php", root).map(f => f.id);
}
const has = (code: string, id: string) => ids(code).includes(id);
const wrap = (body: string) => `<?php\n${body}\n`;

describe("stdlib passthroughs and decoders", () => {
  it("trim() carries request taint through a helper", () => {
    const code = wrap(`function bu($id){$n=trim($id); return "SELECT * FROM t WHERE id='$n'";}
      function exec_sql($q){global $db; return $db->query($q);}
      function f(){return exec_sql(bu($_GET['id']));}`);
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("array_merge + implode carries taint into a shell command", () => {
    const code = wrap(`function bc($p){return implode(" ",$p);}
      function f(){$h=$_POST['host']; $cmd=bc(array_merge(["ping"],$h)); return shell_exec($cmd);}`);
    expect(has(code, "command-injection")).toBe(true);
  });
  it("json_encode/json_decode round trip carries taint into a header", () => {
    const code = wrap(`function f(){$p=json_encode(["value"=>$_GET['value']]); $d=json_decode($p,true); header("X-Value: ".$d['value']);}`);
    expect(has(code, "header-injection")).toBe(true);
  });
  it("realpath() does not itself neutralize a path traversal", () => {
    const code = wrap(`function f(){$n=$_GET['name']; return file_get_contents(realpath("/base/".$n));}`);
    expect(has(code, "path-traversal")).toBe(true);
  });
  it("urldecode() carries taint into a header (CRLF after decode)", () => {
    expect(has(wrap(`function f(){header("X-Next: ".urldecode($_GET['location']));}`), "header-injection")).toBe(true);
  });
  it("encode-then-decode brings XSS danger back", () => {
    const code = wrap(`function f(){$e=urlencode($_GET['value']); $d=urldecode($e); echo "<div>".$d."</div>";}`);
    expect(has(code, "xss")).toBe(true);
  });
  it("file_get_contents('php://input') is a source", () => {
    const code = wrap(`function f(){$b=file_get_contents("php://input"); echo "<div>".$b."</div>";}`);
    expect(has(code, "xss")).toBe(true);
  });
});

describe("closures, generators and global state", () => {
  it("a closure built from tainted data and called later carries it", () => {
    const code = wrap(`function rl($v){ return function() use ($v) { return $v; }; }
      function f(){ $r=rl($_GET['html']); echo $r(); }`);
    expect(has(code, "xss")).toBe(true);
  });
  it("a callback applied through a higher-order helper carries taint", () => {
    const code = wrap(`function with_value($v,$cb){return $cb($v);}
      function f(){echo with_value($_GET['q'], function($x){return "<div>".$x."</div>";});}`);
    expect(has(code, "xss")).toBe(true);
  });
  it("a generator's yielded value carries taint to its foreach consumer", () => {
    const code = wrap(`function ms($id){ yield "SELECT * FROM t WHERE id='$id'"; }
      function f(){ foreach(ms($_GET['id']) as $q){ global $db; $db->query($q); } }`);
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("second-order SQLi through a global array", () => {
    const code = wrap(`function save(){global $saved; $saved[$_POST['user']]=$_POST['search'];}
      function run(){global $saved; $stored=$saved[$_GET['user']]; global $db; return $db->query("SELECT * FROM t WHERE n='".$stored."'");}`);
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("stored XSS through a global array appended in one function and echoed in another", () => {
    const code = wrap(`function s(){global $c; $c[]=$_POST['comment'];}
      function r(){global $c; foreach($c as $x){ echo "<li>".$x."</li>"; }}`);
    expect(has(code, "xss")).toBe(true);
  });
});

describe("new sinks", () => {
  it.each([
    ["eval()", wrap(`function f(){return eval($_POST['expression']);}`), "eval-exec"],
    ["dynamic function call by attacker-chosen name", wrap(`function f(){$fn=$_POST['function']; return $fn($_POST['argument']);}`), "eval-exec"],
    ["curl_init with tainted URL", wrap(`function f(){$c=curl_init($_GET['url']); return curl_exec($c);}`), "ssrf"],
    ["Twig createTemplate", wrap(`function f(){$t=new \\Twig\\Environment(new \\Twig\\Loader\\ArrayLoader([])); return $t->createTemplate($_POST['template'])->render([]);}`), "ssti"],
    ["ReDoS: tainted pattern", wrap(`function f(){return preg_match($_GET['pattern'],$_GET['value']);}`), "redos"],
    ["ReDoS: pattern built by a helper", wrap(`function cr($p){return "/".$p."/i";} function f(){return preg_match(cr($_POST['pattern']),$_POST['input']);}`), "redos"],
    ["dynamic property set (reflection-style)", wrap(`class C{public $role="user";} function sa($o,$n,$v){$o->$n=$v;} function f(){$c=new C(); sa($c,$_POST['attribute'],$_POST['value']); return $c;}`), "mass-assignment"],
    ["mass assignment via array merge onto object fields", wrap(`class C{public $role="user";} function af($o,$fs){foreach($fs as $k=>$v){$o->$k=$v;} return $o;} function f(){return af(new C(), $_POST);}`), "mass-assignment"],
    ["array-merge mass assignment (pollution analogue)", wrap(`function dm($t,$s){foreach($s as $k=>$v){$t[$k]=$v;} return $t;}
      function f(){$in=json_decode(file_get_contents("php://input"),true); return dm(["options"=>[]],$in);}`), "mass-assignment"],
    ["hand-rolled JWT decode without verification", wrap(`function f(){$t=str_replace("Bearer ","",$_SERVER['HTTP_AUTHORIZATION']); $p=explode(".",$t); $c=json_decode(base64_decode($p[1]),true); return $c['role'];}`), "jwt-none-alg"],
    ["timing-unsafe secret compare", wrap(`const APP_SECRET="s"; function f(){if($_GET['token']==APP_SECRET){return "ok";} return "no";}`), "timing-attack"],
  ])("%s", (_l, code, id) => {
    expect(has(code, id)).toBe(true);
  });
  it("an HTML-encoded value placed inside a <script> block is still XSS", () => {
    const code = wrap(`function f(){$v=htmlspecialchars($_GET['value']); echo "<script>const x='".$v."';</script>";}`);
    expect(has(code, "xss")).toBe(true);
  });
});

describe("precision", () => {
  it("intval() neutralizes SQL injection", () => {
    const code = wrap(`function f(){global $db; $id=intval($_GET['id']); return $db->query("SELECT * FROM t WHERE id=".$id);}`);
    expect(has(code, "sql-injection")).toBe(false);
  });
  it("a plain callback parameter that is only ever called (never reassigned from a source) is not eval-exec", () => {
    const code = wrap(`function with_value($v,$cb){return $cb($v);}
      function f(){echo with_value($_GET['q'], function($x){return "<div>".$x."</div>";});}`);
    expect(has(code, "eval-exec")).toBe(false);
  });
  it("htmlspecialchars() in an ordinary HTML body context is not XSS", () => {
    expect(has(wrap(`function f(){echo "<div>".htmlspecialchars($_GET['value'])."</div>";}`), "xss")).toBe(false);
  });
  it("matching tainted DATA against a literal pattern is not ReDoS", () => {
    expect(has(wrap(`function f(){return preg_match("/^[a-z]+$/",$_GET['value']);}`), "redos")).toBe(false);
  });
  it("comparing two request values is not a secret compare", () => {
    expect(has(wrap(`function f(){if($_GET['token']==$_GET['password']){return "ok";} return "no";}`), "timing-attack")).toBe(false);
  });
  it("a literal allowlist guard clears the value", () => {
    const code = wrap(`function f(){$v=$_GET['q']; if(!in_array($v,["a","b"],true)){return "bad";} echo "<b>".$v."</b>";}`);
    expect(has(code, "xss")).toBe(false);
  });
  it("an opaque unknown function call does not carry taint", () => {
    expect(has(wrap(`function f(){$s=mystery($_GET['q']); echo "<b>".$s."</b>";}`), "xss")).toBe(false);
  });
  it("extract() of a literal array does not taint every local variable", () => {
    expect(has(wrap(`function f(){extract(["a"=>1]); echo "<b>".$a."</b>";}`), "xss")).toBe(false);
  });
  it("a request-independent function has no findings", () => {
    expect(ids(wrap(`function f(){$s="SELECT 1"; echo "<b>".$s."</b>";}`))).toEqual([]);
  });
});
