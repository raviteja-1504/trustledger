import { analyzeFile } from "@/lib/scanner";

describe("PHP SQL injection via interpolation (found via real-world OWASP DVWA testing)", () => {
  it("flags a tainted variable interpolated directly into a double-quoted SQL string", () => {
    const content = `
<?php
if( isset( $_REQUEST[ 'Submit' ] ) ) {
	$id = $_REQUEST[ 'id' ];
	$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
	$result = mysqli_query($conn, $query);
}
?>
`;
    const result = analyzeFile("sqli/source/low.php", content);
    const finding = result.indicators.find(i => i.id === "sql-injection");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
    expect(result.risk_score).toBe("CRITICAL");
  });

  it("does not flag an untainted variable interpolated into a SQL string", () => {
    const content = `
<?php
$tableName = "users";
$query = "SELECT first_name, last_name FROM $tableName WHERE active = 1;";
$result = mysqli_query($conn, $query);
?>
`;
    const result = analyzeFile("db/report.php", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(false);
  });
});

describe("PHP command injection via concatenation (found via real-world OWASP DVWA testing)", () => {
  it("flags a tainted variable concatenated into a shell_exec call", () => {
    const content = `
<?php
if( isset( $_POST[ 'Submit' ]  ) ) {
	$target = $_REQUEST[ 'ip' ];
	$cmd = shell_exec( 'ping  -c 4 ' . $target );
	echo $cmd;
}
?>
`;
    const result = analyzeFile("exec/source/low.php", content);
    const finding = result.indicators.find(i => i.id === "command-injection");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
    expect(result.risk_score).toBe("CRITICAL");
  });

  it("does not misfire on an ordinary regex .exec() call sharing the bare 'exec(' token", () => {
    const content = `
function parseLine(pattern, line) {
  const target = pattern.exec(line);
  return target;
}
module.exports = parseLine;
`;
    const result = analyzeFile("src/lib/parseLine.ts", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(false);
  });
});

describe("PHP file inclusion (LFI/RFI) — a previously completely uncovered vulnerability class", () => {
  it("flags a request parameter passed directly to include()", () => {
    const content = `
<?php
$page = isset($_GET['page']) ? $_GET['page'] : 'home.php';
include($_GET['page']);
?>
`;
    const result = analyzeFile("router.php", content);
    const finding = result.indicators.find(i => i.id === "file-inclusion");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("flags a tainted variable passed to require_once", () => {
    const content = `
<?php
$file = $_GET['page'];
require_once($file);
?>
`;
    const result = analyzeFile("loader.php", content);
    expect(result.indicators.some(i => i.id === "file-inclusion")).toBe(true);
  });

  it("does not flag a static, hardcoded include", () => {
    const content = `
<?php
require_once 'includes/config.php';
include 'header.php';
?>
`;
    const result = analyzeFile("app.php", content);
    expect(result.indicators.some(i => i.id === "file-inclusion")).toBe(false);
  });
});

describe("PHP extractTaintedVars: filter_input()/extract() propagate end-to-end", () => {
  it("propagates filter_input(INPUT_GET, ...) into a real detector, mirroring Go's := and C#'s [FromRoute] fixes", () => {
    const content = `
<?php
$ip = filter_input(INPUT_GET, 'ip');
$cmd = shell_exec('ping -c 1 ' . $ip);
?>
`;
    const result = analyzeFile("ping.php", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(true);
  });

  it("propagates extract($_GET)'s bulk taint into a real detector", () => {
    const content = `
<?php
extract($_GET);
$cmd = shell_exec('ping -c 1 ' . $target);
?>
`;
    const result = analyzeFile("ping_extract.php", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(true);
  });
});

describe("PHP SQL injection — additional precision cases", () => {
  it("does not flag a PDO ?-placeholder parameterised query", () => {
    const content = `
<?php
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
?>
`;
    const result = analyzeFile("users/safe_pdo.php", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(false);
  });

  it("flags a multi-line query built with .= concatenation before execution", () => {
    const content = `
<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '";
$query .= $id;
mysqli_query($conn, $query);
?>
`;
    const result = analyzeFile("users/multiline.php", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(true);
  });
});

describe("PHP command injection — escapeshellarg guard and new sinks", () => {
  it("does not flag a shell_exec call wrapped in escapeshellarg()", () => {
    const content = `
<?php
$ip = $_GET['ip'];
$out = shell_exec('ping -c 1 ' . escapeshellarg($ip));
?>
`;
    const result = analyzeFile("ping_safe.php", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(false);
  });

  it("flags proc_open with a tainted argument", () => {
    const content = `
<?php
$cmd = $_GET['cmd'];
$proc = proc_open($cmd, $descriptors, $pipes);
?>
`;
    const result = analyzeFile("run_proc.php", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(true);
  });

  it("flags backtick execution with an inline superglobal", () => {
    const content = `
<?php
if (isset($_GET['ip'])) {
  $out = \`ping -c 1 $_GET[ip]\`;
  echo $out;
}
?>
`;
    const result = analyzeFile("backtick.php", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(true);
  });
});

describe("PHP insecure deserialization (unserialize) — a previously weakly-covered vulnerability class", () => {
  it("flags a named variable assigned from a superglobal then unserialized", () => {
    const content = `
<?php
$data = $_COOKIE['data'];
$obj = unserialize($data);
?>
`;
    const result = analyzeFile("session/restore.php", content);
    expect(result.indicators.some(i => i.id === "insecure-deserialization")).toBe(true);
  });

  it("flags unserialize() fed by base64_decode() of a superglobal", () => {
    const content = `
<?php
$obj = unserialize(base64_decode($_GET['data']));
?>
`;
    const result = analyzeFile("session/restore2.php", content);
    expect(result.indicators.some(i => i.id === "insecure-deserialization")).toBe(true);
  });

  it("flags an ordinary file operation on a phar:// URI", () => {
    const content = `
<?php
$path = $_GET['path'];
if (file_exists("phar://" . $path)) { echo "found"; }
?>
`;
    const result = analyzeFile("check.php", content);
    const finding = result.indicators.find(i => i.id === "insecure-deserialization");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });
});

describe("PHP XSS — a previously completely uncovered vulnerability class", () => {
  it("flags echo of an unescaped superglobal", () => {
    const content = `
<?php
if (isset($_GET['name'])) {
  echo "Hello, " . $_GET['name'];
}
?>
`;
    const result = analyzeFile("greet.php", content);
    expect(result.indicators.some(i => i.id === "xss")).toBe(true);
  });

  it("flags a named-taint echo of an unescaped variable", () => {
    const content = `
<?php
$name = $_GET['name'];
echo "Welcome!";
echo $name;
?>
`;
    const result = analyzeFile("greet2.php", content);
    expect(result.indicators.some(i => i.id === "xss")).toBe(true);
  });

  it("does not flag echo wrapped in htmlspecialchars()", () => {
    const content = `
<?php
if (isset($_GET['name'])) {
  echo htmlspecialchars($_GET['name']);
}
?>
`;
    const result = analyzeFile("greet_safe.php", content);
    expect(result.indicators.some(i => i.id === "xss")).toBe(false);
  });
});

describe("PHP SSRF — named-taint and new sink families", () => {
  it("flags a named-taint curl_setopt CURLOPT_URL call", () => {
    const content = `
<?php
$url = $_GET['url'];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
?>
`;
    const result = analyzeFile("fetch.php", content);
    expect(result.indicators.some(i => i.id === "ssrf")).toBe(true);
  });

  it("flags a Guzzle client call with a tainted URL", () => {
    const content = `
<?php
$url = $_GET['url'];
$response = $client->get($url);
?>
`;
    const result = analyzeFile("fetch_guzzle.php", content);
    expect(result.indicators.some(i => i.id === "ssrf")).toBe(true);
  });
});

describe("PHP path traversal — named-taint variant", () => {
  it("flags a named-taint fopen() call", () => {
    const content = `
<?php
$f = $_GET['file'];
$fh = fopen($f, 'r');
?>
`;
    const result = analyzeFile("download.php", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(true);
  });
});

describe("PHP IDOR/BOLA — a previously totally uncovered vulnerability class", () => {
  it("flags Eloquent's User::find($id) with no ownership check nearby", () => {
    const content = `
<?php
$id = $_GET['id'];
$user = User::find($id);
?>
`;
    const result = analyzeFile("app/Http/Controllers/UserController.php", content);
    const finding = result.indicators.find(i => i.id === "idor");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  it("does not flag when an Auth::/Gate:: check is present nearby", () => {
    const content = `
<?php
$id = $_GET['id'];
if (!Auth::user()->can('view', $id)) { abort(403); }
$user = User::find($id);
?>
`;
    const result = analyzeFile("app/Http/Controllers/UserController_safe.php", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(false);
  });

  it("flags a PDO execute(['id' => $id]) lookup with no ownership check", () => {
    const content = `
<?php
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $id]);
?>
`;
    const result = analyzeFile("users/lookup.php", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(true);
  });
});

describe("PHP authz — missing session guard on a sensitive action (legacy/plain PHP)", () => {
  it("flags a DB write with no $_SESSION guard nearby", () => {
    const content = `
<?php
$id = $_GET['id'];
mysqli_query($conn, "DELETE FROM users WHERE id=$id");
?>
`;
    const result = analyzeFile("delete_user.php", content);
    const finding = result.indicators.find(i => i.id === "php-missing-session-guard");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  it("does not flag when a session guard is present before the sensitive action", () => {
    const content = `
<?php
if (!isset($_SESSION['user_id'])) { header('Location: /login'); exit; }
$id = $_GET['id'];
mysqli_query($conn, "DELETE FROM users WHERE id=$id");
?>
`;
    const result = analyzeFile("delete_user_safe.php", content);
    expect(result.indicators.some(i => i.id === "php-missing-session-guard")).toBe(false);
  });
});
