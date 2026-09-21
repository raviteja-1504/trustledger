import { warmPhpTaintEngine, parsePhpSourceSync, scanAstTaintPHP } from "@/lib/astTaintPHP";

beforeAll(async () => { await warmPhpTaintEngine(); }, 30000);

function scan(content: string) {
  const root = parsePhpSourceSync(content, "a.php");
  if (!root) throw new Error("parse failed");
  return scanAstTaintPHP(content, "a.php", root);
}

describe("astTaintPHP.scanAstTaintPHP", () => {
  it("returns [] and never throws on empty input", () => {
    expect(scan("<?php\n")).toEqual([]);
  });

  it("returns [] and never throws on syntactically broken input", () => {
    const root = parsePhpSourceSync("<?php\nfunction {{{ not php", "x.php");
    if (root) expect(() => scanAstTaintPHP("<?php\nfunction {{{ not php", "x.php", root)).not.toThrow();
  });

  describe("sql-injection", () => {
    it("flags mysqli_query with a tainted, concatenated query string", () => {
      const content = `<?php
function handle() {
  $name = $_GET['name'];
  $sql = "SELECT * FROM users WHERE name = '" . $name . "'";
  mysqli_query($conn, $sql);
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(true);
    });

    it("flags a ->query() method call with a tainted interpolated string", () => {
      const content = `<?php
function handle() {
  $id = $_GET['id'];
  $sql = "SELECT * FROM users WHERE id = $id";
  $db->query($sql);
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(true);
    });

    it("does not flag a query with no tainted input", () => {
      const content = `<?php
function handle() {
  $sql = "SELECT * FROM users";
  mysqli_query($conn, $sql);
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(false);
    });
  });

  describe("command-injection", () => {
    it("flags shell_exec with tainted input", () => {
      const content = `<?php
function handle() {
  $host = $_GET['host'];
  shell_exec("ping " . $host);
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
    });

    it("does not flag shell_exec with only a fixed string", () => {
      const content = `<?php
function cleanup() {
  shell_exec("rm -rf /tmp/cache");
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(false);
    });
  });

  describe("xss", () => {
    it("flags echo of tainted, unsanitized input", () => {
      const content = `<?php
function handle() {
  $name = $_GET['name'];
  echo $name;
}`;
      expect(scan(content).some(f => f.id === "xss")).toBe(true);
    });
  });

  describe("insecure-deserialization", () => {
    it("flags unserialize with tainted input", () => {
      const content = `<?php
function handle() {
  $data = $_COOKIE['data'];
  unserialize($data);
}`;
      expect(scan(content).some(f => f.id === "insecure-deserialization")).toBe(true);
    });
  });

  describe("file-inclusion", () => {
    it("flags include with a tainted path", () => {
      const content = `<?php
function handle() {
  $page = $_GET['page'];
  include $page;
}`;
      expect(scan(content).some(f => f.id === "file-inclusion")).toBe(true);
    });

    it("does not flag include with a fixed path", () => {
      const content = `<?php
function handle() {
  include "header.php";
}`;
      expect(scan(content).some(f => f.id === "file-inclusion")).toBe(false);
    });
  });

  describe("path-traversal", () => {
    it("flags file_get_contents with a tainted path", () => {
      const content = `<?php
function handle() {
  $file = $_GET['file'];
  file_get_contents($file);
}`;
      expect(scan(content).some(f => f.id === "path-traversal")).toBe(true);
    });
  });

  describe("ssrf", () => {
    it("flags curl_setopt(CURLOPT_URL, ...) with a tainted URL", () => {
      const content = `<?php
function handle() {
  $url = $_GET['url'];
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $url);
}`;
      expect(scan(content).some(f => f.id === "ssrf")).toBe(true);
    });
  });

  describe("same-file interprocedural call binding", () => {
    it("propagates taint through a local helper's return value to the call site", () => {
      const content = `<?php
function buildQuery($id) {
  return "SELECT * FROM users WHERE id = " . $id;
}
function handle() {
  $id = $_GET['id'];
  mysqli_query($conn, buildQuery($id));
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(true);
    });

    it("does not propagate taint through a helper whose return never depends on its parameters", () => {
      const content = `<?php
function tableName($id) {
  return "users";
}
function handle() {
  $id = $_GET['id'];
  mysqli_query($conn, tableName($id));
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(false);
    });

    it("catches a sink call inside a local function's own body (not just its return)", () => {
      const content = `<?php
function logAndRun($cmd) {
  shell_exec($cmd);
}
function handle() {
  $userCmd = $_GET['cmd'];
  logAndRun($userCmd);
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
    });
  });

  describe("field-sensitive taint tracking (new capability)", () => {
    it("flags a sink using a field that was itself assigned a tainted value", () => {
      const content = `<?php
function handle() {
  $name = $_GET['name'];
  $user = new User();
  $user->name = $name;
  mysqli_query($conn, "SELECT * FROM t WHERE x = '" . $user->name . "'");
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(true);
    });

    it("does not flag a sibling field never assigned taint", () => {
      const content = `<?php
function handle() {
  $name = $_GET['name'];
  $user = new User();
  $user->name = $name;
  mysqli_query($conn, "SELECT * FROM t WHERE x = '" . $user->email . "'");
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(false);
    });
  });

  describe("sanitizer recognition (new capability)", () => {
    it("does not flag a value sanitized via htmlspecialchars before reaching echo", () => {
      const content = `<?php
function handle() {
  $name = $_GET['name'];
  $clean = htmlspecialchars($name);
  echo $clean;
}`;
      expect(scan(content).some(f => f.id === "xss")).toBe(false);
    });

    it("still flags an unsanitized value reaching the same sink", () => {
      const content = `<?php
function handle() {
  $name = $_GET['name'];
  echo $name;
}`;
      expect(scan(content).some(f => f.id === "xss")).toBe(true);
    });
  });

  describe("bounded interprocedural propagation (MAX_PROPAGATION_ROUNDS = 3)", () => {
    const chain = `
function levelA($x) { return levelB($x); }
function levelB($x) { return levelC($x); }
function levelC($x) { return levelD($x); }
function levelD($x) { return $x; }`;

    it("resolves a chain called at its base case", () => {
      const content = `<?php${chain}
function handle() {
  $input = $_GET['input'];
  shell_exec(levelD($input));
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
    });

    it("resolves levelB, 2 hops deep, within the cap", () => {
      const content = `<?php${chain}
function handle() {
  $input = $_GET['input'];
  shell_exec(levelB($input));
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
    });

    it("does NOT resolve levelA, the outermost 3-hop caller, proving the round cap is real", () => {
      const content = `<?php${chain}
function handle() {
  $input = $_GET['input'];
  shell_exec(levelA($input));
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(false);
    });
  });
});

describe("BOLA (Broken Object Level Authorization) — PHP resource-identifier ownership check", () => {
  function scan(content: string) {
    const root = parsePhpSourceSync(content, "a.php");
    if (!root) throw new Error("parse failed");
    return scanAstTaintPHP(content, "a.php", root);
  }

  it("flags a read function with no ownership check reaching a DB lookup", () => {
    const content = `<?php
function getUser($id) {
  $user = User::find($id);
  return $user;
}`;
    const bola = scan(content).filter(f => f.id === "bola-missing-ownership-check");
    expect(bola.some(f => f.severityOverride === "medium")).toBe(true);
  });

  it("flags a write function at high severity", () => {
    const content = `<?php
function deleteUser($id) {
  User::where('id', $id)->delete();
}`;
    const bola = scan(content).filter(f => f.id === "bola-missing-ownership-check");
    expect(bola.some(f => f.severityOverride === "high")).toBe(true);
  });

  it("does not flag when a real ownership comparison is present in the function body", () => {
    const content = `<?php
function getUser($id) {
  if ($id != $_SESSION['user_id']) {
    return null;
  }
  return User::find($id);
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  it("suppresses when an Auth::check()-style call is present in the function body", () => {
    const content = `<?php
function deleteUser($id) {
  Auth::check();
  User::where('id', $id)->delete();
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  it("does not flag a function with no resource-id-shaped parameter", () => {
    const content = `<?php
function listUsers() {
  return User::all();
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  it("flags new ClassName($id) constructor-sink shape", () => {
    const content = `<?php
function getProfile($id) {
  $profile = new UserProfile($id);
  return $profile;
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(true);
  });

  it("never throws on a malformed PHP snippet", () => {
    const content = `<?php
function getUser($id) {
  return null;
`;
    const root = parsePhpSourceSync(content, "a.php");
    if (root) expect(() => scanAstTaintPHP(content, "a.php", root)).not.toThrow();
  });
});

describe("open redirect + header injection via header(...)", () => {
  it("flags header('Location: ' . $tainted) as open-redirect", () => {
    const content = `<?php
$next = $_GET['next'];
header("Location: " . $next);
exit;`;
    expect(scan(content).some(f => f.id === "open-redirect")).toBe(true);
  });

  it("flags header('X-Anything: ' . $tainted) as header-injection, not open-redirect", () => {
    const content = `<?php
$email = $_GET['email'];
header("X-User-Email: " . $email);`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "header-injection")).toBe(true);
    expect(findings.some(f => f.id === "open-redirect")).toBe(false);
  });
});

describe("LDAP injection via ldap_search(...)", () => {
  it("flags a tainted filter (3rd positional arg)", () => {
    const content = `<?php
$ldapUser = $_GET['username'];
$filter = "(uid=" . $ldapUser . ")";
$ldap = ldap_connect("ldap://localhost");
ldap_search($ldap, "dc=example,dc=com", $filter);`;
    expect(scan(content).some(f => f.id === "ldap-injection")).toBe(true);
  });
});

describe("NoSQL injection via array-driver-style calls", () => {
  it("flags a tainted array literal passed to ->findOne(...)", () => {
    const content = `<?php
$mongoUser = $_POST['username'];
$mongoQuery = [
    "username" => $mongoUser,
    "password" => $_POST['password']
];
$collection->findOne($mongoQuery);`;
    expect(scan(content).some(f => f.id === "nosql-injection")).toBe(true);
  });
});

describe("XPath vs SQL injection discrimination", () => {
  it("flags $xpath->query(...) as xpath-injection when $xpath is a real DOMXPath", () => {
    const content = `<?php
$xpathUser = $_GET['user'];
$xpathQuery = "//user[name='" . $xpathUser . "']";
$xmlDoc = new DOMDocument();
$xmlDoc->load("users.xml");
$xpath = new DOMXPath($xmlDoc);
$result = $xpath->query($xpathQuery);`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "xpath-injection")).toBe(true);
    expect(findings.some(f => f.id === "sql-injection")).toBe(false);
  });

  it("still flags a real DB driver's ->query(...) as sql-injection", () => {
    const content = `<?php
$id = $_GET['id'];
$conn = new mysqli("localhost", "root", "pw", "db");
$sql = "SELECT * FROM users WHERE id = '$id'";
$result = $conn->query($sql);`;
    expect(scan(content).some(f => f.id === "sql-injection")).toBe(true);
  });
});

describe("BOLA -- top-level script code, broadened resource-id names, and SQL-sink one-hop resolution", () => {
  it("flags an unguarded top-level raw-SQL lookup keyed on a superglobal-sourced *Id-suffixed variable", () => {
    const content = `<?php
$accountId = $_GET['account_id'];
$sql = "SELECT * FROM accounts WHERE id = '$accountId'";
$account = $conn->query($sql);`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(true);
  });

  it("one-hop lookback uses the assignment PRECEDING the call, not the file's last assignment to the same variable", () => {
    // $sql is reassigned later using $accountId; the earlier query() call
    // sees only the first assignment, which uses no resource-id variable.
    const content = `<?php
$accountId = $_GET['account_id'];
$sql = "SELECT 1 FROM config";
$conn->query($sql);
$sql = "SELECT * FROM accounts WHERE id = '$accountId'";
$conn->query($sql);`;
    const bola = scan(content).filter(f => f.id === "bola-missing-ownership-check");
    expect(bola.length).toBe(1);
    expect(bola[0].line).toBe(6);
  });

  it("does not flag top-level code with no resource-id-shaped superglobal variable", () => {
    const content = `<?php
$name = $_GET['name'];
echo "<h1>Hello " . $name . "</h1>";`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  it("still flags a function-scoped BOLA case using a camelCase *Id param name (accountId, not just id)", () => {
    const content = `<?php
function getAccount($accountId) {
  $sql = "SELECT * FROM accounts WHERE id = '$accountId'";
  return $conn->query($sql);
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(true);
  });
});

describe("collectLocalFunctions -- same-named function in a different scope no longer silently overwrites the real one", () => {
  it("first-declared-wins: a same-named class method declared later doesn't erase the real top-level function's BOLA finding", () => {
    const content = `<?php
function getUser($id) {
  $sql = "SELECT * FROM users WHERE id = '$id'";
  return $conn->query($sql);
}
class Database {
  public function getUser($x) {
    return null;
  }
}`;
    // Without the fix, collectLocalFunctions' flat overwrite would leave
    // the map's "getUser" entry pointing at Database::getUser's real-but-
    // empty body (declared later in the file), silently losing the top-
    // level getUser()'s own body -- and with it, this finding.
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(true);
  });
});
