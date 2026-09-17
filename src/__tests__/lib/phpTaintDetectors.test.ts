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
