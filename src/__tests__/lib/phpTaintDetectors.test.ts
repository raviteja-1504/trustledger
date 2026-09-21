import { analyzeFile } from "@/lib/scanner";

// Regex-layer (scanner.ts) detectors added while closing PHP-detector gaps
// surfaced by a real OWASP-style PHP benchmark file -- mirrors
// csharpTaintDetectors.test.ts's own analyzeFile()-based, end-to-end style.
// The AST-layer (astTaintPHP.ts) counterparts of the sink/BOLA decisions
// are already covered in astTaintPHP.test.ts -- this file covers the
// categories that are regex-only (weak-crypto, XXE constant, cookie
// security, PII-in-logs, debug/verbose-error, mass-assignment loop,
// weak-signing-secret).

describe("PHP weak-crypto (regex-only, no AST engine equivalent anywhere)", () => {
  it("flags md5($password)", () => {
    const content = `<?php
$password = $_POST['password'];
$hash = md5($password);
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "weak-crypto")).toBe(true);
  });

  it("flags sha1($password)", () => {
    const content = `<?php
$password = $_POST['password'];
$hash2 = sha1($password);
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "weak-crypto")).toBe(true);
  });
});

describe("PHP XXE via LIBXML_NOENT/LIBXML_DTDLOAD constants", () => {
  it("flags DOMDocument::loadXML with dangerous flags", () => {
    const content = `<?php
$xml = $_POST['xml'];
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "xxe")).toBe(true);
  });
});

describe("PHP cookie security via setcookie(...)", () => {
  it("flags a session cookie with no secure/httponly args at all (positional form)", () => {
    const content = `<?php
setcookie(
    "session",
    session_id()
);
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "cookie-no-httponly")).toBe(true);
  });

  it("flags a session cookie missing httponly in the PHP 7.3+ array-options form", () => {
    const content = `<?php
setcookie("session", session_id(), ['secure' => true]);
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "cookie-no-httponly")).toBe(true);
  });

  it("does not flag a session cookie with both flags true in the array-options form", () => {
    const content = `<?php
setcookie("session", session_id(), ['secure' => true, 'httponly' => true]);
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "cookie-no-httponly" || i.id === "cookie-no-secure")).toBe(false);
  });

  it("does not flag a non-auth-named cookie", () => {
    const content = `<?php
setcookie("theme", "dark");
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "cookie-no-httponly")).toBe(false);
  });
});

describe("PHP PII/secrets in logs via error_log(...)", () => {
  it("flags a password concatenated into error_log(...)", () => {
    const content = `<?php
$password = $_POST['password'];
error_log("User password: " . $password);
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "pii-in-logs")).toBe(true);
  });
});

describe("PHP debug/error disclosure", () => {
  it("flags ini_set('display_errors', '1')", () => {
    const content = `<?php
// Enable verbose error output for local debugging.
ini_set("display_errors", "1");
error_reporting(E_ALL);
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "debug-mode-enabled")).toBe(true);
  });

  it("flags a secret-named variable concatenated into a thrown exception message", () => {
    const content = `<?php
$dbPassword = "MyDatabasePassword123!";
throw new Exception("Database password: " . $dbPassword);
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "verbose-error")).toBe(true);
  });
});

describe("PHP mass assignment via dynamic property-write loop", () => {
  it("flags foreach ($data as $key => $value) { $obj->$key = $value; }", () => {
    const content = `<?php
$userData = $_POST;
$user = new User();
foreach ($userData as $key => $value) {
    $user->$key = $value;
}
$user->save();
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "mass-assignment")).toBe(true);
  });

  it("does not flag an ordinary foreach with no dynamic property write", () => {
    const content = `<?php
$items = $_POST['items'];
foreach ($items as $key => $value) {
    echo $key;
}
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "mass-assignment")).toBe(false);
  });
});

describe("PHP weak-signing-secret via hash_hmac(...) literal key", () => {
  it("flags a short literal key passed as hash_hmac's 3rd arg", () => {
    const content = `<?php
$jwt = hash_hmac("sha256", "payload", "secret");
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "weak-signing-secret")).toBe(true);
  });

  it("flags a multi-line hash_hmac call whose data arg is itself a nested call", () => {
    const content = `<?php
$jwt = base64_encode(
    json_encode($jwtPayload)
) . "." . hash_hmac(
    "sha256",
    json_encode($jwtPayload),
    "secret"
);
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.filter(i => i.id === "weak-signing-secret").length).toBe(1);
  });

  it("does not flag hash_hmac keyed by a variable", () => {
    const content = `<?php
$jwt = hash_hmac("sha256", "payload", $key);
// padding so the fixture clears analyzeFile's minimum-content guard
$other = 1;
`;
    const result = analyzeFile("a.php", content);
    expect(result.indicators.some(i => i.id === "weak-signing-secret")).toBe(false);
  });
});
