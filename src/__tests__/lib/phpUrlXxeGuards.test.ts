/**
 * @jest-environment node
 *
 * PHP: relative-URL checks (str_starts_with / strpos === 0 / str_contains '://') before a Location header, a resolved
 * host rejected when private or reserved before a request, and XXE judged by libxml's real opt-ins (LIBXML_NOENT,
 * LIBXML_DTDLOAD without LIBXML_NONET, substituteEntities, re-enabled entity loader). Each has a twin that reports.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";

beforeAll(async () => { await warmPhpTaintEngine(); }, 120000);

const fn = (body: string) => `<?php\nfunction handler() {\n    $url = $_GET['url'];\n${body}\n}\n`;
const has = (code: string, id: string) => analyzeFile("src/handler.php", code).indicators.some(i => i.id === id && !!i.sourceExpr);
const xxe = (code: string) => analyzeFile("src/handler.php", code).indicators.some(i => i.id === "xxe");

describe("redirects", () => {
  it("an early return unless it starts with '/' and not '//' (strpos form); one half alone still reports", () => {
    expect(has(fn(`    if (strpos($url, '/') !== 0 || strpos($url, '//') === 0) {\n        return;\n    }\n    header('Location: ' . $url);`), "open-redirect")).toBe(false);
    expect(has(fn(`    if (strpos($url, '/') !== 0) {\n        return;\n    }\n    header('Location: ' . $url);`), "open-redirect")).toBe(true);
  });
  it("str_contains '://' or str_starts_with '//' rejected first; only one of them still reports", () => {
    expect(has(fn(`    if (str_contains($url, '://') || str_starts_with($url, '//')) {\n        return;\n    }\n    header('Location: ' . $url);`), "open-redirect")).toBe(false);
    expect(has(fn(`    if (str_contains($url, '://')) {\n        return;\n    }\n    header('Location: ' . $url);`), "open-redirect")).toBe(true);
  });
  it("both halves in one && condition around the redirect; the strpos '://' form of the early return", () => {
    expect(has(fn(`    if (str_starts_with($url, '/') && !str_starts_with($url, '//')) {\n        header('Location: ' . $url);\n    }`), "open-redirect")).toBe(false);
    expect(has(fn(`    if (str_starts_with($url, '/') && strlen($url) > 1) {\n        header('Location: ' . $url);\n    }`), "open-redirect")).toBe(true);
    expect(has(fn(`    if (strpos($url, '://') !== false || str_starts_with($url, '//')) {\n        return;\n    }\n    header('Location: ' . $url);`), "open-redirect")).toBe(false);
    expect(has(fn(`    if (strpos($url, '://') === false || str_starts_with($url, '//')) {\n        return;\n    }\n    header('Location: ' . $url);`), "open-redirect")).toBe(true);
  });
  it("a literal https://host/ prefix", () => {
    expect(has(fn(`    if (str_starts_with($url, 'https://example.com/')) {\n        header('Location: ' . $url);\n    }`), "open-redirect")).toBe(false);
    expect(has(fn(`    if (str_starts_with($url, 'https://example.com')) {\n        header('Location: ' . $url);\n    }`), "open-redirect")).toBe(true);
  });
});

describe("SSRF", () => {
  const resolved = (flags: string) => fn(`    $host = parse_url($url, PHP_URL_HOST);\n    $ip = gethostbyname($host);\n    if (filter_var($ip, FILTER_VALIDATE_IP, ${flags}) === false) {\n        return;\n    }\n    $content = file_get_contents($url);\n    echo htmlspecialchars($content);`);
  it("the resolved host rejected when private or reserved; only one of the two flags still reports", () => {
    expect(has(resolved("FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE"), "ssrf")).toBe(false);
    expect(has(resolved("FILTER_FLAG_NO_PRIV_RANGE"), "ssrf")).toBe(true);
  });
  it("an https-only scheme check is no SSRF defence", () => {
    expect(has(fn(`    if (parse_url($url, PHP_URL_SCHEME) !== 'https') {\n        return;\n    }\n    $content = file_get_contents($url);\n    echo htmlspecialchars($content);`), "ssrf")).toBe(true);
  });
});

describe("XXE by libxml's opt-ins", () => {
  const x = (stmt: string) => `<?php\nfunction parse() {\n    $xml = file_get_contents('php://input');\n    $doc = new DOMDocument();\n    ${stmt}\n    return $doc;\n}\n`;
  it("LIBXML_NOENT substitutes entities even with LIBXML_NONET; DTDLOAD without NONET fetches", () => {
    expect(xxe(x(`$doc->loadXML($xml, LIBXML_NOENT | LIBXML_NONET);`))).toBe(true);
    expect(xxe(x(`$doc->loadXML($xml, LIBXML_DTDLOAD);`))).toBe(true);
    expect(xxe(x(`$doc->substituteEntities = true;\n    $doc->loadXML($xml);`))).toBe(true);
    expect(xxe(x(`libxml_disable_entity_loader(false);\n    $doc->loadXML($xml);`))).toBe(true);
  });
  it("LIBXML_DTDLOAD confined by LIBXML_NONET, and no flags at all, are not", () => {
    expect(xxe(x(`$doc->loadXML($xml, LIBXML_NONET | LIBXML_DTDLOAD);`))).toBe(false);
    expect(xxe(x(`$doc->loadXML($xml);`))).toBe(false);
  });
});
