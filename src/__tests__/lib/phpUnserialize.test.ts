/**
 * @jest-environment node
 *
 * PHP unserialize(): request data is object injection, unless no arbitrary class can be built (allowed_classes false or
 * a list) or the payload's HMAC was checked first with a key that is a real secret (not one built from literals).
 */
import { analyzeFile } from "@/lib/scanner";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";

beforeAll(async () => { await warmPhpTaintEngine(); }, 120000);

const fn = (body: string) => `<?php\nfunction handler($req) {\n    $payload = $req->post('payload');\n${body}\n    return 'ok';\n}\n`;
const deser = (code: string) => analyzeFile("app/h.php", code).indicators.some(i => i.id === "insecure-deserialization");
const signed = (key: string) => fn(`${key}    $sig = $req->post('sig');\n    $expected = hash_hmac('sha256', $payload, $key);\n    if (!hash_equals($expected, $sig)) {\n        return 'bad';\n    }\n    $obj = unserialize($payload);`);

describe("PHP unserialize", () => {
  it("request data into unserialize is object injection", () => {
    expect(deser(fn(`    $obj = unserialize($payload);`))).toBe(true);
    expect(deser(fn(`    $obj = unserialize($payload, ['allowed_classes' => true]);`))).toBe(true);
  });
  it("allowed_classes false or an explicit list is not", () => {
    expect(deser(fn(`    $obj = unserialize($payload, ['allowed_classes' => false]);`))).toBe(false);
    expect(deser(fn(`    $obj = unserialize($payload, ['allowed_classes' => [SafeDto::class]]);`))).toBe(false);
  });
  it("an HMAC checked first clears it, unless its key is built from literals", () => {
    expect(deser(signed(`    $key = getenv('HMAC_SECRET');\n`))).toBe(false);
    expect(deser(signed(`    $key = 'changeme123';\n`))).toBe(true);
    expect(deser(signed(`    $salt = 'changeme123';\n    $key = md5($salt);\n`))).toBe(true);
    // computed but never compared: proves nothing
    expect(deser(fn(`    $key = getenv('HMAC_SECRET');\n    $expected = hash_hmac('sha256', $payload, $key);\n    $obj = unserialize($payload);`))).toBe(true);
  });
});
