/**
 * @jest-environment node
 *
 * PHP cipher use: openssl_encrypt with ECB or a broken cipher (also when an earlier argument holds parentheses), an
 * unauthenticated mode with no MAC in the file, a fixed or empty IV, and repeating-key XOR. Each has a safe twin.
 */
import { analyzeFile } from "@/lib/scanner";

const fn = (body: string, extra = "") => `<?php\nfunction handler($req) {\n${body}\n}\n${extra}\n`;
const weak = (code: string) => analyzeFile("app/crypto.php", code).indicators.some(i => i.id === "weak-crypto");

describe("PHP weak cipher use", () => {
  it("ECB, DES, RC4 and Blowfish, also after an argument with parentheses", () => {
    expect(weak(fn(`    $enc = openssl_encrypt($req->param('data'), 'AES-128-ECB', $key);`))).toBe(true);
    expect(weak(fn(`    $enc = openssl_encrypt($req->param('data'), 'DES-CBC', $key, 0, random_bytes(8));`))).toBe(true);
    expect(weak(fn(`    $enc = openssl_encrypt($req->param('data'), 'RC4', $key);`))).toBe(true);
    expect(weak(fn(`    $enc = openssl_encrypt($req->param('data'), 'BF-CBC', $key, 0, $iv);`))).toBe(true);
  });
  it("CBC with a random IV but no MAC anywhere in the file; with hash_hmac it is fine, and GCM always is", () => {
    const cbc = `    $iv = random_bytes(16);\n    $enc = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);`;
    expect(weak(fn(cbc))).toBe(true);
    expect(weak(fn(`${cbc}\n    $mac = hash_hmac('sha256', $iv . $enc, $macKey);`))).toBe(false);
    expect(weak(fn(`    $iv = random_bytes(12);\n    $enc = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);`))).toBe(false);
  });
  it("a fixed, empty or zero IV, inline or assigned first", () => {
    const withMac = "\n    $mac = hash_hmac('sha256', $enc, $macKey);";
    expect(weak(fn(`    $iv = str_repeat("\\0", 16);\n    $enc = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);${withMac}`))).toBe(true);
    expect(weak(fn(`    $enc = openssl_encrypt($data, 'aes-256-cbc', $key, 0, '');${withMac}`))).toBe(true);
    expect(weak(fn(`    $iv = 'staticiv12345678';\n    $enc = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);${withMac}`))).toBe(true);
    expect(weak(fn(`    $iv = random_bytes(16);\n    $enc = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);${withMac}`))).toBe(false);
  });
  it("XOR with a repeating key; XOR of two hashes is not encryption", () => {
    expect(weak(fn(`    for ($i = 0; $i < strlen($data); $i++) {\n        $result .= $data[$i] ^ $key[$i % strlen($key)];\n    }`))).toBe(true);
    expect(weak(fn(`    $out = $data ^ str_repeat($key, strlen($data));`))).toBe(true);
    expect(weak(fn(`    $mixed = $a ^ $b;`))).toBe(false);
  });
});
