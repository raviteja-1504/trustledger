/**
 * Scanner integrity: the trust chain is canonical, and security risk is reported on its own, apart from the AI score.
 */
import crypto from "crypto";
import { buildTrustChain, runScan, calculateRisk, type FileAnalysis } from "@/lib/scanner";

const f = (file_path: string, content_hash: string) => ({ file_path, content_hash }) as unknown as FileAnalysis;

describe("trust chain", () => {
  const files = [f("src/b.ts", "hb"), f("src/a.ts", "ha"), f("src/c.ts", "hc")];

  it("is the same whatever order the files were analysed in", () => {
    const a = buildTrustChain(files, "scan-1");
    const b = buildTrustChain([...files].reverse(), "scan-1");
    expect(b.chain_hash).toBe(a.chain_hash);
    expect(a.file_hashes.map(x => x.path)).toEqual(["src/a.ts", "src/b.ts", "src/c.ts"]);
  });

  it("changes when any file's contents, any path, or the set of files changes", () => {
    const base = buildTrustChain(files, "s").chain_hash;
    expect(buildTrustChain([f("src/b.ts", "hb"), f("src/a.ts", "CHANGED"), f("src/c.ts", "hc")], "s").chain_hash).not.toBe(base);
    expect(buildTrustChain([f("src/b.ts", "hb"), f("src/a2.ts", "ha"), f("src/c.ts", "hc")], "s").chain_hash).not.toBe(base);
    expect(buildTrustChain(files.slice(1), "s").chain_hash).not.toBe(base);
  });

  it("a separator inside a path or hash cannot be moved between fields to forge the same chain", () => {
    expect(buildTrustChain([f("a::b", "c")], "s").chain_hash).not.toBe(buildTrustChain([f("a", "b::c")], "s").chain_hash);
  });

  it("the seal depends on the scan id; the file chain does not", () => {
    const x = buildTrustChain(files, "scan-1"), y = buildTrustChain(files, "scan-2");
    expect(x.chain_hash).toBe(y.chain_hash);
    expect(x.scan_seal).not.toBe(y.scan_seal);
  });

  it("is a plain hash with no secret: it is an integrity commitment that anyone can recompute", () => {
    const t = buildTrustChain([f("a.ts", "h")], "s");
    const genesis = crypto.createHash("sha256").update("TrustLedger::GENESIS").digest("hex");
    expect(t.genesis_hash).toBe(genesis);
    expect(t.chain_hash).toBe(crypto.createHash("sha256").update(JSON.stringify([genesis, "a.ts", "h"])).digest("hex"));
  });
});

describe("security risk is separate from the AI score", () => {
  const scan = (path: string, content: string) =>
    runScan({ repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main", files: [{ path, content }] });

  it("calculateRisk still raises risk for AI-looking code (the governance gate), but security_risk does not", () => {
    expect(calculateRisk([], 0.9)).toBe("HIGH");           // unchanged: AI-heavy files need a human sign-off
    const aiOnly = Array.from({ length: 6 }, () => `
/**
 * Validates the user input and returns a structured result.
 * @param input - The input to validate
 * @returns The validation result
 */
export async function validateUserInput${Math.random().toString(36).slice(2, 6)}(input: UserInput): Promise<ValidationResult> {
  // Validate the input data before processing
  if (!input) {
    throw new Error("Input is required");
  }
  const result = await processUserData(input);
  return { success: true, data: result };
}`).join("\n");
    const r = scan("src/a.ts", `// Here is the implementation of the handler. Certainly! This function will validate the input.\n${aiOnly}`);
    expect(r.files[0].security_risk).toBe("LOW");
    expect(r.security_risk).toBe("LOW");
  });

  it("a human-written SQL injection is CRITICAL security risk whatever the AI score", () => {
    const code = `const db = require("./db");\n\nfunction find(req, res) {\n  const q = "SELECT * FROM users WHERE id = '" + req.query.id + "'";\n  db.query(q, (err, rows) => res.json(rows));\n}\n\nmodule.exports = { find };\n`;
    const r = scan("src/users.js", code);
    expect(r.files[0].ai_percentage).toBeLessThan(0.3);
    expect(r.files[0].security_risk).toBe("CRITICAL");
    expect(r.security_risk).toBe("CRITICAL");
  });

  it("the file's risk_score is never lower than its security_risk", () => {
    const order = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 } as const;
    for (const [p, c] of [["a.js", "eval(req.query.x)"], ["b.js", "const x = 1;\n".repeat(30)]] as const) {
      const f0 = scan(p, c).files[0];
      expect(order[f0.risk_score]).toBeGreaterThanOrEqual(order[f0.security_risk!]);
    }
  });
});
