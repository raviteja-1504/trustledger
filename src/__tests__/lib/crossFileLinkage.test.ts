/**
 * The cross-file "exposure" warning is tied to the symbol the importer uses. A module can hold a vulnerable function and
 * safe ones; importing a safe one must not read as importing the vulnerable one.
 */
import { runScan } from "@/lib/scanner";

const helper = `
export function lookupUser(db, req) {
  const id = req.params.id;
  const result = db.query(\`SELECT * FROM users WHERE id=\${id}\`);
  return result;
}

export function add(x, y) {
  const total = x + y;
  return total;
}
`.trim();

const consumerOf = (symbol: string) => `
import { ${symbol} } from "./helper";

export function handler(a, b) {
  return ${symbol}(a, b);
}
`.trim();

const exposures = (symbol: string) => {
  const r = runScan({ repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main", files: [{ path: "src/helper.ts", content: helper }, { path: "src/consumer.ts", content: consumerOf(symbol) }] });
  return r.files.find(f => f.file_path === "src/consumer.ts")!.indicators.filter(i => i.id === "cross-file-taint-exposure");
};

describe("cross-file taint exposure is tied to the imported symbol", () => {
  it("importing the vulnerable function is a medium-severity warning that names the path", () => {
    const e = exposures("lookupUser");
    expect(e).toHaveLength(1);
    expect(e[0].severity).toBe("medium");
    expect(e[0].detail).toContain('Imports "lookupUser" from src/helper.ts, whose code has an unresolved');
  });

  it("importing a SAFE function from the same module is only a low note that says it is not shown to be involved", () => {
    const e = exposures("add");
    expect(e).toHaveLength(1);
    expect(e[0].severity).toBe("low");
    expect(e[0].detail).toContain("add is not shown to be involved");
    expect(e[0].detail).toContain("a note, not a finding about this import");
  });

  it("a module with no taint path produces nothing for either symbol", () => {
    const clean = `export function add(x, y) {\n  const total = x + y;\n  return total;\n}\n\nexport function sub(x, y) {\n  const d = x - y;\n  return d;\n}`;
    const r = runScan({ repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main", files: [{ path: "src/helper.ts", content: clean }, { path: "src/consumer.ts", content: consumerOf("add") }] });
    expect(r.files.every(f => f.indicators.every(i => i.id !== "cross-file-taint-exposure"))).toBe(true);
  });
});
