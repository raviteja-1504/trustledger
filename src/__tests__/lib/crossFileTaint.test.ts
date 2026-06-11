import { runScan } from "@/lib/scanner";

describe("cross-file taint propagation", () => {
  it("flags a file that imports a tainted helper from another file", () => {
    const helper = `
export function lookupUser(db, req) {
  const id = req.params.id;
  const result = db.query(\`SELECT * FROM users WHERE id=\${id}\`);
  return result;
}
`.trim();

    const consumer = `
import { lookupUser } from "./helper";

export async function handler(db, req) {
  const user = lookupUser(db, req);
  return user;
}
`.trim();

    const result = runScan({
      repo: "test/cross-file", pr_number: 1, commit_sha: "abc1234", branch: "main",
      files: [
        { path: "src/helper.ts", content: helper },
        { path: "src/consumer.ts", content: consumer },
      ],
    });

    const consumerFile = result.files.find(f => f.file_path === "src/consumer.ts")!;
    const crossFileFindings = consumerFile.indicators.filter(i => i.id === "cross-file-taint-exposure");
    expect(crossFileFindings.length).toBeGreaterThan(0);
    expect(crossFileFindings[0].detail).toContain("src/helper.ts");
  });

  it("does not flag files with no cross-file taint", () => {
    const a = `export function add(x: number, y: number): number { return x + y; }`;
    const b = `
import { add } from "./a";
export function sum3(x: number, y: number, z: number): number {
  return add(add(x, y), z);
}
`.trim();

    const result = runScan({
      repo: "test/cross-file-clean", pr_number: 1, commit_sha: "abc1234", branch: "main",
      files: [
        { path: "src/a.ts", content: a },
        { path: "src/b.ts", content: b },
      ],
    });

    for (const f of result.files) {
      expect(f.indicators.some(i => i.id === "cross-file-taint-exposure")).toBe(false);
    }
  });
});
