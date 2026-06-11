import fs from "fs";
import path from "path";
import { runScan } from "@/lib/scanner";

const ROOT = path.resolve(__dirname, "../../..");

describe("scanner self-scan — false positive regression", () => {
  it("finds no critical/high security indicators in scanner.ts's own source", () => {
    const file = "src/lib/scanner.ts";
    const content = fs.readFileSync(path.join(ROOT, file), "utf-8");
    const result = runScan({
      repo: "bigrepo/test", pr_number: 1, commit_sha: "abc1234", branch: "main",
      files: [{ path: file, content }],
    });
    const lines = content.split("\n");
    const flagged = result.files[0].indicators.filter(
      ind => ind.severity === "critical" || ind.severity === "high",
    );
    if (flagged.length > 0) {
      const detail = flagged.map(ind => {
        const lineNo = (ind as { line?: number }).line;
        const snippet = lineNo ? lines[lineNo - 1]?.trim().slice(0, 140) : "(no line)";
        return `  [${ind.severity}] ${ind.id} L${lineNo}: ${ind.detail}\n      >> ${snippet}`;
      }).join("\n");
      throw new Error(`Unexpected security findings on scanner.ts's own source:\n${detail}`);
    }
  });
});
