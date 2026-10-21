/**
 * Carried-over files on a delta scan (lib/inheritedViolations.ts): an unattested HIGH/CRITICAL file the push didn't
 * touch must still block the merge -- pushing an unrelated change used to turn the check green.
 */
import { inheritedViolations, type InheritedFile } from "@/lib/inheritedViolations";

const DEFAULT = "2026-10-23T00:00:00.000Z";
const stored = (f: InheritedFile) => f.risk_score;
const none = new Map<string, string>();

describe("inheritedViolations", () => {
  it("the bypass: an unattested HIGH file the push didn't change still blocks", () => {
    // push 1 found payments.ts HIGH; push 2 only edited utils.ts, so payments.ts is inherited
    const files = [{ file_path: "src/payments.ts", risk_score: "HIGH" }];
    expect(inheritedViolations(files, new Set(), stored, none, DEFAULT))
      .toEqual([{ file_path: "src/payments.ts", risk_score: "HIGH", sla_deadline: DEFAULT }]);
  });

  it("an attestation carried over, or a low-risk file, does not block", () => {
    const files = [
      { file_path: "a.ts", risk_score: "CRITICAL" },
      { file_path: "b.ts", risk_score: "MEDIUM" },
      { file_path: "c.ts", risk_score: "LOW" },
      { file_path: "d.ts", risk_score: "CRITICAL" },
    ];
    expect(inheritedViolations(files, new Set(["a.ts"]), stored, none, DEFAULT).map(v => [v.file_path, v.risk_score]))
      .toEqual([["d.ts", "CRITICAL"]]);
  });

  it("findings under an active triage decision don't count, the same rule the re-analysed files get", () => {
    const files = [{ file_path: "a.ts", risk_score: "HIGH" }, { file_path: "b.ts", risk_score: "CRITICAL" }];
    // every finding in a.ts was accepted as a risk, so its risk after triage is LOW; b.ts is down to HIGH
    const afterTriage = (f: InheritedFile) => f.file_path === "a.ts" ? "LOW" : "HIGH";
    // the row keeps the file's stored risk, like the re-analysed files' rows
    expect(inheritedViolations(files, new Set(), afterTriage, none, DEFAULT))
      .toEqual([{ file_path: "b.ts", risk_score: "CRITICAL", sla_deadline: DEFAULT }]);
  });

  it("keeps the deadline the file already had, so another push doesn't extend the SLA", () => {
    const files = [{ file_path: "a.ts", risk_score: "HIGH" }, { file_path: "b.ts", risk_score: "HIGH" }];
    const prior = new Map([["a.ts", "2026-10-21T09:00:00.000Z"]]);
    expect(inheritedViolations(files, new Set(), stored, prior, DEFAULT).map(v => v.sla_deadline))
      .toEqual(["2026-10-21T09:00:00.000Z", DEFAULT]);
  });
});
