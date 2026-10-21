/**
 * The violation work queue (lib/violations.ts): real detection times and deadlines (every countdown used to be
 * "now minus a few hours"), files closed without review flagged as such, and "repos blocked from deploying" that
 * agrees with the GitHub check -- closing a violation doesn't unblock a merge.
 */
import { deriveViolations } from "@/lib/violations";
import type { DashboardData } from "@/types";

const file = (o: Record<string, unknown>) => ({ repo: "acme/api", ai_pct: 0.5, attested: false, scan_id: "s1", pr_number: 3, ...o });
const data = (files: Record<string, unknown>[]) => ({ repos: [], top_risk_files: files.map(file) } as unknown as DashboardData);

describe("deriveViolations", () => {
  it("uses the scan's time and the violation's recorded deadline", () => {
    const v = deriveViolations(data([
      { file_path: "a.ts", risk_score: "CRITICAL", detected_at: "2026-10-01T08:00:00.000Z", sla_deadline: "2026-10-01T20:00:00.000Z" },
      { file_path: "b.ts", risk_score: "HIGH", detected_at: "2026-10-01T08:00:00.000Z", sla_deadline: null },
    ]));
    // the recorded deadline wins over 24 h from detection (an org can set a shorter SLA)
    expect(v.find(x => x.file === "a.ts")).toMatchObject({ detected_at: "2026-10-01T08:00:00.000Z", sla_deadline: "2026-10-01T20:00:00.000Z" });
    // no deadline on record: 48 h from the real detection
    expect(v.find(x => x.file === "b.ts")).toMatchObject({ detected_at: "2026-10-01T08:00:00.000Z", sla_deadline: "2026-10-03T08:00:00.000Z" });
  });

  it("flags a file closed without review", () => {
    const v = deriveViolations(data([{ file_path: "a.ts", risk_score: "HIGH", resolved: true }, { file_path: "b.ts", risk_score: "HIGH" }, { file_path: "c.ts", risk_score: "CRITICAL", resolved: true }]));
    expect(v.filter(x => x.file).map(x => [x.file, !!x.closed_without_attestation])).toEqual([["c.ts", true], ["a.ts", true], ["b.ts", false]]);
  });

  it("a repo stays blocked while a file is unattested, closed or not -- like the GitHub check", () => {
    const blocked = (files: Record<string, unknown>[], statuses: Record<string, string> = {}) =>
      deriveViolations(data(files), statuses).find(x => x.type === "deploy_blocked");
    expect(blocked([{ file_path: "a.ts", risk_score: "HIGH", resolved: true }], { "high::s1::a.ts": "resolved" })).toBeDefined();
    expect(blocked([{ file_path: "a.ts", risk_score: "HIGH", attested: true }])).toBeUndefined();
    // its clock is the earliest blocking file's
    expect(blocked([
      { file_path: "a.ts", risk_score: "HIGH", detected_at: "2026-10-02T00:00:00.000Z", sla_deadline: "2026-10-04T00:00:00.000Z" },
      { file_path: "b.ts", risk_score: "CRITICAL", repo: "acme/web", detected_at: "2026-10-01T00:00:00.000Z", sla_deadline: "2026-10-01T12:00:00.000Z" },
    ])).toMatchObject({ title: "2 repos blocked from deploying", detected_at: "2026-10-01T00:00:00.000Z", sla_deadline: "2026-10-01T12:00:00.000Z" });
  });
});
