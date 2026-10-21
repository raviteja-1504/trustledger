/**
 * Assigning reviewers on the violations page: an assignment follows the file to a newer push (lib/violationStatuses
 * assigneeFor), only people who can attest the file's risk are offered (canAttestSeverity / memberPermissions), and
 * a file incident knows its pull request (lib/incidentLinks) -- as does "repos blocked from deploying".
 */
import { assigneeFor, canAttestSeverity, type ServerOverride } from "@/lib/violationStatuses";
import { memberPermissions, NO_PERMISSIONS } from "@/lib/permissions";
import { latestScanPerFile, fileKey } from "@/lib/incidentLinks";
import { deriveViolations } from "@/lib/violations";
import type { DashboardData } from "@/types";

describe("assigneeFor", () => {
  const o: Record<string, ServerOverride> = {
    "crit::s1::src/auth.ts": { status: "open", assigned_email: "old@a.io", updated_at: "2026-10-01T00:00:00Z", repo: "acme/api" },
    "crit::s2::src/auth.ts": { status: "open", assigned_email: "rev@a.io", updated_at: "2026-10-02T00:00:00Z", repo: "acme/api" },
    // the same path in another repository is another file
    "crit::s9::src/auth.ts": { status: "open", assigned_email: "web@a.io", updated_at: "2026-10-05T00:00:00Z", repo: "acme/web" },
    // a status-only override on the new push carries no assignee of its own
    "crit::s3::src/auth.ts": { status: "in_review", assigned_email: null, updated_at: "2026-10-06T00:00:00Z", repo: "acme/api" },
  };

  it("a violation's own assignee wins", () => {
    expect(assigneeFor("crit::s1::src/auth.ts", "acme/api", "src/auth.ts", o)).toEqual({ email: "old@a.io", from: "crit::s1::src/auth.ts" });
  });

  it("a newer push of the file keeps the newest assignee from the same repository, and says where it came from", () => {
    expect(assigneeFor("crit::s3::src/auth.ts", "acme/api", "src/auth.ts", o)).toEqual({ email: "rev@a.io", from: "crit::s2::src/auth.ts" });
    expect(assigneeFor("crit::s4::src/auth.ts", "acme/web", "src/auth.ts", o)).toEqual({ email: "web@a.io", from: "crit::s9::src/auth.ts" });
  });

  it("another file, or a violation with no file, carries nothing", () => {
    expect(assigneeFor("crit::s3::src/db.ts", "acme/api", "src/db.ts", o)).toBeNull();
    expect(assigneeFor("deploy::blocked", undefined, undefined, o)).toBeNull();
  });
});

describe("who can be assigned", () => {
  const reviewer = { email: "r@a.io", name: null, can_attest: { critical: true, high: true, medium: true } };
  const junior = { email: "j@a.io", name: null, can_attest: { critical: false, high: true, medium: true } };
  const dev = { email: "d@a.io", name: null, can_attest: { critical: false, high: false, medium: false } };

  it("only someone whose role may attest the file's risk", () => {
    expect([reviewer, junior, dev].filter(m => canAttestSeverity(m, "CRITICAL")).map(m => m.email)).toEqual(["r@a.io"]);
    expect([reviewer, junior, dev].filter(m => canAttestSeverity(m, "HIGH")).map(m => m.email)).toEqual(["r@a.io", "j@a.io"]);
    expect([reviewer, junior, dev].filter(m => canAttestSeverity(m, "MEDIUM")).map(m => m.email)).toEqual(["r@a.io", "j@a.io"]);
    // HIGH and MEDIUM are separate permissions
    const highOnly = { email: "h@a.io", name: null, can_attest: { critical: false, high: true, medium: false } };
    expect([canAttestSeverity(highOnly, "HIGH"), canAttestSeverity(highOnly, "MEDIUM")]).toEqual([true, false]);
  });

  it("anyone for a repo-level violation, and anyone listed without permissions (older API)", () => {
    expect(canAttestSeverity(dev, null)).toBe(true);
    expect(canAttestSeverity({ email: "x@a.io", name: null }, "CRITICAL")).toBe(true);
  });

  it("a member's permissions: custom role replaces the built-in one; an unreadable one grants nothing", () => {
    expect(memberPermissions("security_reviewer", null, null).can_attest_critical).toBe(true);
    expect(memberPermissions("developer", null, null).can_attest_high).toBe(false);
    expect(memberPermissions("security_reviewer", "cr1", { can_attest_high: true }).can_attest_critical).toBe(false);
    expect(memberPermissions("developer", "cr1", { can_attest_high: true }).can_attest_high).toBe(true);
    expect(memberPermissions("admin", "cr-missing", undefined)).toEqual(NO_PERMISSIONS);
  });
});

describe("the pull request behind an incident or a blocked repo", () => {
  it("an incident's file: the newest scan of its repository containing it", () => {
    const scans = [
      { id: "s1", repo_full_name: "acme/api", pr_number: 4, created_at: "2026-10-01T00:00:00Z" },
      { id: "s2", repo_full_name: "acme/api", pr_number: 5, created_at: "2026-10-03T00:00:00Z" },
      { id: "s3", repo_full_name: "acme/api", pr_number: 6, created_at: "2026-10-04T00:00:00Z" },
      { id: "w1", repo_full_name: "acme/web", pr_number: 9, created_at: "2026-10-09T00:00:00Z" },
    ];
    const files = [
      { scan_id: "s1", file_path: "auth.ts" }, { scan_id: "s2", file_path: "auth.ts" },
      { scan_id: "s3", file_path: "db.ts" }, { scan_id: "w1", file_path: "auth.ts" },
      // a file of a scan that wasn't loaded (outside the newest scans read): ignored
      { scan_id: "gone", file_path: "auth.ts" },
    ];
    const m = latestScanPerFile(scans, files);
    // s3 is newer but doesn't contain auth.ts; w1 has auth.ts but in another repo
    expect(m.get(fileKey("acme/api", "auth.ts"))).toEqual({ scan_id: "s2", pr_number: 5 });
    expect(m.get(fileKey("acme/web", "auth.ts"))).toEqual({ scan_id: "w1", pr_number: 9 });
    expect(m.get(fileKey("acme/api", "db.ts"))).toEqual({ scan_id: "s3", pr_number: 6 });
  });

  it("'repos blocked from deploying' lists each blocked pull request once", () => {
    const data = { repos: [], top_risk_files: [
      { repo: "acme/api", file_path: "a.ts", risk_score: "CRITICAL", attested: false, scan_id: "s2", pr_number: 5, ai_pct: 0 },
      { repo: "acme/api", file_path: "b.ts", risk_score: "HIGH", attested: false, scan_id: "s2", pr_number: 5, ai_pct: 0 },
      { repo: "acme/web", file_path: "c.ts", risk_score: "HIGH", attested: false, scan_id: "w1", pr_number: 9, ai_pct: 0 },
      { repo: "acme/ops", file_path: "d.ts", risk_score: "HIGH", attested: true, scan_id: "o1", pr_number: 2, ai_pct: 0 },
    ] } as unknown as DashboardData;
    expect(deriveViolations(data).find(v => v.type === "deploy_blocked")?.prs).toEqual([
      { repo: "acme/api", scan_id: "s2", pr_number: 5 }, { repo: "acme/web", scan_id: "w1", pr_number: 9 },
    ]);
  });
});
