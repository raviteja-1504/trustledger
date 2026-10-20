/**
 * Audit entries as the page shows them (lib/auditEvents.ts): their own labels and categories, facts from the
 * payload, links, and the stored hashes.
 */
import { auditMeta, describeAuditRow, sinceFor, typesByCategory, type AuditRow } from "@/lib/auditEvents";

const row = (event_type: string, payload: Record<string, unknown> = {}, o: Partial<AuditRow> = {}): AuditRow =>
  ({ id: 7, event_type, actor_email: "ada@acme.test", payload, created_at: "2026-10-20T10:00:00Z", entry_hash: "e".repeat(64), prev_hash: "p".repeat(64), ...o });

describe("describeAuditRow", () => {
  it("events keep their own meaning (no more 'incident' counted as 'merge blocked')", () => {
    expect(auditMeta("incident_created")).toMatchObject({ label: "Incident opened", category: "incidents", severity: "critical" });
    expect(auditMeta("user_login")).toMatchObject({ label: "Signed in", category: "access", severity: "info" });
    expect(auditMeta("report_generated")).toMatchObject({ label: "Report generated", category: "evidence", severity: "info" });
    expect(auditMeta("violation_resolved").category).toBe("findings");
    expect(auditMeta("brand_new_event")).toMatchObject({ label: "Brand new event", category: "settings" });
  });

  it("a scan: title, severity from its risk, facts, link to the scan", () => {
    const v = describeAuditRow(row("scan_complete", { repo: "o/api", pr_number: 7, commit_sha: "abcdef1234567", file_count: 12, overall_risk: "CRITICAL" }, { resource_type: "scan", resource_id: "s1" }));
    expect(v).toMatchObject({ title: "Scan completed for PR #7 — CRITICAL risk", severity: "critical", repo: "o/api", link: { href: "/pr/s1", label: "Open scan" } });
    expect(v.facts).toEqual(expect.arrayContaining([["Commit", "abcdef123"], ["Files", "12"], ["Risk", "CRITICAL"]]));
    expect(describeAuditRow(row("scan_complete", { overall_risk: "LOW" })).severity).toBe("info");
  });

  it("a sign-off, a status change, a sign-in, a role change", () => {
    expect(describeAuditRow(row("attestation", { file_path: "src/pay.ts", scan_id: "s2", risk_score: "HIGH" }))).toMatchObject({ title: "pay.ts signed off by ada@acme.test", link: { href: "/pr/s2" } });
    expect(describeAuditRow(row("violation_resolved", { status: "in_review", file_path: "a/b.ts" })).title).toBe("Finding marked in review — b.ts");
    const login = describeAuditRow(row("user_login", { method: "password", mfa: true }));
    expect(login).toMatchObject({ title: "ada@acme.test signed in", facts: [["Method", "password"], ["Two-factor", "yes"]] });
    expect(describeAuditRow(row("member_role_changed", { email: "bob@x", from: "developer", to: "admin" })).facts).toEqual([["From", "developer"], ["To", "admin"]]);
  });

  it("system entries have no actor; stored hashes are carried through; unknown types show their simple fields", () => {
    const v = describeAuditRow(row("risk_updated", { action: "auto_synced", closed: 2 }, { actor_email: "system" }));
    expect(v).toMatchObject({ actor: null, title: "Risk register auto synced", entry_hash: "e".repeat(64), prev_hash: "p".repeat(64) });
    const u = describeAuditRow(row("brand_new_event", { count: 3, nested: { x: 1 }, label: "x" }, { resource_type: "thing", resource_id: "42" }));
    expect(u.facts).toEqual([["Count", "3"], ["Label", "x"], ["Resource", "thing 42"]]);
  });

  it("repositories connected in bulk list the first few", () => {
    const v = describeAuditRow(row("repo_connected", { count: 7, source: "github_import", repos: ["a/1", "a/2", "a/3", "a/4", "a/5", "a/6", "a/7"] }));
    expect(v.title).toBe("7 repositories connected");
    expect(v.facts).toEqual([["Source", "github import"], ["Repositories", "a/1, a/2, a/3, a/4, a/5 +2 more"]]);
  });
});

describe("typesByCategory / sinceFor", () => {
  it("every known type appears once, grouped in category order", () => {
    const g = typesByCategory();
    const all = g.flatMap(([, t]) => t.map(([x]) => x));
    expect(new Set(all).size).toBe(all.length);
    expect(g[0][0]).toBe("scans");
    expect(all).toContain("user_login");
  });
  it("periods", () => {
    const now = Date.parse("2026-10-20T12:00:00Z");
    expect(sinceFor("30", now)).toBe("2026-09-20");
    expect(sinceFor("all", now)).toBeNull();
    expect(sinceFor("x", now)).toBeNull();
  });
});
