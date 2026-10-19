/**
 * Control evidence (lib/controlEvidence.ts): facts are derived from real rows, checks report what was measured,
 * a control is as strong as its weakest check, and the framework catalogue cites the right controls.
 */
import {
  CHECK_INFO, FRAMEWORKS, STATUS_LABEL, deriveFacts, evaluateChecks, evaluateFramework, frameworkById, normalizeFrameworkId, countStatuses,
  type ComplianceFacts, type FactRows,
} from "@/lib/controlEvidence";
import { buildOverview, buildPackage } from "@/lib/evidenceEngine";

jest.mock("@/lib/supabase", () => ({ createServiceClient: jest.fn() }));

const NOW = "2026-10-19T12:00:00.000Z";

function rows(over: Partial<FactRows> = {}): FactRows {
  return {
    period_start: "2026-07-21T00:00:00.000Z", period_end: NOW, now: NOW,
    activeRepos: ["acme/api", "acme/web"],
    scans: [
      { id: "s1", repo: "acme/api", pr_number: 7, pr_author: "alice", created_at: "2026-10-01T00:00:00Z" },
      { id: "s2", repo: "acme/api", pr_number: 7, pr_author: "alice", created_at: "2026-10-02T00:00:00Z" }, // supersedes s1
      { id: "s3", repo: "acme/api", pr_number: 8, pr_author: "Bob", created_at: "2026-10-03T00:00:00Z" },
    ],
    riskyFiles: [
      { scan_id: "s1", file_path: "old.ts", ai_percentage: 0.9 },   // superseded: not counted
      { scan_id: "s2", file_path: "a.ts", ai_percentage: 0.8 },
      { scan_id: "s2", file_path: "b.ts", ai_percentage: 0.1 },
      { scan_id: "s3", file_path: "c.ts", ai_percentage: 0.5 },     // exactly the AI-heavy threshold
    ],
    attestations: [
      { scan_id: "s2", file_path: "a.ts", reviewer_github: "carol" },
      { scan_id: "s3", file_path: "c.ts", reviewer_github: "bob" },   // self-approval, case-insensitive
      { scan_id: "s1", file_path: "old.ts", reviewer_github: null },  // can't compare
    ],
    violations: [
      { scan_id: "s1", file_path: "x.ts", status: "open", sla_deadline: "2026-10-05T00:00:00Z" },
      { scan_id: "s2", file_path: "x.ts", status: "resolved", sla_deadline: "2026-10-05T00:00:00Z" }, // latest row: resolved
      { scan_id: "s3", file_path: "y.ts", status: "open", sla_deadline: "2026-10-10T00:00:00Z" },     // overdue
      { scan_id: "s3", file_path: "z.ts", status: "in_review", sla_deadline: "2026-11-01T00:00:00Z" },
      { scan_id: "s3", file_path: "w.ts", status: "open", sla_deadline: null },
      { scan_id: "missing", file_path: "q.ts", status: "open", sla_deadline: "2026-01-01T00:00:00Z" }, // unknown scan: ignored
    ],
    secrets: { open: 0, open_critical: 0, resolved_in_period: 2 },
    audit: { valid: true, total: 40 },
    members: [{ can_attest: true }, { can_attest: false }, { can_attest: true }],
    ai: { policy_configured: true, compliance: 1, open_violations: 0 },
    files_analyzed: 12,
    ...over,
  };
}

describe("deriveFacts", () => {
  it("counts each pull request's latest scan only, and reviews against the real author", () => {
    const f = deriveFacts(rows());
    expect(f.prs_scanned).toBe(2);
    expect(f.repos).toEqual({ active: 2, scanned: 1 });
    expect(f.risky).toEqual({ total: 3, reviewed: 2, ai_heavy_total: 2, ai_heavy_reviewed: 2 });
    expect(f.reviews).toEqual({ total: 3, independent: 1, self: 1, unknown: 1 });
  });

  it("open findings are the latest row per file; overdue means past its deadline now", () => {
    const f = deriveFacts(rows());
    expect(f.findings).toEqual({ open: 3, open_with_deadline: 2, overdue: 1 });
    // A deadline of exactly now hasn't been missed yet.
    const due = deriveFacts(rows({ violations: [{ scan_id: "s3", file_path: "y.ts", status: "open", sla_deadline: NOW }] }));
    expect(due.findings.overdue).toBe(0);
  });

  it("access and AI facts come straight through; a failed Shadow AI load is 'unavailable', not 'no policy'", () => {
    const f = deriveFacts(rows());
    expect(f.access).toEqual({ members: 3, can_attest: 2 });
    expect(f.ai).toEqual({ available: true, policy_configured: true, compliance: 1, open_violations: 0, files_analyzed: 12 });
    expect(deriveFacts(rows({ ai: null })).ai.available).toBe(false);
    expect(evaluateChecks(deriveFacts(rows({ ai: null }))).ai_policy.status).toBe("not_tested");
  });

  it("a scan with no author or reviewer without a GitHub login can't be compared", () => {
    const f = deriveFacts(rows({
      scans: [{ id: "s1", repo: "acme/api", pr_number: 1, pr_author: null, created_at: NOW }],
      attestations: [{ scan_id: "s1", file_path: "a.ts", reviewer_github: "carol" }, { scan_id: "s1", file_path: "b.ts", reviewer_github: " " }],
    }));
    expect(f.reviews).toEqual({ total: 2, independent: 0, self: 0, unknown: 2 });
  });
});

function facts(over: Partial<ComplianceFacts> = {}): ComplianceFacts {
  return {
    period_start: "a", period_end: "b",
    repos: { active: 4, scanned: 4 }, prs_scanned: 10,
    risky: { total: 10, reviewed: 10, ai_heavy_total: 4, ai_heavy_reviewed: 4 },
    reviews: { total: 10, independent: 10, self: 0, unknown: 0 },
    findings: { open: 3, open_with_deadline: 3, overdue: 0 },
    secrets: { open: 0, open_critical: 0, resolved_in_period: 1 },
    audit: { valid: true, total: 100, broken_at: null },
    access: { members: 5, can_attest: 2 },
    ai: { available: true, policy_configured: true, compliance: 1, open_violations: 0, files_analyzed: 50 },
    ...over,
  };
}

describe("evaluateChecks", () => {
  it("everything evidenced → every check collected", () => {
    const c = evaluateChecks(facts());
    for (const k of Object.values(c)) expect([k.key, k.status]).toEqual([k.key, "pass"]);
  });

  it("review coverage: ≥90% collected, ≥50% gaps, below that failing, none → no evidence yet", () => {
    const at = (reviewed: number) => evaluateChecks(facts({ risky: { total: 10, reviewed, ai_heavy_total: 0, ai_heavy_reviewed: 0 } })).review;
    expect(at(9).status).toBe("pass");
    expect(at(8).status).toBe("partial");
    expect(at(5).status).toBe("partial");
    expect(at(4).status).toBe("fail");
    expect(at(8).gaps).toEqual(["2 high-risk files not yet reviewed"]);
    expect(at(8).summary).toContain("8 of 10 high-risk files");
    expect(evaluateChecks(facts({ risky: { total: 0, reviewed: 0, ai_heavy_total: 0, ai_heavy_reviewed: 0 } })).review.status).toBe("not_tested");
  });

  it("independent review: any self-approval is a gap, more than 5% is failing; unknowns are a gap", () => {
    const at = (independent: number, self: number, unknown = 0) =>
      evaluateChecks(facts({ reviews: { total: independent + self + unknown, independent, self, unknown } })).independent_review;
    expect(at(100, 0).status).toBe("pass");
    expect(at(95, 5).status).toBe("partial");
    expect(at(94, 6).status).toBe("fail");
    expect(at(10, 0, 1).status).toBe("partial");
    expect(at(0, 0, 3)).toMatchObject({ status: "partial", score: 0 });
    expect(at(0, 0, 0).status).toBe("not_tested");
    expect(at(9, 1).gaps[0]).toBe("1 self-approval: the author signed off their own change");
  });

  it("deadlines, secrets and audit trail fail on the real problem", () => {
    expect(evaluateChecks(facts({ findings: { open: 5, open_with_deadline: 5, overdue: 1 } })).remediation.status).toBe("partial");
    expect(evaluateChecks(facts({ findings: { open: 5, open_with_deadline: 5, overdue: 2 } })).remediation.status).toBe("fail");
    expect(evaluateChecks(facts({ findings: { open: 2, open_with_deadline: 0, overdue: 0 } })).remediation.status).toBe("pass");
    expect(evaluateChecks(facts({ secrets: { open: 2, open_critical: 0, resolved_in_period: 0 } })).secrets.status).toBe("partial");
    expect(evaluateChecks(facts({ secrets: { open: 2, open_critical: 1, resolved_in_period: 0 } })).secrets.status).toBe("fail");
    const broken = evaluateChecks(facts({ audit: { valid: false, total: 9, broken_at: 4 } })).audit_trail;
    expect(broken).toMatchObject({ status: "fail" });
    expect(broken.summary).toContain("at entry 4");
    expect(evaluateChecks(facts({ audit: { valid: true, total: 0, broken_at: null } })).audit_trail.status).toBe("not_tested");
  });

  it("scanning gaps name the unscanned repositories; no scans → findings checks have no evidence", () => {
    expect(evaluateChecks(facts({ repos: { active: 4, scanned: 3 } })).scanning).toMatchObject({ status: "partial", gaps: ["1 active repository with no scan in this period"] });
    const none = evaluateChecks(facts({ prs_scanned: 0 }));
    expect(none.remediation.status).toBe("not_tested");
    expect(none.secrets.status).toBe("not_tested");
  });

  it("AI governance: no policy fails; unapproved tools are a gap; AI-written risky code needs review", () => {
    expect(evaluateChecks(facts({ ai: { ...facts().ai, policy_configured: false } })).ai_policy.status).toBe("fail");
    expect(evaluateChecks(facts({ ai: { ...facts().ai, compliance: 0.8, open_violations: 2 } })).ai_policy).toMatchObject({ status: "partial", score: 80 });
    expect(evaluateChecks(facts({ ai: { ...facts().ai, compliance: null } })).ai_policy.status).toBe("pass");
    expect(evaluateChecks(facts({ risky: { total: 10, reviewed: 7, ai_heavy_total: 4, ai_heavy_reviewed: 1 } })).ai_review.status).toBe("fail");
    expect(evaluateChecks(facts({ ai: { ...facts().ai, files_analyzed: 0 } })).ai_provenance.status).toBe("not_tested");
  });
});

describe("frameworks", () => {
  it("cite the real controls and no longer assess the EU AI Act", () => {
    const ids = (id: string) => frameworkById(id)!.controls.map(c => c.id);
    expect(ids("soc2")).toEqual(["CC8.1", "CC7.1", "CC6.1", "CC7.2"]);
    expect(ids("iso27001")).toEqual(["A.8.25", "A.8.28", "A.8.29", "A.8.32", "A.8.8", "A.8.15"]);
    expect(ids("pcidss")).toEqual(["6.2.3", "6.2.3.1", "6.2.4", "6.3.1", "10.3.2"]);
    expect(FRAMEWORKS.map(f => f.id)).toEqual(["soc2", "iso27001", "pcidss", "aigov"]);
    expect(frameworkById("aigov")!.scope).toMatch(/EU AI Act is not assessed/);
    for (const f of FRAMEWORKS) expect(f.scope.length).toBeGreaterThan(80);
  });

  it("old ids keep working", () => {
    expect(normalizeFrameworkId("EUAI")).toBe("aigov");
    expect(normalizeFrameworkId("EU AI Act")).toBe("aigov");
    expect(normalizeFrameworkId("AIGOV")).toBe("aigov");
    expect(normalizeFrameworkId("PCI-DSS")).toBe("pcidss");
    expect(normalizeFrameworkId("ISO 27001")).toBe("iso27001");
    expect(normalizeFrameworkId("SOC2")).toBe("soc2");
    expect(normalizeFrameworkId("whatever")).toBe("soc2");
  });

  it("a control is its weakest tested check; untested checks don't drag it down", () => {
    const soc2 = frameworkById("soc2")!;
    const checks = evaluateChecks(facts({ reviews: { total: 10, independent: 8, self: 2, unknown: 0 }, prs_scanned: 10 }));
    const cc81 = evaluateFramework(soc2, checks).find(c => c.control_id === "CC8.1")!;
    expect(cc81.status).toBe("fail");
    expect(cc81.checks.map(c => c.key)).toEqual(["review", "independent_review", "scanning"]);

    const untested = evaluateChecks(facts({ risky: { total: 0, reviewed: 0, ai_heavy_total: 0, ai_heavy_reviewed: 0 } }));
    expect(evaluateFramework(soc2, untested).find(c => c.control_id === "CC8.1")!.status).toBe("pass");
    const allUntested = evaluateChecks(facts({ audit: { valid: true, total: 0, broken_at: null } }));
    expect(evaluateFramework(soc2, allUntested).find(c => c.control_id === "CC7.2")).toMatchObject({ status: "not_tested", score: 0 });
    expect(countStatuses(evaluateFramework(soc2, checks))).toEqual({ pass: 3, partial: 0, fail: 1, not_tested: 0 });
  });

  it("every check used by a framework is described, with the same label the evaluation reports", () => {
    const c = evaluateChecks(facts());
    for (const f of FRAMEWORKS) for (const ctl of f.controls) for (const k of ctl.checks) expect(CHECK_INFO[k].label).toBe(c[k].label);
  });

  it("statuses read as evidence, never as compliance", () => {
    expect(Object.values(STATUS_LABEL)).toEqual(["Evidence collected", "Gaps found", "Failing", "No evidence yet"]);
  });
});

describe("evidence packages", () => {
  it("package keeps the shape older consumers read, plus scope and checks", () => {
    const r = rows();
    const pkg = buildPackage("EUAI", deriveFacts(r), r, NOW);
    expect(pkg).toMatchObject({ framework: "aigov", framework_name: "AI code governance", generated_at: NOW });
    expect(pkg.controls.map(c => c.control_id)).toEqual(["AIG-1", "AIG-2", "AIG-3", "AIG-4"]);
    expect(pkg.controls[2]).toMatchObject({ status: "fail", status_label: "Failing" });
    expect(pkg.controls[0].evidence[0].description).toContain("Approved AI tools policy:");
    expect(pkg.summary).toMatchObject({ total_scans: 3, total_attestations: 3, open_violations: 3, audit_events: 40, scan_files_total: 12 });
    expect(pkg.scope).toBe(frameworkById("aigov")!.scope);
  });

  it("overview lists PCI DSS only when it applies, and each gap once, worst first", () => {
    const f = deriveFacts(rows());
    expect(buildOverview(f, { pciApplicable: false }, NOW).frameworks.map(x => x.id)).toEqual(["soc2", "iso27001", "aigov"]);
    const o = buildOverview(f, { pciApplicable: true }, NOW);
    expect(o.frameworks.map(x => x.id)).toEqual(["soc2", "iso27001", "pcidss", "aigov"]);
    expect(o.gaps.map(g => g.key)).toEqual(["independent_review", "remediation", "review", "scanning"]);
    expect(new Set(o.gaps.map(g => g.key)).size).toBe(o.gaps.length);
  });
});
