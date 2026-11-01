/**
 * Framework-specific views (lib/frameworkViews.ts): ISO/IEC 27001 Statement of Applicability input, PCI DSS 6.2.4
 * attack classes, and the AI governance mapping -- each honest about where TrustLedger holds no evidence.
 */
import { FRAMEWORKS, evaluateChecks, evaluateFramework, frameworkById, type ComplianceFacts } from "@/lib/controlEvidence";
import { AI_MAPPING_CAVEAT, PCI_624_CLASSES, aiGovernanceMappings, frameworkView, isoSoaRows } from "@/lib/frameworkViews";
import { FINDING_CATALOG } from "@/lib/findingCatalog";

const facts: ComplianceFacts = {
  period_start: "2026-07-01T00:00:00Z", period_end: "2026-10-01T00:00:00Z",
  repos: { active: 2, scanned: 2 }, prs_scanned: 5,
  risky: { total: 4, reviewed: 3, ai_heavy_total: 0, ai_heavy_reviewed: 0 },
  reviews: { total: 3, independent: 3, self: 0, unknown: 0 },
  findings: { open: 0, open_with_deadline: 0, overdue: 0 }, secrets: { open: 0, open_critical: 0, resolved_in_period: 0 },
  audit: { valid: true, total: 9, broken_at: null }, access: { members: 3, can_attest: 1 },
  ai: { available: true, policy_configured: true, compliance: null, open_violations: 0, files_analyzed: 4 },
};
const evaluated = (id: string) => evaluateFramework(frameworkById(id)!, evaluateChecks(facts));

describe("ISO/IEC 27001 Statement of Applicability input", () => {
  const rows = isoSoaRows(evaluated("iso27001"));

  it("lists the Annex A 8 development controls in Annex order, evidenced exactly where TrustLedger has a control", () => {
    expect(rows.map(r => r.control)).toEqual(["A.8.4", "A.8.8", "A.8.15", "A.8.25", "A.8.26", "A.8.27", "A.8.28", "A.8.29", "A.8.30", "A.8.31", "A.8.32", "A.8.33"]);
    const isoIds = frameworkById("iso27001")!.controls.map(c => c.id).sort();
    expect(rows.filter(r => r.evidenced).map(r => r.control).sort()).toEqual(isoIds);
  });

  it("an unevidenced control says so and leaves applicability to the organisation", () => {
    const a84 = rows.find(r => r.control === "A.8.4")!;
    expect(a84).toMatchObject({ evidenced: false, status: null, evidence_reference: "—" });
    expect(a84.implementation).toMatch(/no evidence.*Decide its applicability in your SoA/);
  });

  it("evidenced controls carry the control statement, its partial coverage, gaps, and where the evidence is", () => {
    const a832 = rows.find(r => r.control === "A.8.32")!;
    expect(a832.evidence_reference).toMatch(/Change-Management Register/);
    expect(a832.implementation).toBe(frameworkById("iso27001")!.controls.find(c => c.id === "A.8.32")!.statement);
    expect(rows.find(r => r.control === "A.8.15")!.implementation).toMatch(/\(Partial: .*TrustLedger's own activity log/);
    expect(rows.find(r => r.control === "A.8.28")!.gaps).toEqual(["1 high-risk file not yet reviewed"]);
  });
});

describe("PCI DSS 6.2.4 attack classes", () => {
  it("covers the six classes the requirement lists", () => {
    expect(PCI_624_CLASSES.map(c => c.key)).toEqual(["injection", "data", "crypto", "business-logic", "access-control", "high-risk"]);
    expect(PCI_624_CLASSES.find(c => c.key === "business-logic")!.title).toMatch(/XSS and CSRF/);
  });

  it("every rule named is a real rule in the catalog, listed once", () => {
    const all = PCI_624_CLASSES.flatMap(c => c.rules);
    expect(all.filter(r => !FINDING_CATALOG[r])).toEqual([]);
    expect(new Set(all).size).toBe(all.length);
  });

  it("each class says where static scanning stops", () => {
    for (const c of PCI_624_CLASSES) expect(c.limits.length).toBeGreaterThan(20);
  });
});

describe("AI governance mapping", () => {
  const rows = aiGovernanceMappings(frameworkById("aigov")!, evaluated("aigov"));

  it("one row per AIG control with its status; controls with no counterpart claim none", () => {
    expect(rows.map(r => r.control)).toEqual(["AIG-1", "AIG-2", "AIG-3", "AIG-4"]);
    expect(rows.find(r => r.control === "AIG-4")!.status).toBe("pass");
    for (const id of ["AIG-3", "AIG-4"]) {
      const r = rows.find(x => x.control === id)!;
      expect([r.iso42001, r.nist_ai_rmf]).toEqual([[], []]);
      expect(r.note).toMatch(/^No direct counterpart/);
    }
    expect(rows.find(r => r.control === "AIG-1")!.iso42001.map(x => x.id)).toEqual(["A.9.2", "A.10.3"]);
  });

  it("is labelled indicative and not conformity", () => {
    expect(AI_MAPPING_CAVEAT).toMatch(/Indicative/);
    expect(AI_MAPPING_CAVEAT).toMatch(/does not show conformity/);
  });
});

describe("frameworkView", () => {
  it("ISO → SoA input, PCI → 6.2.4, AI governance → mapping, SOC 2 → none (its view is the change register)", () => {
    const kinds = Object.fromEntries(FRAMEWORKS.map(f => [f.id, frameworkView(f, evaluated(f.id))?.kind ?? null]));
    expect(kinds).toEqual({ soc2: null, iso27001: "iso_soa", pcidss: "pci_624", aigov: "ai_mapping" });
  });
});
