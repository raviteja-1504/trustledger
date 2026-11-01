/**
 * Report section 4b: each framework's working form, rendered from lib/frameworkViews.ts.
 */
import React from "react";
import { render, screen, within } from "@testing-library/react";
import FrameworkView from "@/components/reports/FrameworkView";
import { evaluateChecks, evaluateFramework, frameworkById, type ComplianceFacts } from "@/lib/controlEvidence";

const facts: ComplianceFacts = {
  period_start: "2026-07-01T00:00:00Z", period_end: "2026-10-01T00:00:00Z",
  repos: { active: 2, scanned: 2 }, prs_scanned: 5,
  risky: { total: 4, reviewed: 3, ai_heavy_total: 0, ai_heavy_reviewed: 0 },
  reviews: { total: 3, independent: 3, self: 0, unknown: 0 },
  findings: { open: 0, open_with_deadline: 0, overdue: 0 }, secrets: { open: 0, open_critical: 0, resolved_in_period: 0 },
  audit: { valid: true, total: 9, broken_at: null }, access: { members: 3, can_attest: 1 },
  ai: { available: true, policy_configured: true, compliance: null, open_violations: 0, files_analyzed: 4 },
};
const show = (id: string) => {
  const fw = frameworkById(id)!;
  return render(<FrameworkView fw={fw} controls={evaluateFramework(fw, evaluateChecks(facts))} />);
};

describe("FrameworkView", () => {
  it("ISO 27001: SoA input with evidenced and unevidenced controls", () => {
    show("iso27001");
    const table = screen.getByRole("table", { name: "Statement of Applicability input" });
    expect(within(table).getAllByRole("row")).toHaveLength(13);
    expect(within(table).getByText("Access to source code")).toBeInTheDocument();
    // the review gap belongs to both controls that rely on that check
    expect(within(table).getAllByText("Gap: 1 high-risk file not yet reviewed")).toHaveLength(2);
  });

  it("PCI DSS: the 6.2.4 attack classes with rule links", () => {
    show("pcidss");
    const table = screen.getByRole("table", { name: "Requirement 6.2.4 attack classes" });
    expect(within(table).getAllByRole("row")).toHaveLength(7);
    expect(within(table).getByRole("link", { name: "sql-injection" })).toHaveAttribute("href", "/rules#sql-injection");
  });

  it("AI governance: the mapping with its caveat", () => {
    show("aigov");
    expect(screen.getByText(/Indicative mapping/)).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "AI governance mapping" });
    expect(within(table).getByText("GOVERN 6.1")).toBeInTheDocument();
  });

  it("SOC 2 has no separate view (the change register is its view)", () => {
    const { container } = show("soc2");
    expect(container).toBeEmptyDOMElement();
  });
});
