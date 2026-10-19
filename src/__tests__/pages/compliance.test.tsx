/**
 * Compliance evidence page: frameworks and controls come from measured facts, no compliance percentages or invented
 * audit dates; PCI DSS only when it applies; old EU AI Act exceptions land under AI code governance.
 */
import React from "react";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ComplianceFacts } from "@/lib/controlEvidence";

jest.mock("@/components/AuthGuard",    () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/PageSkeleton", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/toast", () => ({ useToastHelpers: () => ({ success: jest.fn(), error: jest.fn(), info: jest.fn(), warn: jest.fn() }) }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1", org_name: "Acme", email: "admin@acme.test" } }) }));
jest.mock("@/lib/roles", () => ({ useRole: () => ({ permissions: { canTriage: true } }) }));

const facts: ComplianceFacts = {
  period_start: "2026-07-21T00:00:00.000Z", period_end: "2026-10-19T00:00:00.000Z",
  repos: { active: 3, scanned: 3 }, prs_scanned: 12,
  risky: { total: 10, reviewed: 10, ai_heavy_total: 2, ai_heavy_reviewed: 2 },
  reviews: { total: 10, independent: 8, self: 2, unknown: 0 },
  findings: { open: 1, open_with_deadline: 1, overdue: 0 },
  secrets: { open: 0, open_critical: 0, resolved_in_period: 0 },
  audit: { valid: true, total: 50, broken_at: null },
  access: { members: 4, can_attest: 2 },
  ai: { available: true, policy_configured: true, compliance: 1, open_violations: 0, files_analyzed: 30 },
};

let pci = false;
const calls: string[] = [];
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  authedFetch: jest.fn(async (url: string) => {
    calls.push(url);
    if (url.startsWith("/api/evidence/collect")) return { facts };
    if (url === "/api/settings") return { org: { pci_applicable: pci } };
    if (url === "/api/compliance-exceptions") return { exceptions: [{
      id: "e1", control_id: "Art.13", framework_id: "euai", title: "Old transparency exception", description: null,
      risk_accepted: true, owner_email: "admin@acme.test", due_date: null, remediation: null, status: "open", created_at: "2026-09-01T00:00:00Z",
    }] };
    if (url === "/api/team") return { members: [{ email: "admin@acme.test" }] };
    throw new Error(`unexpected ${url}`);
  }),
}));

import CompliancePage from "@/app/compliance/page";

beforeEach(() => { pci = false; calls.length = 0; });

describe("Compliance evidence page", () => {
  it("shows each framework's evidence counts, no percentages, and no PCI DSS unless it applies", async () => {
    render(<CompliancePage />);
    const soc2 = await screen.findByRole("button", { name: /^SOC 2/ });
    await waitFor(() => expect(soc2).toHaveTextContent("3 of 4 controls with evidence"));
    expect(soc2).toHaveTextContent("1 failing");
    expect(screen.queryByRole("button", { name: /PCI DSS/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /AI code governance/ })).toHaveTextContent("1 exception");
    expect(document.body.textContent).not.toMatch(/\d+%\s*(compliant|overall)|Audit in \d+d|Audit-ready|EU AI Act Art/i);
    expect(calls.find(c => c.startsWith("/api/evidence/collect"))).toMatch(/period_start=/);
  });

  it("lists controls with the measured checks and their gaps", async () => {
    render(<CompliancePage />);
    await screen.findByText("Changes are authorised, tested and approved");
    expect(screen.getAllByText(/8 of 10 comparable sign-offs were by someone other than the pull request author/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Gap: 2 self-approvals/).length).toBeGreaterThan(0);
    expect(screen.getByText(/A SOC 2 report can only be issued by a licensed CPA firm/)).toBeInTheDocument();
  });

  it("shows PCI DSS when the org has a cardholder data environment", async () => {
    pci = true;
    render(<CompliancePage />);
    expect(await screen.findByRole("button", { name: /PCI DSS v4\.0/ })).toBeInTheDocument();
  });

  it("control map shows which control each check evidences, per framework", async () => {
    render(<CompliancePage />);
    await screen.findByText("Changes are authorised, tested and approved");
    fireEvent.click(screen.getByRole("tab", { name: "Control map" }));
    const row = screen.getByText("Reviewer is not the author", { selector: "p" }).closest("tr")!;
    expect(within(row).getByText("CC8.1")).toBeInTheDocument();
    expect(within(row).getByText("A.8.32")).toBeInTheDocument();
    expect(within(row).getByText("AIG-3")).toBeInTheDocument();
    expect(within(row).getByText("Failing")).toBeInTheDocument();
  });

  it("an old EU AI Act exception appears under AI code governance", async () => {
    render(<CompliancePage />);
    fireEvent.click(await screen.findByRole("button", { name: /AI code governance/ }));
    fireEvent.click(screen.getByRole("tab", { name: /Exceptions/ }));
    expect(await screen.findByText("Old transparency exception")).toBeInTheDocument();
    expect(screen.getByText(/control no longer in the AI governance set/)).toBeInTheDocument();
  });
});
