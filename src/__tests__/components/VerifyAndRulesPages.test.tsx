import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn() }));
jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
import { authedFetch } from "@/lib/useRealData";
import VerifyRecordPage from "@/app/verify-record/page";
import RulesPage from "@/app/rules/page";
import type { CatalogRule } from "@/lib/ruleCatalog";

const mockFetch = authedFetch as jest.MockedFunction<typeof authedFetch>;
jest.setTimeout(30000);
beforeEach(() => mockFetch.mockReset());

describe("Verify Trust Record page", () => {
  it("a chosen file is sent for verification and the verdict and record details are shown", async () => {
    mockFetch.mockResolvedValue({
      status: "valid", message: "Valid. This record was produced by TrustLedger with this server's key and hasn't been changed since.",
      summary: { organization: "Acme", change: { repository: "acme/shop", pull_request: 7, commit: "abcdef123456" }, verdict: { overall_risk: "HIGH", merge_gate: "clear", ai_share_percent: 12, open_blocking_violations: 0 },
        summary: { findings: 3, critical: 0, high: 1, introduced_by_pr: 1, accepted_or_false_positive: 1, files: 4, files_attested: 4 } },
    });
    render(<VerifyRecordPage />);
    const file = new File([JSON.stringify({ record: { schema: "trustledger.trust-record/v1" }, signature: null })], "trust-record.json", { type: "application/json" });
    fireEvent.change(screen.getByLabelText("Choose a file"), { target: { files: [file] } });
    expect(await screen.findByText("Valid", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(mockFetch).toHaveBeenCalledWith("/api/trust-record/verify", expect.objectContaining({ method: "POST" }));
    expect(screen.getByText(/acme\/shop · PR #7 · abcdef1234/)).toBeInTheDocument();
    expect(screen.getByText("4 of 4 files attested")).toBeInTheDocument();
  });

  it("text that isn't JSON is rejected locally, without calling the server", async () => {
    render(<VerifyRecordPage />);
    fireEvent.change(screen.getByLabelText("Trust Record JSON"), { target: { value: "not json" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByText("Not a Trust Record", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("a tampered record says so and warns that its details can't be trusted", async () => {
    mockFetch.mockResolvedValue({ status: "tampered", message: "Tampered.", summary: { organization: null, change: { repository: "a/b", pull_request: 1, commit: "c0ffee00" } } });
    render(<VerifyRecordPage />);
    fireEvent.change(screen.getByLabelText("Trust Record JSON"), { target: { value: "{}" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByText("Tampered", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByText(/only trustworthy when the record is valid/)).toBeInTheDocument();
  });
});

describe("Rule catalog page", () => {
  const rules: CatalogRule[] = [
    { id: "sql-injection", title: "SQL Injection", description: "Query built from input.", cwe: "CWE-89", severity: "critical", detection: "data-flow", appliesTo: ["Python", "Java"], fix: { title: "Parameterise", description: "Use bound parameters.", code_after: "db.query(sql, [id])" } },
    { id: "cloud-open-admin-port", title: "Admin/Database Port Open to the Internet", description: "0.0.0.0/0 to SSH.", cwe: "CWE-284", severity: "high", detection: "configuration", appliesTo: ["Terraform"], fix: null },
    { id: "hardcoded-secret", title: "Hardcoded Secret", description: "A credential in source.", cwe: "CWE-798", severity: null, detection: "pattern", appliesTo: [], fix: null },
  ];

  it("lists rules, filters by detection, searches, and expands a rule's remediation", async () => {
    mockFetch.mockResolvedValue({ rules });
    render(<RulesPage />);
    expect(await screen.findByText("SQL Injection", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Data flow (1)" })).toBeInTheDocument();
    expect(screen.getByText("varies")).toBeInTheDocument();                         // pattern rule without a fixed severity

    fireEvent.click(screen.getByRole("button", { name: "Configuration (1)" }));
    expect(screen.queryByText("SQL Injection")).toBeNull();
    expect(screen.getByText("Admin/Database Port Open to the Internet")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^All/ }));
    fireEvent.change(screen.getByLabelText("Search rules"), { target: { value: "cwe-798" } });
    await waitFor(() => expect(screen.queryByText("SQL Injection")).toBeNull(), { timeout: 5000 });
    expect(screen.getByText("Hardcoded Secret")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Search rules"), { target: { value: "" } });
    fireEvent.click(screen.getByText("SQL Injection"));
    expect(screen.getByText("Use bound parameters.")).toBeInTheDocument();
    expect(screen.getByText("db.query(sql, [id])")).toBeInTheDocument();
    expect(screen.getByText("Confirmed")).toBeInTheDocument();                     // the confidence vocabulary is explained
  });
});
