import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn() }));
jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
import { authedFetch } from "@/lib/useRealData";
import RulesPage from "@/app/rules/page";
import type { CatalogRule } from "@/lib/ruleCatalog";

const mockFetch = authedFetch as jest.MockedFunction<typeof authedFetch>;
jest.setTimeout(30000);
beforeEach(() => mockFetch.mockReset());

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
