import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
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

  const withUsage = () => mockFetch.mockImplementation(async (url: string) => url.includes("usage=1")
    ? { rules, scope: "org", usage: { "hardcoded-secret": { files: 3, repos: 2, where: [
        { repo: "o/api", file_path: "src/config.ts", scan_id: "s1" }, { repo: "o/web", file_path: "env.ts", scan_id: "s2" },
      ] } } }
    : { rules }) as never;

  it("shows where each rule fires in your code, leads with those, and can show only them", async () => {
    withUsage();
    render(<RulesPage />);
    const summary = await screen.findByRole("region", { name: "Catalog summary" });
    await waitFor(() => expect(within(summary).getByText("Firing in your code").parentElement).toHaveTextContent("1"));
    const rows = () => screen.getAllByRole("row").filter(r => r.hasAttribute("aria-expanded"));
    expect(rows()[0]).toHaveTextContent("Hardcoded Secret");                        // firing rules first
    expect(rows()[0]).toHaveTextContent("3 files · 2 repos");
    expect(rows()[1]).toHaveTextContent("None");

    fireEvent.click(screen.getByLabelText("Only rules firing in my code"));
    expect(rows()).toHaveLength(1);
    fireEvent.click(screen.getByText("Hardcoded Secret"));
    expect(screen.getByRole("link", { name: /config\.ts/ })).toHaveAttribute("href", "/pr/s1");
    expect(screen.getByText("and 1 more")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(rows()).toHaveLength(3);
  });

  it("filters by severity and language, and sorts by name", async () => {
    withUsage();
    render(<RulesPage />);
    await screen.findByText("SQL Injection");
    const rows = () => screen.getAllByRole("row").filter(r => r.hasAttribute("aria-expanded")).map(r => r.querySelector("p")!.textContent);
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "high" } });
    expect(rows()).toEqual(["Admin/Database Port Open to the Internet"]);
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "all" } });
    fireEvent.change(screen.getByLabelText("Applies to"), { target: { value: "Python" } });
    expect(rows()).toEqual(["SQL Injection"]);
    fireEvent.change(screen.getByLabelText("Applies to"), { target: { value: "all" } });
    fireEvent.change(screen.getByLabelText("Sort"), { target: { value: "name" } });
    expect(rows()).toEqual(["Admin/Database Port Open to the Internet", "Hardcoded Secret", "SQL Injection"]);
  });

  it("a #rule-id link opens that rule", async () => {
    withUsage();
    window.location.hash = "#sql-injection";
    render(<RulesPage />);
    expect(await screen.findByText("Use bound parameters.")).toBeInTheDocument();
    window.location.hash = "";
  });

  it("if counting usage fails, the catalog still works and says it couldn't count", async () => {
    mockFetch.mockImplementation(async (url: string) => { if (url.includes("usage=1")) throw new Error("down"); return { rules }; });
    render(<RulesPage />);
    expect(await screen.findByText("SQL Injection")).toBeInTheDocument();
    expect(screen.getByText("Couldn't count")).toBeInTheDocument();
    expect(screen.getByLabelText("Only rules firing in my code")).toBeDisabled();
  });
});
