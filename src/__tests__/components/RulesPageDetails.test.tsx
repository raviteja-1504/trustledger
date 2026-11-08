/**
 * Rule catalog, the new parts: "Show all files" really loads every file (grouped, filterable, capped with a
 * notice), new / fixed since the previous scan, and a full remediation panel.
 */
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn() }));
jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
import { authedFetch } from "@/lib/useRealData";
import RulesPage from "@/app/rules/page";
import type { CatalogRule } from "@/lib/ruleCatalog";
import type { RuleLocation } from "@/lib/ruleUsage";

const mockFetch = authedFetch as jest.MockedFunction<typeof authedFetch>;
jest.setTimeout(30000);

const rules: CatalogRule[] = [
  { id: "sql-injection", title: "SQL Injection", description: "Query built from input.", cwe: "CWE-89", severity: "critical", detection: "data-flow", appliesTo: ["Python"],
    fix: { title: "Parameterise the query", description: "Use bound parameters. Never concatenate input into SQL. Validate the id type.", code_before: "db.query('... ' + id)", code_after: "db.query('... $1', [id])", effort: "low" } },
  { id: "nosql-injection", title: "NoSQL Injection", description: "Operator injection.", cwe: "CWE-89", severity: "high", detection: "data-flow", appliesTo: ["JavaScript/TypeScript"], fix: null },
  { id: "open-port", title: "Open admin port", description: "0.0.0.0/0 to SSH.", cwe: "CWE-284", severity: "high", detection: "configuration", appliesTo: ["Terraform"], fix: null },
  { id: "weak-hash", title: "Weak hash", description: "MD5.", cwe: null, severity: null, detection: "pattern", appliesTo: [], fix: null },
];
const loc = (repo: string, file_path: string, scan_id = "s1"): RuleLocation => ({ repo, file_path, scan_id });
const first = [loc("o/api", "src/a.ts"), loc("o/api", "src/b.ts"), loc("o/web", "w.ts", "s2")];
const everyFile = [...first, ...Array.from({ length: 5 }, (_, i) => loc("o/web", `pages/p${i}.ts`, "s2")), ...Array.from({ length: 12 }, (_, i) => loc("o/api", `lib/l${String(i).padStart(2, "0")}.ts`))];

let allResponse: () => unknown;
const calls: string[] = [];
const setup = (usage: Record<string, unknown>) => mockFetch.mockImplementation((async (url: string) => {
  calls.push(url);
  if (url.includes("rule=")) return allResponse();
  if (url.includes("usage=1")) return { rules, scope: "org", usage };
  return { rules };
}) as never);
const usage = () => ({
  "sql-injection": { files: everyFile.length, repos: 2, where: first, new: 3, fixed: 1, compared: true },
  "nosql-injection": { files: 2, repos: 1, where: [loc("o/api", "x.ts"), loc("o/api", "y.ts")], new: 0, fixed: 0, compared: true },
  "open-port": { files: 0, repos: 0, new: 0, fixed: 2, compared: true },
});
const rowOf = (title: string) => screen.getByText(title).closest("tr")!;

beforeEach(() => { mockFetch.mockReset(); calls.length = 0; allResponse = () => ({ locations: everyFile, total: everyFile.length, truncated: false, scope: "org" }); });

describe("Show all files", () => {
  it("is a real control that loads every file, not a static 'and N more'", async () => {
    setup(usage());
    render(<RulesPage />);
    fireEvent.click(await screen.findByText("SQL Injection"));
    const where = within(screen.getByTestId("where-it-fires"));
    expect(where.getAllByRole("link")).toHaveLength(3);                       // the first few
    fireEvent.click(where.getByRole("button", { name: `Show all ${everyFile.length} files →` }));
    await waitFor(() => expect(where.getAllByRole("link")).toHaveLength(everyFile.length));
    expect(calls.some(c => c === "/api/rules?rule=sql-injection")).toBe(true);
    expect(where.queryByRole("button", { name: /Show all/ })).toBeNull();
  });

  it("groups the files by repository, each linking into the scan at that file", async () => {
    setup(usage());
    render(<RulesPage />);
    fireEvent.click(await screen.findByText("SQL Injection"));
    fireEvent.click(screen.getByRole("button", { name: /Show all/ }));
    const where = within(await screen.findByTestId("where-it-fires"));
    await waitFor(() => expect(where.getAllByRole("link").length).toBeGreaterThan(3));
    expect(where.getByText(/api/, { selector: "p" })).toHaveTextContent("14 files");
    expect(where.getByText(/web/, { selector: "p" })).toHaveTextContent("6 files");
    expect(where.getByRole("link", { name: "pages/p3.ts" })).toHaveAttribute("href", "/pr/s2?file=pages%2Fp3.ts");
  });

  it("with many files, a repository filter and a path filter narrow the list", async () => {
    setup(usage());
    render(<RulesPage />);
    fireEvent.click(await screen.findByText("SQL Injection"));
    fireEvent.click(screen.getByRole("button", { name: /Show all/ }));
    const where = within(await screen.findByTestId("where-it-fires"));
    await waitFor(() => expect(where.getAllByRole("link").length).toBe(everyFile.length));
    fireEvent.change(where.getByLabelText("Repository"), { target: { value: "o/web" } });
    expect(where.getAllByRole("link")).toHaveLength(6);
    fireEvent.change(where.getByLabelText("Filter files"), { target: { value: "p2" } });
    expect(where.getAllByRole("link").map(a => a.textContent)).toEqual(["pages/p2.ts"]);
    fireEvent.change(where.getByLabelText("Filter files"), { target: { value: "zzz" } });
    expect(where.getByText("No file matches.")).toBeInTheDocument();
  });

  it("says when even 'all' was cut at the cap, with the real total", async () => {
    allResponse = () => ({ locations: everyFile, total: 2600, truncated: true, scope: "org" });
    setup(usage());
    render(<RulesPage />);
    fireEvent.click(await screen.findByText("SQL Injection"));
    fireEvent.click(screen.getByRole("button", { name: /Show all/ }));
    expect(await screen.findByText(`Showing ${everyFile.length} of 2,600 files.`)).toBeInTheDocument();
  });

  it("a failure says so and can be retried", async () => {
    setup(usage());
    render(<RulesPage />);
    fireEvent.click(await screen.findByText("SQL Injection"));
    allResponse = () => { throw new Error("Server busy"); };
    fireEvent.click(screen.getByRole("button", { name: /Show all/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Server busy");
    allResponse = () => ({ locations: everyFile, total: everyFile.length, truncated: false });
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(within(screen.getByTestId("where-it-fires")).getAllByRole("link")).toHaveLength(everyFile.length));
  });

  it("'Show fewer' goes back to the first few", async () => {
    setup(usage());
    render(<RulesPage />);
    fireEvent.click(await screen.findByText("SQL Injection"));
    fireEvent.click(screen.getByRole("button", { name: /Show all/ }));
    await waitFor(() => expect(within(screen.getByTestId("where-it-fires")).getAllByRole("link")).toHaveLength(everyFile.length));
    fireEvent.click(screen.getByRole("button", { name: "Show fewer" }));
    expect(within(screen.getByTestId("where-it-fires")).getAllByRole("link")).toHaveLength(3);
  });

  it("no button when everything is already listed", async () => {
    setup(usage());
    render(<RulesPage />);
    fireEvent.click(await screen.findByText("NoSQL Injection"));
    expect(within(screen.getByTestId("where-it-fires")).queryByRole("button", { name: /Show all/ })).toBeNull();
  });
});

describe("new and fixed since the previous scan", () => {
  it("rows carry ▲ new and ✓ fixed chips; unchanged rules carry none", async () => {
    setup(usage());
    render(<RulesPage />);
    await screen.findByText("SQL Injection");
    expect(within(rowOf("SQL Injection")).getByText("▲ 3 new")).toBeInTheDocument();
    expect(within(rowOf("SQL Injection")).getByText("✓ 1 fixed")).toBeInTheDocument();
    expect(within(rowOf("NoSQL Injection")).queryByText(/new|fixed/)).toBeNull();
  });

  it("the summary counts them, and a rule that is now clear still appears, as fixed", async () => {
    setup(usage());
    render(<RulesPage />);
    const summary = await screen.findByRole("region", { name: "Catalog summary" });
    await waitFor(() => expect(within(summary).getByText("New since last scan").parentElement).toHaveTextContent("3"));
    expect(within(summary).getByText("New since last scan").parentElement).toHaveTextContent("files in 1 rule · 1 critical or high");
    expect(within(summary).getByText("Fixed since last scan").parentElement).toHaveTextContent("3");     // 1 + 2
    expect(within(rowOf("Open admin port")).getByText("✓ 2 fixed")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Open admin port"));
    expect(screen.getByText(/Fixed in 2 files since the previous scan/)).toBeInTheDocument();
  });

  it("'Only rules with new findings' and the newest-first sort", async () => {
    setup({ ...usage(), "nosql-injection": { files: 2, repos: 1, where: [], new: 7, fixed: 0, compared: true } });
    render(<RulesPage />);
    await screen.findByText("SQL Injection");
    const titles = () => screen.getAllByRole("row").filter(r => r.hasAttribute("aria-expanded")).map(r => r.querySelector("p")!.textContent);
    fireEvent.change(screen.getByLabelText("Sort"), { target: { value: "new" } });
    expect(titles().slice(0, 2)).toEqual(["NoSQL Injection", "SQL Injection"]);
    fireEvent.click(screen.getByLabelText("Only rules with new findings"));
    expect(titles()).toEqual(["NoSQL Injection", "SQL Injection"]);
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(titles()).toHaveLength(4);
  });

  it("with no earlier scan to compare with, it says so and offers no false 'new' claims", async () => {
    setup({ "sql-injection": { files: 3, repos: 1, where: first } });
    render(<RulesPage />);
    const summary = await screen.findByRole("region", { name: "Catalog summary" });
    await waitFor(() => expect(within(summary).getByText("Firing in your code").parentElement).toHaveTextContent("1"));
    expect(within(summary).getAllByText("No earlier scan to compare with")).toHaveLength(2);
    expect(screen.getByLabelText("Only rules with new findings")).toBeDisabled();
    expect(within(rowOf("SQL Injection")).queryByText(/new$/)).toBeNull();
  });
});

describe("remediation", () => {
  const open = async () => { setup(usage()); render(<RulesPage />); fireEvent.click(await screen.findByText("SQL Injection")); return within(await screen.findByTestId("remediation")); };

  it("leads with how soon to fix it, from the severity", async () => {
    const r = await open();
    expect(r.getByText("Priority: Same day")).toBeInTheDocument();
    expect(r.getByText(/Before merging/)).toBeInTheDocument();
  });

  it("the fix is steps, with the effort", async () => {
    const r = await open();
    const steps = within(r.getByText("How to fix").nextElementSibling as HTMLElement).getAllByRole("listitem").map(li => li.textContent);
    expect(steps).toEqual(["Use bound parameters.", "Never concatenate input into SQL.", "Validate the id type."]);
    expect(r.getByText("Parameterise the query")).toBeInTheDocument();
    expect(r.getByText(/Quick fix: a few lines/)).toBeInTheDocument();
  });

  it("shows the vulnerable and the fixed example, each with a copy button", async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    const r = await open();
    expect(r.getByText("Vulnerable")).toBeInTheDocument();
    expect(r.getByText("Fixed")).toBeInTheDocument();
    fireEvent.click(r.getByRole("button", { name: "Copy the fixed example" }));
    expect(writeText).toHaveBeenCalledWith("db.query('... $1', [id])");
    expect(await r.findByText("Copied ✓")).toBeInTheDocument();
  });

  it("says how to verify, for this kind of rule", async () => {
    const r = await open();
    expect(r.getByText(/break the path between the input and the dangerous call/)).toBeInTheDocument();
    expect(r.getByText(/Add a test that sends the malicious input/)).toBeInTheDocument();
  });

  it("links related rules for the same CWE and the MITRE page", async () => {
    const r = await open();
    fireEvent.click(r.getByRole("button", { name: "NoSQL Injection" }));
    expect(screen.getByText("Operator injection.")).toBeInTheDocument();            // the related rule opened
    expect(r.getByRole("link", { name: /Read about CWE-89 on MITRE/ })).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/89.html");
  });

  it("a rule with no recorded fix still explains how to verify and links its CWE", async () => {
    setup(usage());
    render(<RulesPage />);
    fireEvent.click(await screen.findByText("Open admin port"));
    const r = within(screen.getAllByTestId("remediation")[0]);
    expect(r.getByText(/No specific fix is recorded/)).toBeInTheDocument();
    expect(r.getByText(/Apply the change to the configuration file/)).toBeInTheDocument();
  });

  it("a rule with no severity gets no priority banner; with no CWE, no CWE link", async () => {
    setup(usage());
    render(<RulesPage />);
    fireEvent.click(await screen.findByText("Weak hash"));
    const r = within(screen.getByTestId("remediation"));
    expect(r.queryByText(/^Priority/)).toBeNull();
    expect(r.queryByRole("link", { name: /MITRE/ })).toBeNull();
  });
});
