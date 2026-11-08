import React from "react";
import { render, screen, fireEvent, waitFor, within, configure } from "@testing-library/react";
import "@testing-library/jest-dom";

const toastError = jest.fn();
let canTriage = true;
const profile = { org_id: "org-1" };
jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/PageSkeleton", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/toast", () => ({ useToastHelpers: () => ({ success: jest.fn(), error: toastError, info: jest.fn(), warn: jest.fn() }) }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile }) }));
jest.mock("@/lib/roles", () => ({ useRole: () => ({ permissions: { canTriage } }) }));
jest.mock("@/lib/api", () => ({ api: { settings: jest.fn().mockResolvedValue({ members: [{ email: "ana@example.com" }, { email: "bo@example.com" }] }) } }));
jest.mock("@/lib/offlineData", () => ({ readSeed: () => null }));
jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn(), isSeedMode: () => false }));

import { authedFetch } from "@/lib/useRealData";
import RiskRegisterPage from "@/app/risk-register/page";
import type { RiskItem } from "@/lib/riskRegister";

const mockFetch = authedFetch as jest.MockedFunction<typeof authedFetch>;
jest.setTimeout(30000);
// Under a loaded full-suite run the first render can take longer than the default 1 s wait.
configure({ asyncUtilTimeout: 10_000 });

const today = new Date();
const dayStr = (offset: number) => new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() + offset)).toISOString().slice(0, 10);
const risk = (o: Partial<RiskItem> & { id: string }): RiskItem => ({
  title: o.id, description: "desc", category: "ai-code", likelihood: 3, impact: 3, status: "open", treatment: "mitigate", owner: "unassigned",
  mitigation: "plan", identified_at: dayStr(-3), auto_derived: true, notes: [], ...o,
});
const RISKS: RiskItem[] = [
  risk({ id: "DR-CRIT", title: "2 CRITICAL files unattested in api", likelihood: 5, impact: 5, repo: "o/api", related_link: "/dashboard#review-queue" }),
  risk({ id: "DR-HIGH", title: "HIGH files awaiting attestation in web", likelihood: 4, impact: 4, owner: "ana@example.com", due_date: dayStr(-2), repo: "o/web", status: "mitigating" }),
  risk({ id: "MR-1", title: "Vendor risk", auto_derived: false, category: "compliance", owner: "bo@example.com" }),
  risk({ id: "DR-OLD", title: "Old secrets risk", status: "closed", likelihood: 5, impact: 5, repo: "o/api" }),
];
type Reg = { risks: RiskItem[]; basis: Record<string, unknown> | null; sync: Record<string, number> | null; syncError: string | null; capped: { shown: number; total: number } | null; canEdit: boolean; generatedAt: string };
const REG: Reg = {
  risks: RISKS,
  basis: { repos: 2, highCriticalFiles: 10, attestedFiles: 6, closedWithoutAttestation: 1, waitingFiles: 3, latestScanAt: new Date(Date.now() - 2 * 3600_000).toISOString() },
  sync: { inserted: 1, updated: 0, reopened: 0, closed: 2 }, syncError: null, capped: null, canEdit: true, generatedAt: new Date().toISOString(),
};

const setup = (over: Partial<Reg> = {}) => {
  mockFetch.mockImplementation((async (url: string, init?: { method?: string }) => {
    if (url === "/api/risk-register") return { ...REG, ...over };
    if (url === "/api/risk-register/state") return { risk: {} };
    throw new Error(`unexpected ${url} ${init?.method ?? ""}`);
  }) as never);
};
const patchCalls = () => mockFetch.mock.calls.filter(([u, i]) => u === "/api/risk-register/state" && (i as { method?: string })?.method === "PATCH").map(([, i]) => JSON.parse((i as { body: string }).body));
const rowIds = () => Array.from(document.querySelectorAll("[id^='risk-']")).map(e => e.id.replace("risk-", ""));

beforeEach(() => { mockFetch.mockReset(); toastError.mockReset(); canTriage = true; });

describe("RiskRegisterPage", () => {
  it("loads the whole register in ONE request (no dashboard, scan or sync chain)", async () => {
    setup();
    render(<RiskRegisterPage />);
    expect((await screen.findAllByText("2 CRITICAL files unattested in api")).length).toBeGreaterThan(0);
    expect(screen.getByText("Risk Register")).toBeInTheDocument();
    expect(mockFetch.mock.calls.map(c => c[0])).toEqual(["/api/risk-register"]);
  });

  it("says what the register is based on, so it can be checked against the attestations", async () => {
    setup();
    render(<RiskRegisterPage />);
    const basis = await screen.findByTestId("register-basis");
    expect(basis).toHaveTextContent("2 repositories, latest scan 2h ago");
    expect(basis).toHaveTextContent("Of 10 high/critical files: 6 attested, 1 closed without a sign-off, 3 waiting");
    expect(basis).toHaveTextContent("Register updated: 1 new, 2 closed because their files are now attested or fixed");
  });

  it("summarises from the active risks: open, critical, overdue, unassigned", async () => {
    setup();
    render(<RiskRegisterPage />);
    const s = within(await screen.findByRole("region", { name: "Register summary" }));
    const val = (label: string) => s.getByText(label).closest("div")!.parentElement!.querySelector("p")!.textContent;
    expect(val("Open Risks")).toBe("2");              // DR-CRIT and MR-1 (DR-HIGH is mitigating, DR-OLD closed)
    expect(val("Critical")).toBe("1");                // the closed 25 is not counted
    expect(val("Overdue")).toBe("1");
    expect(val("Unassigned")).toBe("1");
  });

  it("'Act on first' leads with the overdue risk, then the critical one, with the reasons", async () => {
    setup();
    render(<RiskRegisterPage />);
    const focus = within(await screen.findByRole("region", { name: "Act on first" }));
    const items = focus.getAllByRole("listitem").map(li => li.textContent);
    expect(items[0]).toContain("HIGH files awaiting attestation in web");
    expect(items[0]).toContain("Overdue by 2 days");
    expect(items[1]).toContain("2 CRITICAL files unattested in api");
    expect(items[1]).toContain("Nobody owns it");
    fireEvent.click(within(focus.getAllByRole("listitem")[1]).getByRole("button"));
    expect(document.getElementById("risk-DR-CRIT")!.querySelector("button")).toHaveAttribute("aria-expanded", "true");
  });

  it("shows active risks by default; closed ones are history under their own tab", async () => {
    setup();
    render(<RiskRegisterPage />);
    await screen.findByText("Vendor risk");
    expect(rowIds()).toEqual(["DR-CRIT", "DR-HIGH", "MR-1"]);                          // highest score first, no closed
    fireEvent.click(screen.getByRole("button", { name: /^Closed/ }));
    expect(rowIds()).toEqual(["DR-OLD"]);
    fireEvent.click(screen.getByRole("button", { name: /^All/ }));
    expect(rowIds()).toHaveLength(4);
  });

  it("filters by repository, owner and search, and clears them", async () => {
    setup();
    render(<RiskRegisterPage />);
    await screen.findByText("Vendor risk");
    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "o/web" } });
    expect(rowIds()).toEqual(["DR-HIGH"]);
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    fireEvent.change(screen.getByLabelText("Owner"), { target: { value: "bo@example.com" } });
    expect(rowIds()).toEqual(["MR-1"]);
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    fireEvent.change(screen.getByLabelText("Search risks"), { target: { value: "vendor" } });
    expect(rowIds()).toEqual(["MR-1"]);
    fireEvent.change(screen.getByLabelText("Search risks"), { target: { value: "zzz" } });
    expect(screen.getByText("No risks match this filter")).toBeInTheDocument();
  });

  it("a heat map cell filters to that likelihood and impact; clicking it again clears", async () => {
    setup();
    render(<RiskRegisterPage />);
    await screen.findByText("Vendor risk");
    fireEvent.click(screen.getByRole("button", { name: "Likelihood 4, impact 4: 1 active risk" }));
    expect(rowIds()).toEqual(["DR-HIGH"]);
    fireEvent.click(screen.getByRole("button", { name: "Likelihood 4, impact 4: 1 active risk" }));
    expect(rowIds()).toHaveLength(3);
    expect(screen.getByRole("button", { name: "Likelihood 1, impact 1: 0 active risks" })).toBeDisabled();
  });

  it("exposure bars filter by repository", async () => {
    setup();
    render(<RiskRegisterPage />);
    await screen.findByText("Vendor risk");
    fireEvent.click(screen.getByTitle("Filter to web"));
    expect(rowIds()).toEqual(["DR-HIGH"]);
  });

  it("changing the owner saves owner_email (the column), not 'owner'", async () => {
    setup();
    render(<RiskRegisterPage />);
    await screen.findByRole("region", { name: "Act on first" });
    fireEvent.click(within(document.getElementById("risk-DR-CRIT")!).getByRole("button", { name: /2 CRITICAL files/ }));
    const detail = document.getElementById("risk-DR-CRIT")!;
    await waitFor(() => expect(within(detail).getByLabelText("Owner")).toContainElement(within(detail).getByRole("option", { name: "ana" })));
    fireEvent.change(within(detail).getByLabelText("Owner"), { target: { value: "ana@example.com" } });
    await waitFor(() => expect(patchCalls()).toHaveLength(1));
    expect(patchCalls()[0]).toEqual({ external_id: "DR-CRIT", patch: { owner_email: "ana@example.com" } });
    expect(within(detail).getByLabelText("Owner")).toHaveValue("ana@example.com");
  });

  it("a status change is shown at once and saved; a failed save puts it back and says so", async () => {
    setup();
    render(<RiskRegisterPage />);
    fireEvent.click(await screen.findByText("Vendor risk"));
    mockFetch.mockImplementation((async (url: string) => { if (url === "/api/risk-register/state") throw new Error("Not allowed"); return REG; }) as never);
    const detail = document.getElementById("risk-MR-1")!;
    fireEvent.change(within(detail).getByLabelText("Status"), { target: { value: "accepted" } });
    await waitFor(() => expect(toastError).toHaveBeenCalledWith("Couldn't update risk", "Not allowed"));
    expect(within(detail).getByLabelText("Status")).toHaveValue("open");
  });

  it("saves a note with the date", async () => {
    setup();
    render(<RiskRegisterPage />);
    fireEvent.click(await screen.findByText("Vendor risk"));
    const detail = document.getElementById("risk-MR-1")!;
    fireEvent.change(within(detail).getByLabelText("Add a note"), { target: { value: "Checked with vendor" } });
    fireEvent.click(within(detail).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(patchCalls()).toHaveLength(1));
    expect(patchCalls()[0].patch.notes[0]).toMatch(/: Checked with vendor$/);
    expect(within(detail).getByText(/Checked with vendor/)).toBeInTheDocument();
  });

  it("adds a manual risk, then it is listed", async () => {
    setup();
    render(<RiskRegisterPage />);
    await screen.findByText("Vendor risk");
    fireEvent.click(screen.getByRole("button", { name: "+ Add Risk" }));
    fireEvent.change(screen.getByLabelText(/^Title/), { target: { value: "Laptop theft" } });
    fireEvent.click(screen.getByRole("button", { name: "Add to Register" }));
    const newId = () => rowIds().find(i => i.startsWith("MR-") && i !== "MR-1");
    await waitFor(() => expect(newId()).toBeDefined());
    expect(within(document.getElementById(`risk-${newId()}`)!).getByText("Laptop theft")).toBeInTheDocument();
    const post = mockFetch.mock.calls.find(([u, i]) => u === "/api/risk-register/state" && (i as { method?: string })?.method === "POST")!;
    expect(JSON.parse((post[1] as { body: string }).body)).toMatchObject({ title: "Laptop theft", likelihood: 3, impact: 3 });
  });

  it("a viewer who cannot triage sees no edit controls and is told why", async () => {
    setup({ canEdit: false, sync: null });
    render(<RiskRegisterPage />);
    fireEvent.click(await screen.findByText("Vendor risk"));
    expect(screen.queryByRole("button", { name: "+ Add Risk" })).toBeNull();
    expect(within(document.getElementById("risk-MR-1")!).getByLabelText("Status")).toBeDisabled();
    expect(screen.getByText(/Changing risks needs the security reviewer role/)).toBeInTheDocument();
  });

  it("past the 500-risk cap it says how many are shown and how many exist", async () => {
    setup({ capped: { shown: 500, total: 730 } });
    render(<RiskRegisterPage />);
    expect(await screen.findByText("Showing 500 of 730 risks.")).toBeInTheDocument();
  });

  it("warns when a sync could not record the register", async () => {
    setup({ syncError: "The register couldn't be recorded just now." });
    render(<RiskRegisterPage />);
    expect(await screen.findByText("The register couldn't be recorded just now.")).toBeInTheDocument();
  });

  it("a load failure is shown with Try again, which reloads", async () => {
    mockFetch.mockRejectedValueOnce(new Error("Server busy"));
    setup();
    mockFetch.mockReset();
    mockFetch.mockRejectedValueOnce(new Error("Server busy")).mockResolvedValue(REG as never);
    render(<RiskRegisterPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Server busy");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Vendor risk")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("an empty register explains why", async () => {
    setup({ risks: [] });
    render(<RiskRegisterPage />);
    expect(await screen.findByText("No risks match this filter")).toBeInTheDocument();
    expect(screen.getByText(/Every high\/critical file is attested/)).toBeInTheDocument();
  });

  it("shows Export and the heat map", async () => {
    setup();
    render(<RiskRegisterPage />);
    await screen.findByText("Vendor risk");
    expect(screen.getByText("Export")).toBeInTheDocument();
    expect(screen.getByText("Risk Heat Map")).toBeInTheDocument();
  });
});
