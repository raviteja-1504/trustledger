/**
 * Settings → Repositories tab.
 */
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

const authedFetch = jest.fn();
jest.mock("@/lib/useRealData", () => ({ authedFetch: (...a: unknown[]) => authedFetch(...a) }));
let role = "admin";
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { role } }) }));

import RepositoriesTab from "@/components/settings/RepositoriesTab";

let repos: Array<{ id: string; repo_full_name: string; default_branch: string; is_active: boolean; created_at: string }>;
let github = { installed: true, accounts: ["raviteja-1504"], install_url: "https://github.com/apps/tl/installations/new" };

beforeEach(() => {
  jest.clearAllMocks();
  role = "admin";
  repos = [
    { id: "r1", repo_full_name: "raviteja-1504/trustledger", default_branch: "master", is_active: true, created_at: "" },
    { id: "r2", repo_full_name: "acme/payments-api", default_branch: "main", is_active: false, created_at: "" },
  ];
  github = { installed: true, accounts: ["raviteja-1504"], install_url: "https://github.com/apps/tl/installations/new" };
  authedFetch.mockImplementation(async (path: string, init?: RequestInit) => {
    if (path === "/api/repos" && !init) return { repos };
    if (path === "/api/repos/github") return github;
    if (path === "/api/repos" && init?.method === "PATCH") return { ok: true };
    if (path === "/api/repos?import=github") {
      repos = [...repos, { id: "r3", repo_full_name: "raviteja-1504/juiceshop-test", default_branch: "main", is_active: true, created_at: "" }];
      return { added: 1, already_connected: 2, total: 3 };
    }
    throw new Error("unexpected " + path);
  });
});

it("shows the GitHub App's installations and each repository's on/off state", async () => {
  render(<RepositoriesTab />);
  expect(await screen.findByText("On @raviteja-1504")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Add another account/ })).toHaveAttribute("href", "https://github.com/apps/tl/installations/new");
  expect(screen.getByRole("switch", { name: /raviteja-1504\/trustledger on/ })).toHaveAttribute("aria-checked", "true");
  expect(screen.getByRole("switch", { name: /acme\/payments-api off/ })).toHaveAttribute("aria-checked", "false");
  expect(screen.getByText("1")).toBeInTheDocument(); // 1 of 2 switched on
});

it("switching a repository sends the change", async () => {
  render(<RepositoriesTab />);
  fireEvent.click(await screen.findByRole("switch", { name: /acme\/payments-api off/ }));
  await waitFor(() => expect(authedFetch).toHaveBeenCalledWith("/api/repos", { method: "PATCH", body: JSON.stringify({ id: "r2", is_active: true }) }));
  expect(screen.getByRole("switch", { name: /acme\/payments-api on/ })).toHaveAttribute("aria-checked", "true");
});

it("a failed switch is rolled back and explained", async () => {
  authedFetch.mockImplementation(async (path: string, init?: RequestInit) => {
    if (init?.method === "PATCH") throw new Error("Only admins can switch repositories on or off.");
    if (path === "/api/repos") return { repos };
    return github;
  });
  render(<RepositoriesTab />);
  fireEvent.click(await screen.findByRole("switch", { name: /raviteja-1504\/trustledger on/ }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Only admins");
  expect(screen.getByRole("switch", { name: /raviteja-1504\/trustledger on/ })).toHaveAttribute("aria-checked", "true");
});

it("Import from GitHub reports what it added and shows the new repository", async () => {
  render(<RepositoriesTab />);
  fireEvent.click(await screen.findByRole("button", { name: "Import from GitHub" }));
  expect(await screen.findByRole("status")).toHaveTextContent("Added 1 repository from GitHub. 2 were already here.");
  expect(await screen.findByText("raviteja-1504/juiceshop-test")).toBeInTheDocument();
});

it("without the GitHub App: install link, import disabled", async () => {
  github = { installed: false, accounts: [], install_url: "https://github.com/apps/tl/installations/new" };
  repos = [];
  render(<RepositoriesTab />);
  expect(await screen.findByText("Not installed")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Install on GitHub/ })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Import from GitHub" })).toBeDisabled();
  expect(screen.getByText(/Install the GitHub App above, then import/)).toBeInTheDocument();
});

it("non-admins see the list read-only", async () => {
  role = "developer";
  render(<RepositoriesTab />);
  const list = await screen.findByRole("list");
  for (const sw of within(list).getAllByRole("switch")) expect(sw).toBeDisabled();
  expect(screen.queryByRole("button", { name: "Import from GitHub" })).not.toBeInTheDocument();
  expect(screen.getByText("Only admins can import or switch repositories.")).toBeInTheDocument();
});

describe("plan limit", () => {
  const withPlan = (repos_active: number, limit: number) => {
    const base = authedFetch.getMockImplementation()!;
    authedFetch.mockImplementation(async (path: string, init?: RequestInit) => path === "/api/billing"
      ? { limits: { repos: limit, members: 5, scans: 1, attestations: 1, reports: 1 }, usage: { repos_active, members: 1, scans_this_month: 0, attestations_this_month: 0, reports_this_month: 0 } }
      : base(path, init));
  };
  it("shows the repositories the plan allows, and warns before the limit", async () => {
    withPlan(9, 10);
    render(<RepositoriesTab />);
    expect(await screen.findByRole("progressbar", { name: "Active repositories on your plan" })).toHaveAttribute("aria-valuetext", "9 of 10");
    expect(screen.getByText(/1 of 10 repositories left on your plan/)).toBeInTheDocument();
  });
  it("says so when the plan is full", async () => {
    withPlan(10, 10);
    render(<RepositoriesTab />);
    expect(await screen.findByText(/At the limit: all 10 repositories on your plan are used/)).toBeInTheDocument();
  });
  it("works without it: no meter if the plan can't be loaded, and non-admins don't ask", async () => {
    render(<RepositoriesTab />);
    await screen.findByText("On @raviteja-1504");
    expect(screen.queryByRole("progressbar")).toBeNull();
    role = "developer";
    authedFetch.mockClear();
    render(<RepositoriesTab />);
    await screen.findAllByText("On @raviteja-1504");
    expect(authedFetch.mock.calls.some(c => c[0] === "/api/billing")).toBe(false);
  });
});
