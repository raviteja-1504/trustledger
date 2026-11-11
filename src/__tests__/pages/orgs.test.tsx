/**
 * Organisations page: real numbers for your own organisation; a portfolio view for platform admins with health,
 * reasons, filters and sorting; plan usage meters with warnings; no dead links; creation only for those who may.
 */
import React from "react";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/PageSkeleton", () => ({ __esModule: true, default: ({ loading }: { loading: boolean }) => (loading ? <p>loading…</p> : null) }));
let role = "admin";
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-a", org_slug: "acme", org_name: "Acme", role, email: "a@x.io" } }) }));   // a fresh object each render, as an auth refresh can produce
jest.mock("@/lib/useRealData", () => ({ isSeedMode: () => false, authedFetch: jest.fn() }));

import OrgsPage from "@/app/orgs/page";
import { authedFetch } from "@/lib/useRealData";

jest.setTimeout(30_000);
const fetchMock = authedFetch as jest.Mock;
const ago = (d: number) => new Date(Date.now() - d * 86_400_000).toISOString();
const org = (id: string, name: string, over: Record<string, unknown> = {}) => ({
  id, slug: id, name, github_org: null, plan: "free", created_at: ago(200), is_current: false,
  scans_30d: 40, scans_prev_30d: 40, scans_this_month: 1, open_violations: 3, open_critical: 0, overdue: 0, member_count: 1, repo_count: 1,
  latest_risk: "LOW", latest_ai_pct: 0.2, last_scan: ago(1), ...over,
});
const respond = (orgs: unknown[], total = orgs.length) => fetchMock.mockImplementation(async (url: string, init?: { method?: string }) => {
  if (url === "/api/orgs" && init?.method === "POST") return { org: { id: "new" } };
  return { orgs, total };
});
const renderPage = async () => { render(<OrgsPage />); await screen.findByRole("heading", { level: 1 }); };
const cards = () => screen.getAllByRole("article");

beforeEach(() => { role = "admin"; fetchMock.mockReset(); });

describe("your own organisation (everyone)", () => {
  it("is shown as 'Your organisation' with real numbers, never undefined or NaN", async () => {
    respond([org("org-a", "Acme", { is_current: true, open_violations: 4, open_critical: 1, overdue: 2, latest_risk: "HIGH", latest_ai_pct: 0.36 })]);
    await renderPage();
    expect(screen.getByRole("heading", { level: 1, name: "Your organisation" })).toBeInTheDocument();
    const card = within(screen.getByTestId("org-org-a"));
    expect(card.getByText("Your organisation")).toBeInTheDocument();
    expect(card.getByText("4")).toBeInTheDocument();
    expect(card.getByText("1 critical · 2 overdue")).toBeInTheDocument();
    expect(card.getByText("36%")).toBeInTheDocument();
    expect(screen.getByTestId("org-org-a").textContent).not.toMatch(/undefined|NaN/);
  });

  it("has real actions, not a dead link, and no creation button or summary strip", async () => {
    respond([org("org-a", "Acme", { is_current: true, open_violations: 4 })]);
    await renderPage();
    const card = within(screen.getByTestId("org-org-a"));
    expect(card.getByRole("link", { name: "Open dashboard" })).toHaveAttribute("href", "/dashboard");
    expect(card.getByRole("link", { name: "Open violations (4)" })).toHaveAttribute("href", "/violations");
    expect(card.getByRole("link", { name: "Team" })).toHaveAttribute("href", "/settings/team");
    expect(card.getByRole("link", { name: "Plan & usage" })).toHaveAttribute("href", "/billing");
    expect(document.querySelector('a[href*="?org="]')).toBeNull();
    expect(screen.queryByRole("button", { name: /New organisation/ })).toBeNull();
    expect(screen.queryByRole("region", { name: "Across all organisations" })).toBeNull();
  });

  it("explains why it needs attention", async () => {
    respond([org("org-a", "Acme", { is_current: true, open_critical: 2, last_scan: ago(20), repo_count: 0 })]);
    await renderPage();
    const reasons = within(screen.getByRole("list", { name: "Acme: why it needs attention" })).getAllByRole("listitem").map(li => li.textContent);
    expect(reasons).toEqual(["2 critical violations still open", "No repositories connected yet. Import repositories to start scanning."]);
    expect(screen.getByText("At risk")).toHaveAttribute("data-health", "at_risk");
  });

  it("plan usage: a meter per quota, a message at the cap with a link to the usage page", async () => {
    respond([org("org-a", "Acme", { is_current: true, plan: "free", scans_this_month: 3, repo_count: 1, member_count: 1 })]);
    await renderPage();
    const usage = within(screen.getByLabelText("Acme: plan usage"));
    expect(usage.getByText("3 / 3")).toBeInTheDocument();
    expect(usage.getByText(/At the limit: all 3 scans on your plan are used/)).toBeInTheDocument();
    expect(usage.getAllByRole("link", { name: "See usage" })[0]).toHaveAttribute("href", "/billing");
  });

  it("a load failure says so and can be retried", async () => {
    fetchMock.mockRejectedValueOnce(new Error("Server unavailable"));
    respond([org("org-a", "Acme", { is_current: true })]);
    fetchMock.mockRejectedValueOnce(new Error("Server unavailable"));
    render(<OrgsPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Server unavailable");
    fetchMock.mockReset(); respond([org("org-a", "Acme", { is_current: true })]);
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByTestId("org-org-a")).toBeInTheDocument();
  });

  it("with no organisation at all, points to creating one", async () => {
    respond([]);
    await renderPage();
    expect(screen.getByText("No organisation yet")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Create your organisation/ })).toHaveAttribute("href", "/create-org");
  });
});

describe("a platform admin", () => {
  beforeEach(() => { role = "platform_admin"; });
  const portfolio = () => [
    org("org-a", "Acme", { is_current: true }),
    org("org-b", "Beta", { open_critical: 3, open_violations: 9, latest_risk: "CRITICAL" }),
    org("org-c", "Gamma", { last_scan: ago(20), plan: "free", member_count: 2, repo_count: 1, scans_this_month: 1 }),
    org("org-d", "Delta", { last_scan: ago(90), scans_30d: 0 }),
  ];

  it("sees a portfolio summary and every organisation, worst first", async () => {
    respond(portfolio());
    await renderPage();
    expect(screen.getByRole("heading", { level: 1, name: "Organisations" })).toBeInTheDocument();
    const summary = within(screen.getByRole("region", { name: "Across all organisations" }));
    expect(summary.getByText("4")).toBeInTheDocument();                       // organisations
    expect(summary.getByText("Open critical").previousElementSibling).toHaveTextContent("3");
    expect(summary.getByText("Need attention").previousElementSibling).toHaveTextContent("2");   // Beta at risk, Gamma watch
    expect(cards().map(c => within(c).getAllByRole("heading")[0].textContent)).toEqual(["Beta", "Gamma", "Delta", "Acme"]);
  });

  it("other organisations get an honest note instead of a dead 'View' link", async () => {
    respond(portfolio());
    await renderPage();
    const beta = within(screen.getByTestId("org-org-b"));
    expect(beta.queryByRole("link", { name: /Open dashboard|View/ })).toBeNull();
    expect(beta.getByText(/Overview only/)).toBeInTheDocument();
  });

  it("filters by health with live counts, and by text", async () => {
    respond(portfolio());
    await renderPage();
    const group = within(screen.getByRole("group", { name: "Filter by health" }));
    expect(group.getByRole("button", { name: /At risk 1/ })).toBeInTheDocument();
    fireEvent.click(group.getByRole("button", { name: /At risk/ }));
    expect(cards()).toHaveLength(1);
    fireEvent.click(group.getByRole("button", { name: /^All/ }));
    fireEvent.change(screen.getByLabelText("Search organisations"), { target: { value: "gam" } });
    expect(cards()).toHaveLength(1);
    expect(screen.getByTestId("org-org-c")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Search organisations"), { target: { value: "zzz" } });
    expect(screen.getByText("No organisation matches")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Clear the search and filters/ }));
    expect(cards()).toHaveLength(4);
  });

  it("sorts by name on request", async () => {
    respond(portfolio());
    await renderPage();
    fireEvent.change(screen.getByLabelText("Sort"), { target: { value: "name" } });
    expect(cards().map(c => within(c).getAllByRole("heading")[0].textContent)).toEqual(["Acme", "Beta", "Delta", "Gamma"]);
  });

  it("says when the list was cut at the cap", async () => {
    respond(portfolio(), 250);
    await renderPage();
    expect(screen.getByRole("status")).toHaveTextContent("Showing 4 of 250 organisations.");
  });

  it("creates an organisation, then reloads the list (no invented zero numbers)", async () => {
    respond(portfolio());
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: "+ New organisation" }));
    fireEvent.change(screen.getByPlaceholderText("Acme Corp"), { target: { value: "Zeta Inc" } });
    fireEvent.change(screen.getAllByPlaceholderText("acme-corp")[0], { target: { value: "Zeta Inc" } });
    const created = fetchMock.mock.calls.length;
    fireEvent.click(screen.getByRole("button", { name: "Create organisation" }));
    await waitFor(() => expect(fetchMock.mock.calls.length).toBeGreaterThan(created + 1));
    const post = fetchMock.mock.calls.find(c => c[1]?.method === "POST")!;
    expect(JSON.parse(post[1].body)).toMatchObject({ name: "Zeta Inc", slug: "zeta-inc" });
    expect(fetchMock.mock.calls.at(-1)![0]).toBe("/api/orgs");                 // reloaded
  });

  it("a refused creation shows why and keeps the form", async () => {
    respond(portfolio());
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: "+ New organisation" }));
    fireEvent.change(screen.getByPlaceholderText("Acme Corp"), { target: { value: "Zeta" } });
    fireEvent.change(screen.getAllByPlaceholderText("acme-corp")[0], { target: { value: "zeta" } });
    fetchMock.mockRejectedValueOnce(new Error("That slug is taken."));
    fireEvent.click(screen.getByRole("button", { name: "Create organisation" }));
    expect(await screen.findByText("That slug is taken.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create organisation" })).toBeEnabled();
  });
});

describe("tooltips", () => {
  it("health and metrics explain themselves on focus", async () => {
    respond([org("org-a", "Acme", { is_current: true, open_critical: 1 })]);
    await renderPage();
    const tip = (el: HTMLElement) => { fireEvent.focus(el); const t = screen.getByRole("tooltip").textContent ?? ""; fireEvent.blur(el); return t; };
    expect(tip(screen.getByText("At risk"))).toMatch(/Critical violations are open/);
    expect(tip(screen.getByText("Open violations").closest("[tabindex]") as HTMLElement)).toMatch(/still open or in review/);
  });
});
