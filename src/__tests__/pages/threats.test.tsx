/**
 * Threats: violations, alerts and incidents as tabs of one page, with an overview; the old addresses redirect.
 */
import React from "react";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/threats/ViolationsView", () => ({ __esModule: true, default: () => <div>VIOLATIONS VIEW</div> }));
jest.mock("@/components/threats/AlertsView", () => ({ __esModule: true, default: () => <div>ALERTS VIEW</div> }));
jest.mock("@/components/threats/IncidentsView", () => ({ __esModule: true, default: () => <div>INCIDENTS VIEW</div> }));
const profile = { org_id: "org-1", org_slug: "acme" };
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile }) }));
jest.mock("@/lib/offlineData", () => ({ readSeed: () => null }));
const dashboard = jest.fn();
jest.mock("@/lib/api", () => ({ api: { dashboard: (...a: unknown[]) => dashboard(...a) } }));
jest.mock("@/lib/violationStatuses", () => ({ fetchServerOverrides: async () => ({}), statusesOf: () => ({}) }));
const authedFetch = jest.fn();
jest.mock("@/lib/useRealData", () => ({ authedFetch: (...a: unknown[]) => authedFetch(...a), isSeedMode: () => false }));
const redirect = jest.fn();
jest.mock("next/navigation", () => ({ redirect: (p: string) => redirect(p) }));

import ThreatsPage from "@/app/threats/page";
import ViolationsRedirect from "@/app/violations/page";
import AlertsRedirect from "@/app/alerts/page";
import IncidentsRedirect from "@/app/incidents/page";

const hoursAgo = (h: number) => new Date(Date.now() - h * 3600_000).toISOString();
const DASH = {
  repos: [{ repo: "o/api", attestation_rate: 0, high_crit_count: 2 }], attestation_rate: 0, unattested_deploy_count: 2, overall_ai_pct: 0.5, risk_trend: [], scan_count: 1, file_count: 5,
  top_risk_files: [
    { repo: "o/api", file_path: "late.ts", scan_id: "s1", ai_pct: 0.5, risk_score: "CRITICAL", pr_number: 3, attested: false, detected_at: hoursAgo(30) },
    { repo: "o/api", file_path: "h.ts", scan_id: "s1", ai_pct: 0.5, risk_score: "HIGH", pr_number: 3, attested: false, detected_at: hoursAgo(2) },
  ],
};
function serve(over: { alerts?: unknown[]; incidents?: number; fail?: boolean } = {}) {
  dashboard.mockImplementation(async () => { if (over.fail) throw new Error("down"); return DASH; });
  authedFetch.mockImplementation(async (url: string) => {
    if (over.fail) throw new Error("down");
    if (url.startsWith("/api/alerts")) return { alerts: over.alerts ?? [{ id: "a1", title: "P1 secret committed", severity: "P1", scan_id: "s1", fired_at: hoursAgo(1) }] };
    if (url.startsWith("/api/incidents")) return { count: over.incidents ?? 1 };
    throw new Error(url);
  });
}
beforeEach(() => { dashboard.mockReset(); authedFetch.mockReset(); redirect.mockReset(); window.history.replaceState(null, "", "/threats"); });

describe("Threats page", () => {
  it("opens on an overview that counts all three stages", async () => {
    serve();
    render(<ThreatsPage />);
    const stages = await screen.findByLabelText("Stages");
    expect(within(stages).getByText("open violations")).toBeInTheDocument();
    expect(within(stages).getByText("alert firing")).toBeInTheDocument();
    expect(within(stages).getByText("open incident")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  });

  it("the tabs carry live counts", async () => {
    serve();
    render(<ThreatsPage />);
    await screen.findByLabelText("Stages");
    expect(screen.getByRole("tab", { name: /Alerts\s*1/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Incidents\s*1/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Violations\s*[1-9]/ })).toBeInTheDocument();
  });

  it("'Do first' leads with the incident, and each item opens its tab", async () => {
    serve();
    render(<ThreatsPage />);
    const first = within(await screen.findByRole("region", { name: "Do first" }));
    const items = first.getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("1 open incident");
    fireEvent.click(within(items[0]).getByRole("button"));
    expect(screen.getByText("INCIDENTS VIEW")).toBeInTheDocument();
    expect(window.location.search).toBe("?tab=incidents");
  });

  it("each tab shows its full view; the overview comes back with no tab in the address", async () => {
    serve();
    render(<ThreatsPage />);
    await screen.findByLabelText("Stages");
    fireEvent.click(screen.getByRole("tab", { name: /^Violations/ }));
    expect(screen.getByText("VIOLATIONS VIEW")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: /^Alerts/ }));
    expect(screen.getByText("ALERTS VIEW")).toBeInTheDocument();
    expect(screen.queryByText("VIOLATIONS VIEW")).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    expect(window.location.search).toBe("");
  });

  it("?tab= opens that tab (what the old addresses redirect to)", async () => {
    serve();
    window.history.replaceState(null, "", "/threats?tab=alerts");
    render(<ThreatsPage />);
    expect(await screen.findByText("ALERTS VIEW")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /^Alerts/ })).toHaveAttribute("aria-selected", "true");
  });

  it("says all clear when nothing is open", async () => {
    dashboard.mockResolvedValue({ ...DASH, top_risk_files: [], unattested_deploy_count: 0 });
    authedFetch.mockImplementation(async (url: string) => (url.startsWith("/api/alerts") ? { alerts: [] } : { count: 0 }));
    render(<ThreatsPage />);
    expect(await screen.findByText(/All clear/)).toBeInTheDocument();
  });

  it("if nothing could be loaded it says so and can retry", async () => {
    serve({ fail: true });
    render(<ThreatsPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("couldn't load the overview");
    serve();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    expect(await screen.findByLabelText("Stages")).toBeInTheDocument();
  });

  it("the incidents tab reminds of the list cap", async () => {
    serve();
    window.history.replaceState(null, "", "/threats?tab=incidents");
    render(<ThreatsPage />);
    expect(await screen.findByText(/most recent 1,000/)).toBeInTheDocument();
  });
});

describe("old addresses", () => {
  const sp = (o: Record<string, string | string[] | undefined> = {}) => ({ searchParams: Promise.resolve(o) });
  it("/violations, /alerts and /incidents redirect to their tab, keeping the query string", async () => {
    await ViolationsRedirect(sp({ severity: "CRITICAL" }));
    await AlertsRedirect(sp());
    await IncidentsRedirect(sp({ id: "inc-1" }));
    expect(redirect.mock.calls.map(c => c[0])).toEqual(["/threats?tab=violations&severity=CRITICAL", "/threats?tab=alerts", "/threats?tab=incidents&id=inc-1"]);
  });
});
