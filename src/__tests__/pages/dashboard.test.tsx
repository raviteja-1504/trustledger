/**
 * Dashboard page: renders every section from real payloads, in order, and degrades panel by panel when a source
 * fails instead of breaking the page.
 */
import React from "react";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import type { DashboardData } from "@/types";

jest.mock("next/dynamic", () => () => () => null);
jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/NewScanPanel", () => ({ __esModule: true, default: () => null }));
jest.mock("@/components/setup/SetupGuide", () => ({ __esModule: true, default: () => <div>Setup guide</div> }));
jest.mock("@/components/RoleGate", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/realtime", () => ({ useScansRealtime: () => {} }));
jest.mock("@/lib/policy", () => ({ loadPolicy: () => ({ name: "Standard" }) }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1", org_name: "Acme", name: "Ada Lovelace", email: "ada@acme.test" } }) }));
let role = "admin";
jest.mock("@/lib/roles", () => ({
  useRole: () => ({ role, permissions: { canScan: true, canExportData: true } }),
  ROLE_LABELS: { admin: "Admin", developer: "Developer" },
  ROLE_COLORS: new Proxy({}, { get: () => ({ bg: "", text: "", ring: "", dot: "" }) }),
}));

const dashboard: DashboardData = {
  repos: [
    { repo: "acme/api", ai_pct: 0.6, attestation_rate: 0.5, last_scan: new Date().toISOString().slice(0, 10), scan_count: 4, file_count: 40, latest_scan_id: "s1", high_crit_count: 2 },
    { repo: "acme/web", ai_pct: 0.2, attestation_rate: 1, last_scan: "2026-01-01", scan_count: 1, file_count: 8, latest_scan_id: "s2", high_crit_count: 0 },
  ],
  overall_ai_pct: 0.5, attestation_rate: 0.5, unattested_deploy_count: 1, scan_count: 5, file_count: 48,
  risk_trend: [{ date: "2026-10-12", critical_count: 1, high_count: 2, medium_count: 3 }],
  risk_totals: { critical_count: 1, high_count: 2, medium_count: 3 },
  top_risk_files: [
    { repo: "acme/api", file_path: "src/auth.ts", ai_pct: 0.9, risk_score: "CRITICAL", attested: false, scan_id: "s1", pr_number: 7 },
    { repo: "acme/api", file_path: "src/db.ts", ai_pct: 0.4, risk_score: "HIGH", attested: true, attested_at: "2026-10-18T10:00:00Z", attested_by: "bob@acme.test", scan_id: "s1", pr_number: 7 },
  ],
  sla_breach_critical_count: 0, sla_breach_high_count: 0, sla_breach_files: [], connected_repo_count: 2,
};

let fail = new Set<string>();
const fetched: string[] = [];
jest.mock("@/lib/api", () => ({ api: { dashboard: jest.fn(async () => dashboard) } }));
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  authedFetch: jest.fn(async (url: string) => {
    fetched.push(url);
    const key = url.split("?")[0];
    if (fail.has(key)) throw new Error("down");
    if (key === "/api/violation-status") return { overrides: {} };
    if (key === "/api/secrets") return { findings: [{ status: "open", severity: "CRITICAL" }] };
    if (key === "/api/trust-score") return {
      score: { total: 612, band: "Fair", computed_at: "x", repos: [{ repo: "acme/api", score: 480, open_critical: 1, open_high: 0, review_coverage: 0.5, open_secrets: 1, last_scan: null }],
        dimensions: [{ key: "review", label: "Human review of risky code", weight: 0.2, value: 0.5, points: 100, max_points: 200, gain: 100, grade: "F", formula: "", facts: [], actions: [{ label: "Review 1 high-risk file", href: "/violations", gain: 100 }] }] },
      history: [],
    };
    if (key === "/api/shadow-ai") return { summary: { policy_configured: true, open_violations: 0, violations: 0, approved_usage: 1, unreviewed: 0, unidentified: 0, hints: 0, developers_with_violations: 0, compliance: 1, by_tool: [] } };
    if (key === "/api/evidence/collect") return { period_start: "a", period_end: "b", generated_at: "c", frameworks: [], gaps: [] };
    throw new Error(`unexpected ${url}`);
  }),
}));

import DashboardPage from "@/app/dashboard/page";
import { api } from "@/lib/api";

const dashboardCalls = () => (api.dashboard as jest.Mock).mock.calls;

beforeEach(() => {
  fail = new Set(); fetched.length = 0; role = "admin";
  (api.dashboard as jest.Mock).mockClear();
  localStorage.clear(); sessionStorage.clear();
});

describe("Dashboard sync after a sign-off", () => {
  const signOff = (file: string) => ({ type: "attestation", timestamp: new Date().toISOString(), repo: "acme/api", pr_number: 7, scan_id: "s1",
    overall_risk: "CRITICAL", file_count: 0, total_ai_pct: 0.9, file_path: file, reviewer_email: "ada@acme.test" });

  it("a sign-off event reloads the whole dashboard, bypassing the server cache", async () => {
    render(<DashboardPage />);
    await screen.findByRole("region", { name: "Review queue" });
    expect(dashboardCalls()).toHaveLength(1);
    expect(dashboardCalls()[0][4]).toBeFalsy();
    const trustBefore = fetched.filter(u => u.startsWith("/api/trust-score")).length;

    act(() => { window.dispatchEvent(new Event("tl:attestation")); });
    await waitFor(() => expect(dashboardCalls()).toHaveLength(2));
    expect(dashboardCalls()[1][4]).toBe(true);
    await waitFor(() => expect(fetched.filter(u => u.startsWith("/api/trust-score")).length).toBe(trustBefore + 1));
  });

  it("a sign-off in another tab (recorded in local storage) reloads it too", async () => {
    render(<DashboardPage />);
    await screen.findByRole("region", { name: "Review queue" });
    act(() => {
      localStorage.setItem("tl_local_activity", JSON.stringify([signOff("src/auth.ts")]));
      window.dispatchEvent(new StorageEvent("storage", { key: "tl_local_activity" }));
    });
    await waitFor(() => expect(dashboardCalls().length).toBeGreaterThanOrEqual(2));
    expect(dashboardCalls().at(-1)![4]).toBe(true);
  });

  it("coming back after signing off elsewhere bypasses the cache on the first load", async () => {
    sessionStorage.setItem("tl_dash_seen_signoff", "");
    localStorage.setItem("tl_local_activity", JSON.stringify([signOff("src/auth.ts")]));
    render(<DashboardPage />);
    await screen.findByRole("region", { name: "Review queue" });
    await waitFor(() => expect(dashboardCalls().some(c => c[4] === true)).toBe(true));
  });

  it("nothing new → no extra reloads", async () => {
    localStorage.setItem("tl_local_activity", JSON.stringify([signOff("src/auth.ts")]));
    render(<DashboardPage />);
    await screen.findByRole("region", { name: "Review queue" });
    act(() => { window.dispatchEvent(new Event("focus")); });
    await new Promise(r => setTimeout(r, 50));
    expect(dashboardCalls()).toHaveLength(1);
  });

  it("the activity list shows a sign-off once, even when also recorded locally", async () => {
    localStorage.setItem("tl_local_activity", JSON.stringify([{ ...signOff("src/db.ts"), timestamp: "2026-10-18T09:59:00Z" }]));
    render(<DashboardPage />);
    const activity = await screen.findByRole("region", { name: "Recent activity" });
    expect(within(activity).getAllByRole("link", { name: /Signed off db\.ts/ })).toHaveLength(1);
  });
});

describe("Dashboard page", () => {
  it("shows every section, in order, from real data", async () => {
    render(<DashboardPage />);
    await screen.findByRole("region", { name: "Review queue" });
    const order = ["Needs attention", "Trust Score", "Review queue", "AI tool usage", "Leaked secrets", "Audit evidence", "Repositories", "Recent activity"];
    const regions = screen.getAllByRole("region").map(r => r.getAttribute("aria-label"));
    expect(regions.filter(r => order.includes(r!))).toEqual(order);
    expect(screen.getByRole("heading", { name: /Ada/ })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("img", { name: "Trust Score 612 out of 1000" })).toBeInTheDocument());
    expect(screen.getByRole("link", { name: /Review 1 high-risk file/ })).toHaveAttribute("href", "/violations");
    expect(within(screen.getByRole("region", { name: "Review queue" })).getByRole("link", { name: /auth\.ts/ })).toHaveAttribute("href", "/pr/s1?attest=src%2Fauth.ts");
    await waitFor(() => expect(screen.getByRole("link", { name: /Open secrets/ })).toHaveTextContent("1"));
    expect(screen.getByText("480")).toBeInTheDocument();
    // Needs attention leads with the critical items from the same data.
    const attention = screen.getByRole("region", { name: "Needs attention" });
    await waitFor(() => expect(attention).toHaveTextContent("critical secret exposed"));
    expect(attention).toHaveTextContent("CRITICAL file awaiting attestation");
    expect(within(attention).getByRole("link", { name: /repo pending sign-off/ })).toHaveAttribute("href", "/repo/acme/api");
    // The headline numbers come before the Trust Score.
    const tile = screen.getByRole("link", { name: /Open secrets/ });
    expect(tile.compareDocumentPosition(screen.getByRole("region", { name: "Trust Score" })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(attention).getAllByRole("link", { name: /auth\.ts/ })[0]).toHaveAttribute("href", "/pr/s1?attest=src%2Fauth.ts");
  });

  // The server's unattested_deploy_count is a FILE count; dashboardLiveState replaces it with the repo count.
  it("'Repos awaiting sign-off' counts repos with a file still waiting, not files", async () => {
    const before = dashboard.unattested_deploy_count;
    dashboard.unattested_deploy_count = 5;                 // a FILE count from the server
    try {
      render(<DashboardPage />);
      const tile = await screen.findByRole("link", { name: /Repos awaiting sign-off/ });
      expect(tile).toHaveTextContent(/^\D*1\D/);           // only acme/api has an unsigned HIGH/CRITICAL file
    } finally { dashboard.unattested_deploy_count = before; }
  });

  it("a failing source only blanks its own panel", async () => {
    fail = new Set(["/api/trust-score", "/api/shadow-ai"]);
    render(<DashboardPage />);
    await screen.findByRole("region", { name: "Review queue" });
    await waitFor(() => expect(screen.getAllByText(/Couldn.t load this right now/).length).toBeGreaterThan(0));
    expect(screen.getByRole("img", { name: /Trust Score/ })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Repositories" })).toBeInTheDocument();
  });

  it("developers don't load or see org-wide audit evidence", async () => {
    role = "developer";
    render(<DashboardPage />);
    await screen.findByRole("region", { name: "Review queue" });
    expect(screen.queryByRole("region", { name: "Audit evidence" })).not.toBeInTheDocument();
    expect(fetched.some(u => u.startsWith("/api/evidence/collect"))).toBe(false);
    expect(screen.getByText(/My PRs/)).toBeInTheDocument();
  });
});
