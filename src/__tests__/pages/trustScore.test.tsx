/**
 * Trust Score page: the score from /api/trust-score, plus dependencies, incidents and audit evidence beside it
 * (what the retired Security posture page added) -- each from its own source, "Couldn't load" when that fails --
 * and everything refreshes after a sign-off.
 */
import React from "react";
import { act, render, screen, waitFor, within } from "@testing-library/react";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/PageSkeleton", () => ({ __esModule: true, default: () => <div>loading</div> }));

let failDeps = false;
let total = 655;
const calls: string[] = [];
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  getAuthHeader: async () => ({}),
  authedFetch: jest.fn(async (url: string) => {
    calls.push(url);
    if (url.startsWith("/api/trust-score")) return {
      score: { total, band: "Fair", computed_at: new Date().toISOString(), repos: [],
        dimensions: [{ key: "sla", label: "Fix deadlines met", weight: 0.15, value: 0.2, points: 30, max_points: 150, gain: 120, grade: "F", formula: "f", facts: ["4 findings overdue"], actions: [{ label: "Resolve 4 overdue findings", href: "/sla", gain: 120 }] }] },
      history: [], history_available: true,
    };
    if (url === "/api/dependencies") { if (failDeps) throw new Error("down"); return { counts: { vulnerable: 3, hallucinated: 0, typosquatting: 0, critical: 1, exploits: 0, license_issues: 0 } }; }
    if (url.startsWith("/api/incidents")) return { incidents: [{ status: "active", severity: "P1" }, { status: "active", severity: "P2" }] };
    if (url.startsWith("/api/evidence/collect")) return { period_start: "a", period_end: "b", generated_at: "c",
      frameworks: [{ id: "soc2", name: "SOC 2", short: "SOC 2", status_counts: { pass: 2, partial: 0, fail: 1, not_tested: 0 }, controls: [1, 2, 3].map(i => ({ control_id: `c${i}`, control_name: "x", status: "pass" })) }],
      gaps: [{ key: "k", label: "Secrets", status: "fail", gaps: ["1 open"] }] };
    throw new Error(url);
  }),
}));

import TrustScorePage from "@/app/trust-score/page";

beforeEach(() => { failDeps = false; total = 655; calls.length = 0; });

describe("Trust Score page", () => {
  it("shows the score and, beside it, dependencies, incidents and audit evidence from their sources", async () => {
    render(<TrustScorePage />);
    expect(await screen.findByText("655")).toBeInTheDocument();
    const beside = await screen.findByRole("region", { name: "Beside the score" });
    await waitFor(() => expect(within(beside).getByRole("link", { name: "Dependencies" })).toHaveTextContent("3risky packages"));
    expect(within(beside).getByRole("link", { name: "Dependencies" })).toHaveAttribute("href", "/dependencies");
    const inc = within(beside).getByRole("link", { name: "Incidents" });
    expect(inc).toHaveTextContent("2active incidents");
    expect(inc).toHaveTextContent("At risk");
    const ev = within(beside).getByRole("link", { name: "Audit evidence" });
    expect(ev).toHaveTextContent("2/3");
    expect(ev).toHaveTextContent("Secrets: 1 open");
    expect(screen.getByRole("link", { name: /Resolve 4 overdue findings/ })).toHaveAttribute("href", "/sla");
  });

  it("a failing source shows 'Couldn't load', not a default number", async () => {
    failDeps = true;
    render(<TrustScorePage />);
    const beside = await screen.findByRole("region", { name: "Beside the score" });
    await waitFor(() => expect(within(beside).getByRole("link", { name: "Dependencies" })).toHaveTextContent("Couldn't load"));
    expect(within(beside).getByRole("link", { name: "Dependencies" })).toHaveTextContent("No data");
    expect(within(beside).getByRole("link", { name: "Incidents" })).toHaveTextContent("2");
  });

  it("a sign-off refreshes the score and the cards", async () => {
    render(<TrustScorePage />);
    await screen.findByText("655");
    const n = calls.filter(u => u.startsWith("/api/trust-score")).length;
    total = 702;
    act(() => { window.dispatchEvent(new Event("tl:attestation")); });
    expect(await screen.findByText("702")).toBeInTheDocument();
    expect(calls.filter(u => u.startsWith("/api/trust-score")).length).toBe(n + 1);
    expect(calls.filter(u => u === "/api/dependencies").length).toBe(2);
  });
});
