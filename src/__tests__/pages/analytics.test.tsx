/**
 * Analytics page: shows the measured numbers from /api/analytics, refetches after a sign-off, and invents nothing.
 */
import React from "react";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { computeAnalytics } from "@/lib/orgAnalytics";

jest.mock("next/dynamic", () => () => () => null);
jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1" } }) }));
jest.mock("@/lib/realtime", () => ({ useScansRealtime: () => {} }));

const NOW = new Date().toISOString();
const h = (n: number) => new Date(Date.now() - n * 3600_000).toISOString();
const analytics = computeAnalytics({
  now: NOW, start: h(24 * 30), end: NOW,
  scans: [{ id: "s1", repo: "acme/api", pr_number: 3, pr_author: "alice", created_at: h(30), total_ai_percentage: 0.4, file_count: 5 }],
  violations: [
    { id: "v1", scan_id: "s1", file_path: "a.ts", risk_score: "CRITICAL", status: "resolved", created_at: h(30), resolved_at: h(27), sla_deadline: h(6) },
    { id: "v2", scan_id: "s1", file_path: "b.ts", risk_score: "HIGH", status: "open", created_at: h(30), resolved_at: null, sla_deadline: h(1) },
  ],
  attestations: [{ scan_id: "s1", file_path: "a.ts", risk_score: "CRITICAL", reviewer_email: "carol@acme.test", reviewer_github: "carol", created_at: h(27) }],
});
const calls: string[] = [];
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  authedFetch: jest.fn(async (url: string) => { calls.push(url); return { ...analytics, scope: "org" }; }),
}));

import AnalyticsPage from "@/app/analytics/page";

beforeEach(() => { calls.length = 0; });

describe("Analytics page", () => {
  it("shows measured values", async () => {
    render(<AnalyticsPage />);
    await screen.findByRole("region", { name: "Time to sign-off" });
    expect(calls[0]).toBe("/api/analytics?days=30");
    const sign = screen.getByRole("region", { name: "Time to sign-off" });
    expect(sign).toHaveTextContent("CRITICAL1 sign-off3.0hmedian");
    expect(screen.getByText("Findings opened").parentElement).toHaveTextContent("2");
    expect(screen.getAllByText("Open now")[0].parentElement).toHaveTextContent("1 past their deadline");
    expect(within(screen.getByRole("region", { name: "Reviewers" })).getByText("carol@acme.test")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Repositories" })).getByRole("link", { name: "acme/api" })).toHaveAttribute("href", "/repo/acme/api");
    // None of the old invented panels.
    expect(document.body.textContent).not.toMatch(/AI Adoption Forecast|Dev Speed vs Security|Risk Position|projected/i);
  });

  it("period switch and a sign-off both refetch", async () => {
    render(<AnalyticsPage />);
    await screen.findByRole("region", { name: "Time to sign-off" });
    fireEvent.click(screen.getByRole("button", { name: "90d" }));
    await waitFor(() => expect(calls).toContain("/api/analytics?days=90"));
    const before = calls.length;
    act(() => { window.dispatchEvent(new Event("tl:attestation")); });
    await waitFor(() => expect(calls.length).toBe(before + 1));
  });
});
