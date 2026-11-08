/**
 * Billing shows each plan quota as a meter that warns before the limit and says what happens at it, and the rate limits
 * every plan has.
 */
import React from "react";
import { render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/PageSkeleton", () => ({ __esModule: true, default: ({ loading, children }: { loading?: boolean; children?: React.ReactNode }) => (loading ? <div>loading</div> : <>{children}</>) }));
jest.mock("@/lib/toast", () => ({ useToastHelpers: () => ({ success: jest.fn(), error: jest.fn(), info: jest.fn(), warning: jest.fn(), warn: jest.fn() }) }));
const profile = { org_id: "org-1", org_name: "Acme" };
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile }) }));
jest.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams() }));
let usage: Record<string, number> = {};
jest.mock("@/lib/useRealData", () => ({ isSeedMode: () => false, authedFetch: jest.fn(async () => ({
  org: { name: "Acme", plan: "starter", member_since: "2026-01-01T00:00:00Z" },
  limits: { scans: 1000, attestations: 5000, repos: 10, members: 5, reports: 20, price: 99 },
  usage: { scans_this_month: 100, attestations_this_month: 100, repos_active: 3, members: 2, reports_this_month: 1, scans_all_time: 5, attestations_all_time: 5, ...usage },
  period: { start: "2026-11-01T00:00:00Z", end: "2026-11-08T00:00:00Z" },
})) }));

import BillingPage from "@/app/billing/page";

describe("Billing limits", () => {
  it("shows each quota as a meter", async () => {
    usage = {};
    render(<BillingPage />);
    expect(await screen.findByRole("progressbar", { name: "Scans this month" })).toHaveAttribute("aria-valuetext", "100 of 1,000");
    for (const l of ["Attestations this month", "Active repositories", "Team members", "Reports generated"]) expect(screen.getByRole("progressbar", { name: l })).toBeInTheDocument();
  });

  it("warns from 80% and says what is left", async () => {
    usage = { members: 4 };                                                      // 4 of 5
    render(<BillingPage />);
    await screen.findByRole("progressbar", { name: "Team members" });
    expect(screen.getByText(/1 of 5 members left on your plan/)).toBeInTheDocument();
  });

  it("says plainly when a quota is used up or exceeded", async () => {
    usage = { repos_active: 10, reports_this_month: 25 };
    render(<BillingPage />);
    await screen.findByRole("progressbar", { name: "Active repositories" });
    expect(screen.getByText(/At the limit: all 10 repositories on your plan are used/)).toBeInTheDocument();
    expect(screen.getByText(/Over the limit: 25 reports against 20 on your plan/)).toBeInTheDocument();
  });

  it("lists the rate limits that apply to every plan", async () => {
    usage = {};
    render(<BillingPage />);
    const rates = within(await screen.findByLabelText("Rate limits"));
    expect(rates.getByText("60 scan submissions per organisation per minute")).toBeInTheDocument();
    expect(rates.getByText("1 rescan of the same pull request per minute")).toBeInTheDocument();
  });
});
