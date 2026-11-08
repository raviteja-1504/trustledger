/**
 * Team: admins see how many seats the plan has before they invite someone past it.
 */
import React from "react";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
let canManageUsers = true;
jest.mock("@/lib/roles", () => ({
  ...jest.requireActual("@/lib/roles"),
  useRole: () => ({ permissions: { canManageUsers } }),
}));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { user_id: "u1", email: "me@x.com", role: "admin" } }) }));
const authedFetch = jest.fn();
jest.mock("@/lib/useRealData", () => ({ authedFetch: (...a: unknown[]) => authedFetch(...a), isSeedMode: () => false }));

import TeamPage from "@/app/settings/team/page";

const members = Array.from({ length: 5 }, (_, i) => ({ user_id: `u${i}`, email: `m${i}@x.com`, name: `M${i}`, role: "developer", created_at: "2026-01-01T00:00:00Z" }));
const serve = (limit: number, usedMembers = 5) => authedFetch.mockImplementation(async (path: string) => {
  if (path === "/api/team") return { members };
  if (path === "/api/billing") return { limits: { members: limit, repos: 1, scans: 1, attestations: 1, reports: 1 }, usage: { members: usedMembers, repos_active: 0, scans_this_month: 0, attestations_this_month: 0, reports_this_month: 0 } };
  if (path === "/api/custom-roles") return { roles: [], assignments: {} };
  return {};
});
beforeEach(() => { authedFetch.mockReset(); canManageUsers = true; });

it("shows seats used against the plan and says when the plan is full", async () => {
  serve(5);
  render(<TeamPage />);
  expect(await screen.findByRole("progressbar", { name: "Team seats" })).toHaveAttribute("aria-valuetext", "5 of 5");
  expect(screen.getByText(/At the limit: all 5 members on your plan are used/)).toBeInTheDocument();
});

it("warns before the last seats go", async () => {
  serve(6);
  render(<TeamPage />);
  expect(await screen.findByText(/1 of 6 members left on your plan/)).toBeInTheDocument();
});

it("is not shown to people who cannot invite", async () => {
  canManageUsers = false;
  serve(5);
  render(<TeamPage />);
  await screen.findAllByText(/member/i);
  expect(screen.queryByRole("progressbar", { name: "Team seats" })).toBeNull();
  expect(authedFetch.mock.calls.some(c => c[0] === "/api/billing")).toBe(false);
});
