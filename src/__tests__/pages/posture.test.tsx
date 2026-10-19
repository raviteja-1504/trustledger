/**
 * Security posture page: the overall number is the Trust Score; every domain is from a real source; a failing source
 * shows "Couldn't load" instead of a made-up value.
 */
import React from "react";
import { render, screen, waitFor, within } from "@testing-library/react";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1" } }) }));
jest.mock("@/lib/realtime", () => ({ useScansRealtime: () => {} }));

let failDeps = false;
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  authedFetch: jest.fn(async (url: string) => {
    if (url.startsWith("/api/trust-score")) return {
      score: { total: 655, band: "Fair", computed_at: "x", repos: [],
        dimensions: [{ key: "sla", label: "Fix deadlines met", weight: 0.15, value: 0.2, points: 30, max_points: 150, gain: 120, grade: "F", formula: "", facts: ["4 findings overdue"], actions: [{ label: "Resolve 4 overdue findings", href: "/sla", gain: 120 }] }] },
      history: [{ day: "2026-10-17", total: 640 }, { day: "2026-10-19", total: 655 }],
    };
    if (url === "/api/dependencies") { if (failDeps) throw new Error("down"); return { counts: { vulnerable: 3, hallucinated: 0, typosquatting: 0, critical: 1, exploits: 0, license_issues: 0 } }; }
    if (url.startsWith("/api/incidents")) return { incidents: [{ status: "active", severity: "P1" }] };
    if (url.startsWith("/api/evidence/collect")) return { period_start: "a", period_end: "b", generated_at: "c", frameworks: [], gaps: [] };
    throw new Error(url);
  }),
}));

import PosturePage from "@/app/posture/page";

beforeEach(() => { failDeps = false; });

describe("Security posture page", () => {
  it("overall is the Trust Score; domains carry real values and link to their pages", async () => {
    render(<PosturePage />);
    const overall = await screen.findByRole("region", { name: "Overall posture" });
    await waitFor(() => expect(overall).toHaveTextContent("655"));
    expect(overall).toHaveTextContent("Fair");
    const sla = screen.getByRole("link", { name: "Fix deadlines" });
    expect(sla).toHaveTextContent("20%");
    expect(sla).toHaveTextContent("4 findings overdue");
    expect(sla).toHaveAttribute("href", "/sla");
    expect(screen.getByRole("link", { name: "Dependencies" })).toHaveTextContent("3risky packages"); // 3 vulnerable (1 of them critical)
    expect(screen.getByRole("link", { name: "Incidents" })).toHaveTextContent("At risk");
    expect(within(screen.getByRole("region", { name: "What to fix first" })).getByRole("link", { name: /Resolve 4 overdue findings/ })).toHaveAttribute("href", "/sla");
  });

  it("a failing source shows 'Couldn't load', not a default number", async () => {
    failDeps = true;
    render(<PosturePage />);
    await waitFor(() => expect(screen.getByRole("link", { name: "Dependencies" })).toHaveTextContent("Couldn't load"));
    expect(screen.getByRole("link", { name: "Dependencies" })).toHaveTextContent("No data");
  });
});
