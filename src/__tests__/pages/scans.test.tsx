/**
 * Scan history page: real scans for the period (all pages), superseded rows, sign-off status from the server, and an
 * error -- never demo scans -- when loading fails.
 */
import React from "react";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1" } }) }));
jest.mock("@/lib/realtime", () => ({ useScansRealtime: () => {} }));
jest.mock("next/navigation", () => ({ useSearchParams: () => null }));

const now = Date.now();
const iso = (h: number) => new Date(now - h * 3600_000).toISOString();
const scan = (id: string, o: Record<string, unknown> = {}) => ({ scan_id: id, repo: "acme/api", pr_number: 7, commit_sha: "abcdef1234", branch: "feat/x",
  overall_risk: "HIGH", total_ai_percentage: 0.4, file_count: 3, high_crit_count: 2, attested_count: 1, attested_files: ["a.ts"], created_at: iso(1), triggered_by: "webhook", ...o });
let fail = false;
const urls: string[] = [];
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  authedFetch: jest.fn(async (url: string) => {
    urls.push(url);
    if (url.startsWith("/api/violation-status")) return { overrides: { "high::new::b.ts": { status: "resolved" } } };
    if (fail) throw new Error("boom");
    const before = new URLSearchParams(url.split("?")[1]).get("before");
    if (!before) return { scans: [scan("new"), scan("old", { created_at: iso(30), attested_files: [] })], next_before: iso(30) };
    return { scans: [scan("push", { pr_number: 0, overall_risk: "CRITICAL", created_at: iso(50), high_crit_count: 1, attested_files: [] })], next_before: null };
  }),
}));

import ScansPage from "@/app/scans/page";

// Two paged fetches plus a status fetch before the list renders; under full-suite load that can exceed the 1s default.
jest.setTimeout(30_000);
const WAIT = { timeout: 10_000 };

beforeEach(() => { fail = false; urls.length = 0; });

describe("Scan history page", () => {
  it("loads every page of the period, marks superseded scans, and counts sign-offs with resolved findings", async () => {
    render(<ScansPage />);
    const list = await screen.findByRole("region", { name: "Scans" }, WAIT);
    expect(urls.filter(u => u.startsWith("/api/scans"))).toHaveLength(2);
    expect(urls[0]).toMatch(/since=/);
    const rows = within(list).getAllByRole("link");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent("2/2 high-risk signed off");     // a.ts attested + b.ts resolved
    expect(rows[1]).toHaveTextContent("Superseded by a newer push");
    expect(rows[2]).toHaveTextContent("Direct push");
    expect(rows[2]).toHaveTextContent("0/1 high-risk signed off");
    expect(rows[0]).toHaveAttribute("href", "/pr/new");
    expect(screen.getByText("Fully signed off").parentElement).toHaveTextContent("1/2");

    fireEvent.change(screen.getByLabelText("Review"), { target: { value: "pending" } });
    expect(within(list).getAllByRole("link").map(a => a.getAttribute("href"))).toEqual(["/pr/push"]);
  });

  it("a failed load shows an error, never demo scans", async () => {
    fail = true;
    render(<ScansPage />);
    expect(await screen.findByRole("alert", {}, WAIT)).toHaveTextContent("Couldn't load scans");
    expect(document.body.textContent).not.toMatch(/payments-api|fraud-detection/);
  });

  it("a sign-off refreshes the list", async () => {
    render(<ScansPage />);
    await screen.findByRole("region", { name: "Scans" }, WAIT);
    const n = urls.length;
    act(() => { window.dispatchEvent(new Event("tl:attestation")); });
    await waitFor(() => expect(urls.length).toBeGreaterThan(n), WAIT);
  });
});
