/**
 * Report section 3a: the period's sign-off records -- when, what, why, how -- from /api/attest.
 */
import React from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";

let fail = false;
const urls: string[] = [];
const rec = (id: string, repo: string, o: Record<string, unknown> = {}) => ({
  id, signed_at: "2026-10-05T09:30:00Z", repo, pr_number: 7, commit_sha: "abcdef12345", branch: "feat", scan_id: `scan-${id}`, scanned_at: "2026-10-05T03:30:00Z",
  file_path: `src/${id}.ts`, risk_score: "CRITICAL", findings: ["sql-injection"], ai_percentage: 0.8, reviewer_email: "rev@acme.test", reviewer_github: "rev",
  pr_author: "ada", independence: "independent", hours_to_signoff: 6, payload_hash: "0123456789abcdef0123", repeat: false, ...o,
});
jest.mock("@/lib/useRealData", () => ({
  authedFetch: jest.fn(async (url: string) => {
    urls.push(url);
    if (fail) throw new Error("down");
    return {
      records: [rec("pay", "acme/api"), rec("web", "acme/web", { independence: "self", pr_number: 0, findings: [], hours_to_signoff: 0.2 })],
      summary: { records: 2, files: 2, repos: ["acme/api", "acme/web"], reviewers: ["rev@acme.test"], independent: 1, self: 1, unknown: 0,
        first: "2026-10-02T00:00:00Z", last: "2026-10-05T09:30:00Z", median_hours: 3, by_risk: { CRITICAL: 2 } },
      period: { start: "2026-10-01T00:00:00.000Z", end: "2026-10-31T23:59:59.999Z" }, scope: "org",
    };
  }),
}));

import PeriodAttestations, { fmtDuration } from "@/components/reports/PeriodAttestations";

beforeEach(() => { fail = false; urls.length = 0; });

describe("PeriodAttestations", () => {
  it("states the period and explains each record: when, what, why, who & how", async () => {
    render(<PeriodAttestations start="2026-10-01" end="2026-10-31" color="#000" />);
    const head = await screen.findByRole("region", { name: "Sign-offs in this period" });
    expect(urls[0]).toBe("/api/attest?since=2026-10-01&until=2026-10-31");
    expect(head).toHaveTextContent("2 sign-off records from 1 Oct 2026 to 31 Oct 2026 — 2 files in 2 repositories, by 1 reviewer");
    expect(head).toHaveTextContent("Typical time from scan to sign-off: 3 h");
    expect(head).toHaveTextContent("1 independent · 1 self-approved · 0 unknown");
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("acme/api · PR #7 · abcdef1 · feat");
    expect(within(rows[0]).getByRole("link", { name: "sql-injection" })).toHaveAttribute("href", "/rules#sql-injection");
    expect(rows[0]).toHaveTextContent("Independent");
    expect(rows[0]).toHaveTextContent("6 h");
    expect(rows[0]).toHaveTextContent("0123456789ab…");
    expect(rows[1]).toHaveTextContent("direct push");
    expect(rows[1]).toHaveTextContent("Self-approved");
    expect(rows[1]).toHaveTextContent("risk level from the scan");
    expect(screen.getByText(/can.t be edited or deleted/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "acme/web" } });
    expect(screen.getAllByRole("row").slice(1)).toHaveLength(1);
  });

  it("a failed load says so", async () => {
    fail = true;
    render(<PeriodAttestations start="2026-10-01" end="2026-10-31" color="#000" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load sign-off records");
  });

  it("durations read naturally", () => {
    expect(fmtDuration(null)).toBe("—");
    expect(fmtDuration(0.2)).toBe("12 min");
    expect(fmtDuration(0)).toBe("1 min");
    expect(fmtDuration(30)).toBe("30 h");
    expect(fmtDuration(72)).toBe("3 days");
  });
});
