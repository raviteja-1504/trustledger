/**
 * Repository page: real data from /api/repos/summary, sign-off links for waiting files, and an error -- never
 * placeholder scans -- when loading fails.
 */
import React from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1" } }) }));
jest.mock("@/lib/realtime", () => ({ useScansRealtime: () => {} }));
jest.mock("next/navigation", () => ({ useParams: () => ({ slug: ["acme", "api"] }) }));
let fail = false;
const now = new Date().toISOString();
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  authedFetch: jest.fn(async () => {
    if (fail) throw new Error("down");
    return {
      repo: { name: "acme/api", default_branch: "main", is_active: true, connected_at: "2026-08-01T00:00:00Z" }, scope: "org", open_secrets: 2,
      latest_scan: { scan_id: "s3", pr_number: 8, commit_sha: "abcdef1234567", branch: "feat/pay", overall_risk: "CRITICAL", ai_share: 0.6, file_count: 3, created_at: now, triggered_by: "webhook", author: "bob", superseded: false, latest: true },
      files: [
        { file_path: "src/pay.ts", language: "ts", risk_score: "CRITICAL", ai_percentage: 0.8, indicators: ["sql-injection"], status: "waiting", sla_deadline: "2026-01-01T00:00:00Z", overdue: true },
        { file_path: "src/auth.ts", language: "ts", risk_score: "HIGH", ai_percentage: 0.5, indicators: [], status: "attested", attested_by: "rev@acme.test", attested_at: now },
        { file_path: "src/util.ts", language: "ts", risk_score: "LOW", ai_percentage: 0.1, indicators: [], status: "not_required" },
      ],
      signoff: { required: 2, attested: 1, resolved: 0, in_review: 0, waiting: 1, overdue: 1 },
      prs: [{ pr_number: 8, latest_scan_id: "s3", scans: 2, first_scan_at: now, last_scan_at: now, overall_risk: "CRITICAL", author: "bob", high_crit: 2, signed_off: 1 }],
      scans: [
        { scan_id: "s3", pr_number: 8, commit_sha: "abcdef1234567", branch: "feat/pay", overall_risk: "CRITICAL", ai_share: 0.6, file_count: 3, created_at: now, triggered_by: "webhook", author: "bob", superseded: false, latest: true },
        { scan_id: "s2", pr_number: 8, commit_sha: "1111111234567", branch: "feat/pay", overall_risk: "HIGH", ai_share: 0.5, file_count: 3, created_at: now, triggered_by: "webhook", author: "bob", superseded: true, latest: false },
      ],
      stats: { scans: 2, prs: 1, direct_pushes: 0, first_scan: now, last_scan: now, ai_share: 0.55, contributors: [{ login: "bob", scans: 2 }] },
    };
  }),
}));

import RepoDetailPage from "@/app/repo/[...slug]/page";

beforeEach(() => { fail = false; });

describe("Repository page", () => {
  it("shows where the repo stands, from real data", async () => {
    render(<RepoDetailPage />);
    const summary = await screen.findByRole("region", { name: "Repository summary" });
    expect(within(summary).getByText("High-risk signed off").parentElement).toHaveTextContent("1/2");
    expect(within(summary).getByText("Waiting for sign-off").parentElement).toHaveTextContent("1 past the fix deadline");
    expect(within(summary).getByText("Open secrets").parentElement).toHaveTextContent("2");
    const files = screen.getByRole("region", { name: "Current files" });
    expect(within(files).getByRole("link", { name: /Review & sign off/ })).toHaveAttribute("href", "/pr/s3?attest=src%2Fpay.ts");
    expect(within(files).getByText("rev@acme.test", { exact: false })).toBeInTheDocument();
    expect(within(files).queryByText("util.ts")).toBeNull();                  // no sign-off needed: hidden by default
    fireEvent.click(within(files).getByRole("button", { name: /All files/ }));
    expect(within(files).getByText("util.ts")).toBeInTheDocument();
    expect(within(files).getByRole("link", { name: "sql-injection" })).toHaveAttribute("href", "/rules#sql-injection");
    expect(within(screen.getByRole("region", { name: "Pull requests" })).getByText("1/2")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Scans" })).getByText("Superseded")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open on GitHub/ })).toHaveAttribute("href", "https://github.com/acme/api");
  });

  it("a failed load shows an error, not placeholder data", async () => {
    fail = true;
    render(<RepoDetailPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load this repository");
    expect(document.body.textContent).not.toMatch(/API offline|local data/);
  });
});
