/**
 * Reports page: generating the signed PDF downloads it; a failure says what actually went wrong (signing not set
 * up, rate limit, permission, render failure); a failed data load shows an error, never placeholder repos.
 */
import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { DashboardData } from "@/types";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/BrandLogo", () => ({ BrandWordmark: () => null }));
const push = jest.fn();
jest.mock("next/navigation", () => ({ useSearchParams: () => null, useRouter: () => ({ push }) }));
let role = "admin";
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1", org_name: "Acme", email: "ada@acme.test", role } }) }));
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  authedFetch: jest.fn(async (url: string) => {
    if (url.startsWith("/api/settings")) return { org: { pci_applicable: true } };
    if (url.startsWith("/api/report/history")) return { reports: [] };
    if (url.startsWith("/api/violation-status")) return { overrides: {} };
    if (url.startsWith("/api/evidence/collect")) throw new Error("not needed");
    return {};
  }),
}));

const dashboard = {
  repos: [{ repo: "acme/api", ai_pct: 0.4, attestation_rate: 0.5, last_scan: "2026-10-18", scan_count: 3, file_count: 30, latest_scan_id: "s1" }],
  overall_ai_pct: 0.4, attestation_rate: 0.5, unattested_deploy_count: 1, scan_count: 3, file_count: 30,
  risk_trend: [], top_risk_files: [{ repo: "acme/api", file_path: "src/pay.ts", ai_pct: 0.9, risk_score: "CRITICAL", attested: false, scan_id: "s1", pr_number: 7 }],
} as unknown as DashboardData;

let dashFails = false;
let reportRes: () => unknown;
jest.mock("@/lib/api", () => ({
  api: {
    dashboard: jest.fn(async () => { if (dashFails) throw new Error("down"); return dashboard; }),
    generateReport: jest.fn(async () => reportRes()),
  },
}));

import ReportsPage from "@/app/reports/page";
import { api } from "@/lib/api";

// Just what the page reads from a fetch Response (jsdom here has no Response class).
const fakeRes = (status: number, type: string, body: unknown) => ({
  ok: status >= 200 && status < 300, status,
  headers: { get: (h: string) => (h.toLowerCase() === "content-type" ? type : null) },
  json: async () => { if (typeof body === "string") throw new SyntaxError("not json"); return body; },
  blob: async () => body,
});
const json = (status: number, body: unknown) => fakeRes(status, "application/json", body);
// The page loads several sources before the button is ready; under full-suite load that can pass the 1s default.
jest.setTimeout(30_000);
const generateButton = () => screen.findByRole("button", { name: /Generate Signed .* Report/ }, { timeout: 10_000 });

beforeEach(() => {
  dashFails = false;
  role = "admin";
  push.mockClear();
  (api.generateReport as jest.Mock).mockClear();
  (URL as unknown as { createObjectURL: unknown }).createObjectURL = jest.fn(() => "blob:x");
  (URL as unknown as { revokeObjectURL: unknown }).revokeObjectURL = jest.fn();
});

describe("an unattested file's button follows the viewer's role", () => {
  it("a developer can't sign the CRITICAL file off: 'View' opens the file, not the attestation form", async () => {
    role = "developer";
    render(<ReportsPage />);
    // The row re-mounts while the page's sources load, so click the button as it is now until it takes.
    await waitFor(() => {
      fireEvent.click(screen.getByRole("button", { name: "View" }));
      expect(push).toHaveBeenCalledWith("/pr/s1?file=src%2Fpay.ts");
    }, { timeout: 10_000 });
    expect(screen.queryByRole("button", { name: "Attest" })).not.toBeInTheDocument();
  });

  it("someone who may sign it off gets Attest, which opens the sign-off", async () => {
    render(<ReportsPage />);
    await waitFor(() => {
      fireEvent.click(screen.getByRole("button", { name: "Attest" }));
      expect(push).toHaveBeenCalledWith("/pr/s1?attest=src%2Fpay.ts");
    }, { timeout: 10_000 });
  });
});

describe("Reports page", () => {
  it("a generated PDF is downloaded", async () => {
    reportRes = () => fakeRes(200, "application/pdf", new Blob(["%PDF-1.4"]));
    const click = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    render(<ReportsPage />);
    fireEvent.click(await generateButton());
    await waitFor(() => expect(click).toHaveBeenCalled(), { timeout: 10_000 });
    expect(api.generateReport).toHaveBeenCalledWith(expect.objectContaining({ framework: "SOC2" }));
    expect(screen.queryByText(/couldn't render/i)).not.toBeInTheDocument();
    click.mockRestore();
  });

  it.each([
    [json(503, { error: "report_signing_not_configured" }), /no signing key.*EXPORT_SIGNING_KEY/],
    [json(429, { error: "rate_limited" }), /Too many reports/],
    [json(403, { error: "forbidden" }), /can't generate reports/],
    [json(500, { error: "report_render_failed", pdf_render_failed: true }), /couldn't render a PDF/],
    [fakeRes(502, "text/html", "<html>gateway</html>"), /couldn't render a PDF/],
    [fakeRes(200, "application/json", { unexpected: true }), /couldn't render a PDF/],
  ])("a failed generate says why (%#)", async (res, msg) => {
    reportRes = () => res;
    render(<ReportsPage />);
    fireEvent.click(await generateButton());
    expect(await screen.findByText(msg)).toBeInTheDocument();
  });

  it("a failed data load shows an error, not placeholder repositories", async () => {
    dashFails = true;
    render(<ReportsPage />);
    expect(await screen.findByText("Couldn't load report data")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/payments-api|fraud-detection|card_validator/);
  });
});
