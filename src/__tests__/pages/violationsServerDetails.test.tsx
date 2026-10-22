/**
 * Violations page, signed in: assignee / note / escalation come from the server (same on every device), and what
 * this browser held before is uploaded once -- keeping the server's status -- and then removed from the browser.
 */
import React from "react";
import { render, screen, waitFor } from "@testing-library/react";

jest.mock("@/components/AuthGuard",    () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/PageSkeleton", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/toast", () => ({ useToastHelpers: () => ({ success: jest.fn(), error: jest.fn(), info: jest.fn(), warn: jest.fn() }) }));
let role = "developer";
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1", org_slug: "acme", role } }) }));
jest.mock("@/lib/realtime", () => ({ useViolationsRealtime: () => {} }));
jest.mock("@/lib/offlineData", () => ({ readSeed: () => null }));

const now = new Date().toISOString();
jest.mock("@/lib/api", () => ({
  api: {
    dashboard: async () => ({
      attestation_rate: 0, unattested_deploy_count: 1, sla_breach_count: 0, repos: [{ repo: "acme/api", ai_pct: 0.2, attestation_rate: 0, scan_count: 1, file_count: 1, last_scan: now, latest_scan_id: "s1" }],
      top_risk_files: [{ repo: "acme/api", scan_id: "s1", file_path: "src/pay.ts", risk_score: "CRITICAL", ai_pct: 0.5, attested: false, pr_number: 3, created_at: now }],
      risk_trend: [], recent_activity: [],
    }),
  },
}));

const calls: { url: string; init?: { method?: string; body?: string } }[] = [];
let server: Record<string, unknown> = {};
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  authedFetch: jest.fn(async (url: string, init?: { method?: string; body?: string }) => {
    calls.push({ url, init });
    if (url === "/api/violation-status" && !init) return { overrides: server };
    if (url === "/api/violation-status") return { ok: true };
    if (url.startsWith("/api/team")) return { members: [{ email: "rev@acme.io", name: "Rev" }] };
    return { scans: [] };
  }),
}));

import ViolationsPage from "@/app/violations/page";
import { invalidateServerStatuses } from "@/lib/violationStatuses";

const patches = () => calls.filter(c => c.init?.method === "PATCH").map(c => JSON.parse(c.init!.body!));

beforeEach(() => { calls.length = 0; localStorage.clear(); invalidateServerStatuses(); server = {}; role = "developer"; });

describe("the file's action follows the viewer's role", () => {
  it("a developer can't sign the CRITICAL file off: the button opens it in its PR, never the attestation form", async () => {
    render(<ViolationsPage />);
    const open = await screen.findByRole("link", { name: "Open in PR" });
    expect(open).toHaveAttribute("href", "/pr/s1?file=src%2Fpay.ts");
    expect(screen.queryByRole("link", { name: "Attest" })).not.toBeInTheDocument();
  });

  it("a security lead may: the button is Attest and opens the sign-off", async () => {
    role = "admin";
    render(<ViolationsPage />);
    expect(await screen.findByRole("link", { name: "Attest" })).toHaveAttribute("href", "/pr/s1?attest=src%2Fpay.ts");
  });
});

describe("violations page details are server-backed", () => {
  it("uploads this browser's old assignee / note / escalation once, keeping the server's status, then clears them", async () => {
    server = { "crit::s1::src/pay.ts": { status: "in_review" } };
    localStorage.setItem("tl_violation_assignees", JSON.stringify({ "crit::s1::src/pay.ts": "rev@acme.io" }));
    localStorage.setItem("tl_violation_notes", JSON.stringify({ "crit::s1::src/pay.ts": "vendor fix pending" }));
    localStorage.setItem("tl_violation_escalations", JSON.stringify(["crit::s1::src/pay.ts"]));
    render(<ViolationsPage />);
    await waitFor(() => expect(patches()).toHaveLength(1));
    expect(patches()[0]).toEqual({ violation_id: "crit::s1::src/pay.ts", status: "in_review", assigned_email: "rev@acme.io", note: "vendor fix pending", escalated: true });
    await waitFor(() => expect(localStorage.getItem("tl_violation_notes")).toBeNull());
    expect(localStorage.getItem("tl_violation_assignees")).toBeNull();
    expect(localStorage.getItem("tl_violation_escalations")).toBeNull();
  });

  it("the server's values win: nothing is uploaded when it already has them", async () => {
    server = { "crit::s1::src/pay.ts": { status: "open", note: "server note", assigned_email: "rev@acme.io", escalated: true } };
    localStorage.setItem("tl_violation_notes", JSON.stringify({ "crit::s1::src/pay.ts": "stale local note" }));
    render(<ViolationsPage />);
    await waitFor(() => expect(calls.some(c => c.url === "/api/violation-status")).toBe(true));
    await waitFor(() => expect(localStorage.getItem("tl_violation_notes")).toBeNull());
    expect(patches()).toEqual([]);
  });

  it("a failed upload keeps the browser's copy for next time", async () => {
    const { authedFetch } = jest.requireMock("@/lib/useRealData") as { authedFetch: jest.Mock };
    authedFetch.mockImplementation(async (url: string, init?: { method?: string; body?: string }) => {
      calls.push({ url, init });
      if (init?.method === "PATCH") throw new Error("down");
      if (url === "/api/violation-status") return { overrides: {} };
      return { scans: [], members: [] };
    });
    localStorage.setItem("tl_violation_notes", JSON.stringify({ "crit::s1::src/pay.ts": "keep me" }));
    render(<ViolationsPage />);
    await waitFor(() => expect(patches()).toHaveLength(1));
    await new Promise(r => setTimeout(r, 20));
    expect(localStorage.getItem("tl_violation_notes")).toContain("keep me");
    expect(screen.getByRole("heading", { name: "Policy Violations" })).toBeInTheDocument();
  });
});
