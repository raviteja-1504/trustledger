/**
 * Audit Trail page: the server's log only (nothing from browser storage), real event labels, server-side filters,
 * paging, and the server's chain check worded honestly.
 */
import React from "react";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1" } }) }));

const urls: string[] = [];
let verifyResult: Record<string, unknown> = { valid: true, total: 3, verified: 1, legacy: 2, concurrent: 0, first_at: "2026-09-01T00:00:00Z", last_at: "2026-10-04T00:00:00Z" };
const entry = (id: number, type: string, at: string, payload: Record<string, unknown> = {}, actor: string | null = "ada@acme.test") =>
  ({ id, event_type: type, actor_email: actor, payload, entry_hash: `hash${id}`, prev_hash: id > 1 ? `hash${id - 1}` : null, created_at: at });
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  getAuthHeader: async () => ({}),
  authedFetch: jest.fn(async (url: string, init?: { method?: string }) => {
    urls.push(url);
    if (init?.method === "POST") return verifyResult;
    const page = Number(new URLSearchParams(url.split("?")[1]).get("page") ?? 0);
    if (page === 1) return { events: [entry(1, "user_login", "2026-09-01T08:00:00Z", { method: "password" })], total: 4, counts: {}, period_total: 4, page: 1 };
    return {
      events: [
        entry(4, "incident_created", "2026-10-04T09:00:00Z", { title: "CRITICAL unattested file: pay.ts", severity: "P1" }, "system"),
        entry(3, "attestation", "2026-10-03T08:00:00Z", { file_path: "src/pay.ts", scan_id: "s1", repo: "acme/api" }),
        entry(2, "scan_complete", "2026-10-03T07:00:00Z", { repo: "acme/api", pr_number: 7, overall_risk: "HIGH", scan_id: "s1" }, "system"),
      ],
      total: 4, counts: { incident_created: 1, attestation: 1, scan_complete: 1, user_login: 1 }, period_total: 4, page: 0,
    };
  }),
}));

import AuditPage from "@/app/audit/page";

beforeEach(() => { urls.length = 0; localStorage.clear(); });

describe("Audit Trail page", () => {
  it("shows stored entries with their real labels, never browser-stored activity", async () => {
    localStorage.setItem("tl_local_activity", JSON.stringify([{ type: "attestation", timestamp: "2026-10-10T00:00:00Z", repo: "x/local", pr_number: 1, scan_id: "z", file_path: "local.ts", reviewer_email: "me@x", overall_risk: "HIGH", file_count: 0, total_ai_pct: 0 }]));
    render(<AuditPage />);
    expect(await screen.findByText("Incident opened")).toBeInTheDocument();          // not "Merge blocked"
    expect(screen.getByText("pay.ts signed off by ada@acme.test")).toBeInTheDocument();
    expect(screen.getByText("Scan completed for PR #7 — HIGH risk")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/local\.ts|x\/local/);
    expect(urls[0]).toMatch(/^\/api\/audit\?limit=200&page=0&since=\d{4}-\d{2}-\d{2}$/);
    const summary = screen.getByRole("region", { name: "Summary" });
    expect(within(summary).getByText("Entries").parentElement).toHaveTextContent("4");
  });

  it("an entry opens to its facts, SOC 2 criteria, stored hash and a link", async () => {
    render(<AuditPage />);
    fireEvent.click(await screen.findByText("pay.ts signed off by ada@acme.test"));
    expect(screen.getByText("Hash: hash3")).toBeInTheDocument();
    expect(screen.getByText("Previous: hash2")).toBeInTheDocument();
    expect(screen.getByText("CC8.1")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open scan/ })).toHaveAttribute("href", "/pr/s1");
  });

  it("filters go to the server; older entries load on demand", async () => {
    render(<AuditPage />);
    await screen.findByText("Incident opened");
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "reviews" } });
    await waitFor(() => expect(urls.at(-1)).toMatch(/type=attestation%2Cmerge_allowed%2Cmerge_blocked/));
    fireEvent.change(screen.getByLabelText("Period"), { target: { value: "all" } });
    await waitFor(() => expect(urls.at(-1)).not.toMatch(/since=/));
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "all" } });
    await act(async () => { fireEvent.click(await screen.findByRole("button", { name: /Load older entries \(1 more\)/ })); });
    expect(await screen.findByText("ada@acme.test signed in")).toBeInTheDocument();
  });

  it("the chain check says what it checked, including entries it can only link-check", async () => {
    render(<AuditPage />);
    await screen.findByText("Incident opened");
    fireEvent.click(screen.getByRole("button", { name: "Check the whole log" }));
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("Intact. 3 entries from 1 Sept 2026 to 4 Oct 2026: every link is in place, and 1 entry's contents match their hashes.");
    expect(status).toHaveTextContent("2 older entries (written before contents were stored in a checkable form) can only be link-checked.");
  });

  it("a broken chain is reported at the entry", async () => {
    verifyResult = { valid: false, total: 3, verified: 1, legacy: 0, concurrent: 0, broken_at: 3, reason: "content_changed", first_at: null, last_at: null };
    render(<AuditPage />);
    await screen.findByText("Incident opened");
    fireEvent.click(screen.getByRole("button", { name: "Check the whole log" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Problem at entry #3. Its contents no longer match its hash");
  });
});
