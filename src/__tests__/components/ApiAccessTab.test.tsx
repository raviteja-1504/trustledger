import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1", role: "admin" } }) }));
let listResult: unknown = { keys: [] };
let listError: Error | null = null;
let createError: (Error & { code?: string }) | null = null;
let lastCreateBody: Record<string, unknown> | null = null;
const calls: Array<{ path: string; method: string; body?: string }> = [];
jest.mock("@/lib/useRealData", () => ({
  authedFetch: jest.fn(async (path: string, init?: { method?: string; body?: string }) => {
    calls.push({ path, method: init?.method ?? "GET", body: init?.body });
    if (!init?.method) { if (listError) throw listError; return listResult; }
    if (init.method === "POST") {
      if (createError) throw createError;
      lastCreateBody = JSON.parse(init.body ?? "{}");
      return { id: "k-new", key_prefix: "tl_live_abcdef12...", created_at: "2026-11-13T10:00:00Z", raw_key: "tl_live_" + "a".repeat(40) };
    }
    return { ok: true };
  }),
}));

import { ApiAccessTab, apiKeyErrorText } from "@/components/settings/ApiAccessTab";

beforeEach(() => { listResult = { keys: [] }; listError = null; createError = null; lastCreateBody = null; calls.length = 0; });

describe("Settings → API Access", () => {
  it("says what a key can and cannot do, and shows the real call to make", async () => {
    render(<ApiAccessTab />);
    expect(await screen.findByText("A key can")).toBeInTheDocument();
    expect(screen.getByText(/Submit scans and read their results/)).toBeInTheDocument();
    expect(screen.getByText(/Attest \(sign off\) files: that is always a named person/)).toBeInTheDocument();
    expect(screen.getByText(/Create, list or revoke API keys/)).toBeInTheDocument();
    expect(document.body.textContent).toContain("-X POST");
    expect(document.body.textContent).toContain("/api/scans");
    expect(document.body.textContent).toContain("X-TrustLedger-Key");
    // no permission switches that the server would not honour, and none of the endpoints that do not exist
    expect(document.body.textContent).not.toMatch(/api\/v1|Read Dashboard|Submit Attestations/);
    expect(screen.queryByRole("button", { name: /Read Scans|Admin/ })).toBeNull();
  });

  it("lists the organisation's active keys and leaves out revoked ones", async () => {
    listResult = { keys: [
      { id: "k1", name: "GitHub Actions", key_prefix: "tl_live_1111aaaa...", created_at: "2026-11-01T00:00:00Z", last_used: "2026-11-12T00:00:00Z", expires_at: null },
      { id: "k2", name: "Old key", key_prefix: "tl_live_2222bbbb...", created_at: "2026-10-01T00:00:00Z", last_used: null, expires_at: null, revoked: true },
    ] };
    render(<ApiAccessTab />);
    expect(await screen.findByText("GitHub Actions")).toBeInTheDocument();
    expect(screen.queryByText("Old key")).toBeNull();
    expect(screen.getByText(/tl_live_1111aaaa\.\.\. · Created/)).toHaveTextContent("Never expires");
  });

  it("creates a real key through the server, shows it once with the expiry that was chosen", async () => {
    render(<ApiAccessTab />);
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "CI" } });
    fireEvent.change(screen.getByLabelText("Expires"), { target: { value: "90" } });
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));
    expect(await screen.findByText("tl_live_" + "a".repeat(40))).toBeInTheDocument();
    expect(screen.getByText(/It will not be shown again/)).toBeInTheDocument();
    expect(lastCreateBody).toEqual({ name: "CI", expires_days: 90 });
    expect(screen.getByText("CI")).toBeInTheDocument();       // listed straight away
  });

  it("when the server refuses, it says why and invents no key", async () => {
    createError = Object.assign(new Error("insufficient_permissions"), { code: "insufficient_permissions" });
    render(<ApiAccessTab />);
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "CI" } });
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));
    expect(await screen.findByText("Only an administrator can create or revoke API keys.")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/tl_live_[0-9a-f]{40}/);
    expect(localStorage.getItem("tl_api_keys")).toBeNull();
  });

  it("revoking calls the server and removes the key", async () => {
    listResult = { keys: [{ id: "k1", name: "GitHub Actions", key_prefix: "tl_live_1111aaaa...", created_at: "2026-11-01T00:00:00Z", last_used: null, expires_at: null }] };
    render(<ApiAccessTab />);
    fireEvent.click(await screen.findByRole("button", { name: "Revoke GitHub Actions" }));
    await waitFor(() => expect(screen.queryByText("GitHub Actions")).toBeNull());
    expect(calls.some(c => c.method === "DELETE" && c.path === "/api/keys" && c.body === JSON.stringify({ id: "k1" }))).toBe(true);
  });

  it("an expired key is marked as such", async () => {
    listResult = { keys: [{ id: "k1", name: "Old CI", key_prefix: "tl_live_1111aaaa...", created_at: "2026-01-01T00:00:00Z", last_used: null, expires_at: "2026-02-01T00:00:00Z" }] };
    render(<ApiAccessTab />);
    expect(await screen.findByText("expired")).toBeInTheDocument();
  });

  it("a failed load says why instead of looking empty", async () => {
    listError = Object.assign(new Error("insufficient_permissions"), { code: "insufficient_permissions" });
    render(<ApiAccessTab />);
    expect(await screen.findByText("Only an administrator can create or revoke API keys.")).toBeInTheDocument();
  });
});

describe("apiKeyErrorText", () => {
  it("maps the server's codes to words", () => {
    expect(apiKeyErrorText({ code: "rate_limited" })).toMatch(/Too many keys/);
    expect(apiKeyErrorText(new Error("missing_name"))).toBe("Give the key a name.");
    expect(apiKeyErrorText(new Error("boom"))).toMatch(/couldn't do that/);
  });
});
