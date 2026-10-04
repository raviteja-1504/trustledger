/**
 * @jest-environment node
 *
 * Route-handler modules import next/server, which needs the Fetch API
 * globals (Request/Response/Headers). jsdom (this project's default test
 * environment) doesn't implement them; Node's environment does natively.
 */
import type { NextRequest } from "next/server";

// createServiceClient is mocked per-test via jest.mock below; import after mocking.
jest.mock("@/lib/supabase", () => ({
  createServiceClient: jest.fn(),
}));
jest.mock("@/lib/jwt", () => ({
  getJwtSessionId: jest.fn(() => null),
}));

import { requireRole, verifyApiKey } from "@/app/api/_middleware";
import { createServiceClient } from "@/lib/supabase";
import { getJwtSessionId } from "@/lib/jwt";

function fakeRequest(headers: Record<string, string> = {}): NextRequest {
  return {
    headers: { get: (name: string) => headers[name] ?? null },
  } as unknown as NextRequest;
}

describe("requireRole", () => {
  it("allows a role equal to the minimum required", () => {
    expect(requireRole({ org_id: "o1", role: "security_reviewer" }, "security_reviewer")).toBeNull();
  });

  it("allows a role above the minimum required", () => {
    expect(requireRole({ org_id: "o1", role: "admin" }, "developer")).toBeNull();
  });

  it("rejects a role below the minimum required", () => {
    expect(requireRole({ org_id: "o1", role: "developer" }, "admin")).toBe("insufficient_permissions");
  });

  it("treats a missing role as the lowest rank (developer)", () => {
    expect(requireRole({ org_id: "o1" }, "developer")).toBeNull();
    expect(requireRole({ org_id: "o1" }, "admin")).toBe("insufficient_permissions");
  });

  it("treats an unrecognized role string as the lowest rank, not as trusted", () => {
    // Guards against a typo'd or unexpected role value silently granting access.
    expect(requireRole({ org_id: "o1", role: "superadmin" }, "admin")).toBe("insufficient_permissions");
  });
});

describe("verifyApiKey", () => {
  const originalSkipAuth = process.env.NEXT_PUBLIC_SKIP_AUTH;

  afterEach(() => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = originalSkipAuth;
    jest.clearAllMocks();
  });

  it("returns missing_credentials when no Authorization header or API key is present", async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
    const result = await verifyApiKey(fakeRequest());
    expect(result.error).toBe("missing_credentials");
    expect(result.org_id).toBe("");
  });

  it("bypasses auth in demo mode and returns a fixed demo org", async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "true";
    const result = await verifyApiKey(fakeRequest());
    expect(result.org_id).toBe("demo");
    expect(result.error).toBeUndefined();
  });

  it("rejects an invalid bearer token", async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
    (createServiceClient as jest.Mock).mockReturnValue({
      auth: { getUser: jest.fn().mockResolvedValue({ data: { user: null }, error: { message: "bad token" } }) },
    });
    const result = await verifyApiKey(fakeRequest({ Authorization: "Bearer garbage" }));
    expect(result.error).toBe("invalid_token");
  });

  it("rejects a valid user with no org membership (including the email re-link fallback)", async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
    // verifyApiKey falls through: select-by-user_id -> update-by-email (re-link
    // invited users whose org_members row predates their first login) ->
    // select-by-user_id again. All three must resolve to "not found" here.
    const chain: Record<string, unknown> = {};
    for (const m of ["select", "update", "eq", "neq", "or"]) chain[m] = jest.fn(() => chain);
    chain.single      = jest.fn().mockResolvedValue({ data: null });
    chain.maybeSingle = jest.fn().mockResolvedValue({ data: null });

    (createServiceClient as jest.Mock).mockReturnValue({
      auth: { getUser: jest.fn().mockResolvedValue({ data: { user: { id: "u1", email: "a@b.com" } }, error: null }) },
      from: jest.fn(() => chain),
    });
    const result = await verifyApiKey(fakeRequest({ Authorization: "Bearer sometoken" }));
    expect(result.error).toBe("no_org_membership");
  });

  it("links a pending invite by email only when the email is confirmed", async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
    const chain: Record<string, unknown> = {};
    for (const m of ["select", "update", "eq", "neq", "or"]) chain[m] = jest.fn(() => chain);
    chain.single      = jest.fn().mockResolvedValue({ data: null });
    chain.maybeSingle = jest.fn().mockResolvedValue({ data: { org_id: "org-inv", role: "developer", email: "a@b.com", active_session_id: null } });
    const getUser = jest.fn();
    (createServiceClient as jest.Mock).mockReturnValue({ auth: { getUser }, from: jest.fn(() => chain) });

    getUser.mockResolvedValue({ data: { user: { id: "u1", email: "a@b.com", email_confirmed_at: null } }, error: null });
    expect((await verifyApiKey(fakeRequest({ Authorization: "Bearer t" }))).error).toBe("no_org_membership");
    expect(chain.update).not.toHaveBeenCalled();

    getUser.mockResolvedValue({ data: { user: { id: "u1", email: "a@b.com", email_confirmed_at: "2026-10-01T00:00:00Z" } }, error: null });
    expect(await verifyApiKey(fakeRequest({ Authorization: "Bearer t" }))).toMatchObject({ org_id: "org-inv", user_id: "u1" });
    expect(chain.update).toHaveBeenCalledWith({ user_id: "u1" });
  });

  it("refuses a 2FA user's session until the sign-in code step made it the active one", async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
    const member = { org_id: "org-1", role: "admin", email: "a@b.com", active_session_id: "verified-session" };
    (createServiceClient as jest.Mock).mockReturnValue({
      auth: { getUser: jest.fn().mockResolvedValue({ data: { user: { id: "u1", email: "a@b.com" } }, error: null }) },
      from: jest.fn((table: string) => ({
        select: () => ({ eq: () => ({
          single: jest.fn().mockResolvedValue({ data: member }),
          maybeSingle: jest.fn().mockResolvedValue({ data: table === "user_2fa" ? { enabled: true } : null }),
        }) }),
      })),
    });
    (getJwtSessionId as jest.Mock).mockReturnValue("fresh-password-session");
    expect((await verifyApiKey(fakeRequest({ Authorization: "Bearer t" }))).error).toBe("mfa_required");
    (getJwtSessionId as jest.Mock).mockReturnValue(null);
    expect((await verifyApiKey(fakeRequest({ Authorization: "Bearer t" }))).error).toBe("mfa_required");
    (getJwtSessionId as jest.Mock).mockReturnValue("verified-session");
    expect(await verifyApiKey(fakeRequest({ Authorization: "Bearer t" }))).toMatchObject({ org_id: "org-1", user_id: "u1" });
    // Even with no active session recorded yet, 2FA users are refused (a fresh member row has null).
    member.active_session_id = null as unknown as string;
    (getJwtSessionId as jest.Mock).mockReturnValue("any-session");
    expect((await verifyApiKey(fakeRequest({ Authorization: "Bearer t" }))).error).toBe("mfa_required");
  });

  it("authenticates a valid user with an org membership and returns org_id/role", async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
    const single = jest.fn().mockResolvedValue({
      data: { org_id: "org-1", role: "admin", email: "a@b.com", active_session_id: null },
    });
    (createServiceClient as jest.Mock).mockReturnValue({
      auth: { getUser: jest.fn().mockResolvedValue({ data: { user: { id: "u1", email: "a@b.com" } }, error: null }) },
      // org_members → single(); user_2fa → maybeSingle() (no 2FA record)
      from: jest.fn(() => ({
        select: () => ({ eq: () => ({ single, maybeSingle: jest.fn().mockResolvedValue({ data: null }) }) }),
      })),
    });
    const result = await verifyApiKey(fakeRequest({ Authorization: "Bearer sometoken" }));
    expect(result).toMatchObject({ org_id: "org-1", role: "admin", user_id: "u1" });
  });

  it("rejects a session whose JWT session id no longer matches the org member's active session (revoked by a newer login)", async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
    (getJwtSessionId as jest.Mock).mockReturnValue("old-session");
    const single = jest.fn().mockResolvedValue({
      data: { org_id: "org-1", role: "admin", email: "a@b.com", active_session_id: "new-session" },
    });
    (createServiceClient as jest.Mock).mockReturnValue({
      auth: { getUser: jest.fn().mockResolvedValue({ data: { user: { id: "u1", email: "a@b.com" } }, error: null }) },
      // org_members → single(); user_2fa → maybeSingle() (no 2FA record)
      from: jest.fn(() => ({
        select: () => ({ eq: () => ({ single, maybeSingle: jest.fn().mockResolvedValue({ data: null }) }) }),
      })),
    });
    const result = await verifyApiKey(fakeRequest({ Authorization: "Bearer sometoken" }));
    expect(result.error).toBe("session_revoked");
  });

  it("rejects a revoked API key", async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
    const single = jest.fn().mockResolvedValue({ data: { org_id: "org-1", revoked: true } });
    (createServiceClient as jest.Mock).mockReturnValue({
      from: jest.fn(() => ({
        select: () => ({ eq: () => ({ single, limit: () => ({ single }) }) }),
        update: () => ({ eq: () => Promise.resolve({}) }),
      })),
    });
    const result = await verifyApiKey(fakeRequest({ "X-TrustLedger-Key": "tl_live_revokedkey" }));
    expect(result.error).toBe("invalid_api_key");
  });

  it("rejects an expired API key", async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
    const single = jest.fn().mockResolvedValue({
      data: { org_id: "org-1", revoked: false, expires_at: "2020-01-01T00:00:00Z" },
    });
    (createServiceClient as jest.Mock).mockReturnValue({
      from: jest.fn(() => ({
        select: () => ({ eq: () => ({ single, limit: () => ({ single }) }) }),
        update: () => ({ eq: () => Promise.resolve({}) }),
      })),
    });
    const result = await verifyApiKey(fakeRequest({ "X-TrustLedger-Key": "tl_live_expiredkey" }));
    expect(result.error).toBe("api_key_expired");
  });
});
