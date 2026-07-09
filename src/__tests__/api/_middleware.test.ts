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
    for (const m of ["select", "update", "eq", "neq"]) chain[m] = jest.fn(() => chain);
    chain.single      = jest.fn().mockResolvedValue({ data: null });
    chain.maybeSingle = jest.fn().mockResolvedValue({ data: null });

    (createServiceClient as jest.Mock).mockReturnValue({
      auth: { getUser: jest.fn().mockResolvedValue({ data: { user: { id: "u1", email: "a@b.com" } }, error: null }) },
      from: jest.fn(() => chain),
    });
    const result = await verifyApiKey(fakeRequest({ Authorization: "Bearer sometoken" }));
    expect(result.error).toBe("no_org_membership");
  });

  it("authenticates a valid user with an org membership and returns org_id/role", async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
    const single = jest.fn().mockResolvedValue({
      data: { org_id: "org-1", role: "admin", email: "a@b.com", active_session_id: null },
    });
    (createServiceClient as jest.Mock).mockReturnValue({
      auth: { getUser: jest.fn().mockResolvedValue({ data: { user: { id: "u1", email: "a@b.com" } }, error: null }) },
      from: jest.fn(() => ({
        select: () => ({ eq: () => ({ single }) }),
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
      from: jest.fn(() => ({
        select: () => ({ eq: () => ({ single }) }),
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
