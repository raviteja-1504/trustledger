/**
 * Signed in but no profile yet: the guard must route by the API's answer, not loop.
 * And the shared handler for session-level API errors (session_revoked / mfa_required).
 */
import { render, waitFor } from "@testing-library/react";

jest.mock("@/lib/auth", () => ({ useAuth: () => ({ user: { id: "u" }, profile: null, loading: false, signInWithGitHub: jest.fn() }) }));
const signOut = jest.fn(async () => ({}));
jest.mock("@/lib/supabase", () => ({ supabase: { auth: { signOut: () => signOut(), getSession: async () => ({ data: { session: { access_token: "tok" } } }) } } }));
const nav = jest.fn();
const rep = jest.fn();
jest.mock("@/lib/authFlow", () => ({ ...jest.requireActual("@/lib/authFlow"), fullPageNavigate: (u: string) => nav(u), fullPageReplace: (u: string) => rep(u) }));

import AuthGuard from "@/components/AuthGuard";
import { handleSessionError } from "@/lib/useRealData";

const respond = (status: number, body: unknown) => {
  global.fetch = jest.fn(async () => ({ ok: status < 400, status, json: async () => body })) as unknown as typeof fetch;
};

beforeEach(() => { jest.clearAllMocks(); window.history.replaceState({}, "", "/dashboard"); });

it("a user with no organisation goes to create one — /api/me says so with a 401, not only a 404", async () => {
  respond(401, { error: "no_org_membership" });
  render(<AuthGuard><p>app</p></AuthGuard>);
  await waitFor(() => expect(rep).toHaveBeenCalledWith("/create-org"));
});

it("a session still waiting for its 2FA code goes to the code step instead of reloading forever", async () => {
  respond(401, { error: "mfa_required" });
  render(<AuthGuard><p>app</p></AuthGuard>);
  await waitFor(() => expect(nav).toHaveBeenCalledWith("/login?step=2fa&next=%2Fdashboard"));
  expect(rep).not.toHaveBeenCalled();
});

describe("handleSessionError", () => {
  it("session_revoked signs out and explains on the login page", async () => {
    await handleSessionError("session_revoked");
    expect(signOut).toHaveBeenCalled();
    expect(nav).toHaveBeenCalledWith("/login?error=session_revoked");
  });

  it("mfa_required keeps the session and returns here after the code", async () => {
    window.history.replaceState({}, "", "/reports?tab=soc2");
    await handleSessionError("mfa_required");
    expect(signOut).not.toHaveBeenCalled();
    expect(nav).toHaveBeenCalledWith("/login?step=2fa&next=%2Freports%3Ftab%3Dsoc2");
  });

  it("does nothing on the login page itself, or for other errors", async () => {
    await handleSessionError("insufficient_permissions");
    window.history.replaceState({}, "", "/login");
    await handleSessionError("mfa_required");
    expect(nav).not.toHaveBeenCalled();
  });
});
