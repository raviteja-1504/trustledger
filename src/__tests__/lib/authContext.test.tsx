/**
 * The Supabase-backed auth context: password-reset state, completing a reset, sign-out, and emailed links
 * that Supabase couldn't complete.
 */
import { act, render, waitFor } from "@testing-library/react";

type Cb = (event: string, session: unknown) => void;
let authCallback: Cb = () => {};
const sb = {
  getSession: jest.fn(async () => ({ data: { session: null } })),
  onAuthStateChange: jest.fn((cb: Cb) => { authCallback = cb; return { data: { subscription: { unsubscribe: () => {} } } }; }),
  updateUser: jest.fn(async () => ({ error: null })),
  signOut: jest.fn(async () => ({ error: null })),
  resend: jest.fn(async () => ({ error: null })),
  initialize: jest.fn(async () => ({ error: null as unknown })),
};
jest.mock("@/lib/supabase", () => ({ supabase: { auth: sb } }));
const authedFetch = jest.fn();
jest.mock("@/lib/useRealData", () => ({ authedFetch: (...a: unknown[]) => authedFetch(...a) }));
const replaceTo = jest.fn();
jest.mock("@/lib/authFlow", () => ({ ...jest.requireActual("@/lib/authFlow"), fullPageReplace: (u: string) => replaceTo(u) }));

import { AuthProvider, useAuth } from "@/lib/auth";

let ctx: ReturnType<typeof useAuth>;
function Probe() { ctx = useAuth(); return null; }
const mount = async () => { render(<AuthProvider><Probe /></AuthProvider>); await waitFor(() => expect(ctx.loading).toBe(false)); };

beforeEach(() => {
  jest.clearAllMocks();
  localStorage.clear();
  window.history.replaceState({}, "", "/");
  authedFetch.mockResolvedValue({ has_org: true, is_new_user: false, mfa_required: false });
});

it("a reset link keeps the reset session (so the login page knows a reset is in progress) and moves to /login", async () => {
  await mount();
  const session = { access_token: "a", refresh_token: "r", expires_in: 3600, user: { id: "u" } };
  act(() => authCallback("PASSWORD_RECOVERY", session));
  expect(ctx.passwordRecovery).toBe(true);
  expect(ctx.user).toEqual({ id: "u" });
  expect(localStorage.getItem("tl_password_recovery")).toBe("1");
  expect(replaceTo).toHaveBeenCalledWith("/login");
});

it("completing a reset sets the password, clears the reset state and registers the new session", async () => {
  localStorage.setItem("tl_password_recovery", "1");
  await mount();
  let result: Awaited<ReturnType<typeof ctx.completePasswordReset>> | undefined;
  await act(async () => { result = await ctx.completePasswordReset("new-password-1"); });
  expect(sb.updateUser).toHaveBeenCalledWith({ password: "new-password-1" });
  expect(authedFetch).toHaveBeenCalledWith("/api/auth/bootstrap", { method: "POST" });
  expect(result).toEqual({ error: null, mfaRequired: false });
  expect(ctx.passwordRecovery).toBe(false);
  expect(localStorage.getItem("tl_password_recovery")).toBeNull();
});

it("reports when the account still needs its 2FA code after a reset", async () => {
  authedFetch.mockResolvedValue({ has_org: true, is_new_user: false, mfa_required: true });
  await mount();
  let result: Awaited<ReturnType<typeof ctx.completePasswordReset>> | undefined;
  await act(async () => { result = await ctx.completePasswordReset("new-password-1"); });
  expect(result).toEqual({ error: null, mfaRequired: true });
});

it("a failed password update keeps the reset state and registers nothing", async () => {
  localStorage.setItem("tl_password_recovery", "1");
  sb.updateUser.mockResolvedValueOnce({ error: { message: "Auth session missing!" } } as never);
  await mount();
  let result: Awaited<ReturnType<typeof ctx.completePasswordReset>> | undefined;
  await act(async () => { result = await ctx.completePasswordReset("x-password-1"); });
  expect(result?.error).toBe("Auth session missing!");
  expect(authedFetch).not.toHaveBeenCalled();
  expect(ctx.passwordRecovery).toBe(true);
});

it("signing out forgets an unfinished reset", async () => {
  localStorage.setItem("tl_password_recovery", "1");
  await mount();
  await act(async () => { await ctx.signOut(); });
  expect(localStorage.getItem("tl_password_recovery")).toBeNull();
  expect(ctx.passwordRecovery).toBe(false);
});

it("can resend the sign-up confirmation email", async () => {
  await mount();
  await act(async () => { await ctx.resendConfirmation("new@acme.dev"); });
  expect(sb.resend).toHaveBeenCalledWith({ type: "signup", email: "new@acme.dev" });
});

it("an emailed link Supabase couldn't complete sends the user to /login with the reason", async () => {
  window.history.replaceState({}, "", "/?code=abc");
  sb.initialize.mockResolvedValueOnce({ error: { name: "AuthPKCECodeVerifierMissingError", message: "PKCE code verifier not found in storage" } });
  await mount();
  await waitFor(() => expect(replaceTo).toHaveBeenCalledWith("/login?error=link_other_browser"));
});

it("leaves ordinary pages alone", async () => {
  window.history.replaceState({}, "", "/login?error=session_revoked");
  await mount();
  expect(sb.initialize).not.toHaveBeenCalled();
  expect(replaceTo).not.toHaveBeenCalled();
});
