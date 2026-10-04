/**
 * Login page: sign in / sign up / forgot password / reset-link / 2FA flows, against a mocked auth context.
 */
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";

const replace = jest.fn();
let params: Record<string, string> = {};
jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace, push: jest.fn() }),
  useSearchParams: () => ({ get: (k: string) => params[k] ?? null }),
  usePathname: () => "/login",
}));

const authedFetch = jest.fn();
jest.mock("@/lib/useRealData", () => ({ authedFetch: (...a: unknown[]) => authedFetch(...a) }));

type Auth = Record<string, unknown>;
let auth: Auth;
jest.mock("@/lib/auth", () => ({ useAuth: () => auth }));

import LoginPage from "@/app/login/page";

// Several flows wait on real timers (e.g. the 1.5 s "Password set!" pause); under a loaded full run the
// 5 s default was too tight.
jest.setTimeout(20000);

function baseAuth(over: Auth = {}): Auth {
  return {
    user: null, loading: false, passwordRecovery: false,
    signInWithGitHub: jest.fn(async () => ({ error: null })),
    signInWithEmail: jest.fn(async () => ({ error: null })),
    signUpWithEmail: jest.fn(async () => ({ error: null })),
    resendConfirmation: jest.fn(async () => ({ error: null })),
    resetPassword: jest.fn(async () => ({ error: null })),
    clearPasswordRecovery: jest.fn(),
    cancelPasswordRecovery: jest.fn(async () => {}),
    completePasswordReset: jest.fn(async () => ({ error: null, mfaRequired: false })),
    signOut: jest.fn(async () => {}),
    ...over,
  };
}

const assign = jest.fn();
jest.mock("@/lib/authFlow", () => ({ ...jest.requireActual("@/lib/authFlow"), fullPageNavigate: (u: string) => assign(u) }));
beforeEach(() => { jest.clearAllMocks(); params = {}; auth = baseAuth(); authedFetch.mockResolvedValue({ required: false, verified: false }); });

describe("error messages from the URL", () => {
  it("never shows a crafted ?error= value, and a malformed one doesn't crash the page", () => {
    params = { error: "Your account is locked. Call support at 555-0100" };
    const { unmount } = render(<LoginPage />);
    expect(screen.queryByText(/555-0100/)).not.toBeInTheDocument();
    expect(screen.getByText("Sign-in didn't complete. Please try again.")).toBeInTheDocument();
    unmount();
    params = { error: "%" };
    render(<LoginPage />);
    expect(screen.getByText("Sign-in didn't complete. Please try again.")).toBeInTheDocument();
  });

  it("explains known codes in plain words", () => {
    params = { error: "session_revoked" };
    render(<LoginPage />);
    expect(screen.getByText(/signed in somewhere else/)).toBeInTheDocument();
  });

  it("an expired / other-browser email link opens Forgot Password with the explanation", () => {
    params = { error: "link_other_browser" };
    render(<LoginPage />);
    expect(screen.getByText("Reset your password")).toBeInTheDocument();
    expect(screen.getByText(/same browser you requested it from/)).toBeInTheDocument();
  });
});

describe("password reset", () => {
  it("a reset flag with nobody signed in is cleared instead of trapping the user on 'Set your password'", async () => {
    auth = baseAuth({ passwordRecovery: true, user: null });
    render(<LoginPage />);
    await waitFor(() => expect(auth.clearPasswordRecovery).toHaveBeenCalled());
    expect(screen.queryByText("Set your password")).not.toBeInTheDocument();
    expect(screen.getByText(/reset link has expired or was already used/)).toBeInTheDocument();
    expect(screen.getByText("Reset your password")).toBeInTheDocument();
  });

  it("asks for the new password twice, then completes the reset", async () => {
    auth = baseAuth({ passwordRecovery: true, user: { id: "u" } });
    render(<LoginPage />);
    expect(await screen.findByText("Set your password")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "correct-horse-1" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "correct-horse-2" } });
    fireEvent.click(screen.getByRole("button", { name: "Set password & sign in" }));
    expect(await screen.findByText("Passwords do not match.")).toBeInTheDocument();
    expect(auth.completePasswordReset).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "correct-horse-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Set password & sign in" }));
    await waitFor(() => expect(auth.completePasswordReset).toHaveBeenCalledWith("correct-horse-1"));
    expect(await screen.findByText(/Password set!/)).toBeInTheDocument();
  });

  it("goes on to the 2FA step when the account has 2FA, and can be cancelled", async () => {
    auth = baseAuth({ passwordRecovery: true, user: { id: "u" }, completePasswordReset: jest.fn(async () => ({ error: null, mfaRequired: true })) });
    const { unmount } = render(<LoginPage />);
    fireEvent.change(await screen.findByLabelText("New password"), { target: { value: "correct-horse-1" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "correct-horse-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Set password & sign in" }));
    expect(await screen.findByText("Two-factor authentication")).toBeInTheDocument();
    unmount();

    auth = baseAuth({ passwordRecovery: true, user: { id: "u" } });
    render(<LoginPage />);
    fireEvent.click(await screen.findByText("Cancel and go back to sign in"));
    await waitFor(() => expect(auth.cancelPasswordRecovery).toHaveBeenCalled());
  });
});

describe("after signing in", () => {
  it("asks for the 2FA code when the session isn't verified, and submits it", async () => {
    params = { next: "/reports" };
    auth = baseAuth({ user: { id: "u" } });
    authedFetch.mockImplementation(async (_path: string, init?: RequestInit) => init?.method === "POST" ? { ok: true } : { required: true, verified: false });
    render(<LoginPage />);
    expect(await screen.findByText("Two-factor authentication")).toBeInTheDocument();
    expect(replace).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Two-factor code"), { target: { value: "123 456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/reports"));
    expect(authedFetch).toHaveBeenCalledWith("/api/auth/2fa/login", expect.objectContaining({ method: "POST", body: JSON.stringify({ code: "123 456" }) }));
  });

  it("shows the server's message for a wrong code", async () => {
    auth = baseAuth({ user: { id: "u" } });
    authedFetch.mockImplementation(async (_p: string, init?: RequestInit) => {
      if (init?.method === "POST") throw new Error("That code didn't match. Check your authenticator app and try again.");
      return { required: true, verified: false };
    });
    render(<LoginPage />);
    fireEvent.change(await screen.findByLabelText("Two-factor code"), { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByText(/code didn't match/)).toBeInTheDocument();
    expect(assign).not.toHaveBeenCalled();
  });

  it("without 2FA, returns to the page the user asked for — same-site paths only", async () => {
    params = { next: "/reports?tab=soc2" };
    auth = baseAuth({ user: { id: "u" } });
    const { unmount } = render(<LoginPage />);
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/reports?tab=soc2"));
    unmount(); replace.mockClear();
    params = { next: "https://evil.example" };
    render(<LoginPage />);
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/dashboard"));
  });
});

describe("sign in / sign up forms", () => {
  it("offers to resend the confirmation email when the address isn't confirmed", async () => {
    auth = baseAuth({ signInWithEmail: jest.fn(async () => ({ error: "Email not confirmed" })) });
    render(<LoginPage />);
    fireEvent.click(screen.getByText("Sign in with email instead"));
    fireEvent.change(screen.getByLabelText("Work email"), { target: { value: "new@acme.dev" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "longenough1" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    fireEvent.click(await screen.findByRole("button", { name: "Resend confirmation email" }));
    await waitFor(() => expect(auth.resendConfirmation).toHaveBeenCalledWith("new@acme.dev"));
    expect(await screen.findByText(/Confirmation email sent/)).toBeInTheDocument();
  });

  it("gives the GitHub button back when GitHub sign-in can't start", async () => {
    auth = baseAuth({ signInWithGitHub: jest.fn(async () => ({ error: "provider is not enabled" })) });
    render(<LoginPage />);
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: /Continue with GitHub/ })); });
    expect(await screen.findByText("Couldn't start GitHub sign-in. Please try again.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Continue with GitHub/ })).not.toBeDisabled();
  });

  it("the landing page's Get started link (?mode=signup) opens on Sign Up", () => {
    params = { mode: "signup" };
    render(<LoginPage />);
    expect(screen.getByRole("heading", { name: "Create your account" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Sign Up" })).toHaveAttribute("aria-selected", "true");
  });

  it("Forgot password is a link from Sign In (not a third tab), with a way back", () => {
    render(<LoginPage />);
    expect(screen.getAllByRole("tab").map(t => t.textContent)).toEqual(["Sign In", "Sign Up"]);
    fireEvent.click(screen.getByRole("button", { name: "Forgot your password?" }));
    expect(screen.getByRole("heading", { name: "Reset your password" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send reset link" })).toBeInTheDocument();
    expect(screen.queryByRole("tab")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Back to sign in" }));
    expect(screen.getByRole("heading", { name: "Welcome back" })).toBeInTheDocument();
  });

  it("sign-up still checks the two passwords match", async () => {
    render(<LoginPage />);
    fireEvent.click(screen.getByRole("tab", { name: "Sign Up" }));
    fireEvent.change(screen.getByLabelText("Full name"), { target: { value: "Ana" } });
    fireEvent.change(screen.getByLabelText("Work email"), { target: { value: "ana@acme.dev" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "longenough1" } });
    fireEvent.change(screen.getByLabelText("Confirm password"), { target: { value: "longenough2" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(await screen.findByText("Passwords do not match.")).toBeInTheDocument();
    expect(auth.signUpWithEmail).not.toHaveBeenCalled();
  });
});
