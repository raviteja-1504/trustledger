/**
 * GitHub sign-in callback (/auth/callback).
 */
import { render, waitFor } from "@testing-library/react";

const replace = jest.fn();
let params: Record<string, string> = {};
jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace }),
  useSearchParams: () => ({ get: (k: string) => params[k] ?? null }),
}));

const getSession = jest.fn();
const exchangeCodeForSession = jest.fn();
jest.mock("@/lib/supabase", () => ({ supabase: { auth: { getSession: () => getSession(), exchangeCodeForSession: (c: string) => exchangeCodeForSession(c) } } }));
jest.mock("@/lib/auth", () => ({ syncSessionCookie: jest.fn() }));
const authedFetch = jest.fn();
jest.mock("@/lib/useRealData", () => ({ authedFetch: (...a: unknown[]) => authedFetch(...a) }));
const navigate = jest.fn();
jest.mock("@/lib/authFlow", () => ({ ...jest.requireActual("@/lib/authFlow"), fullPageNavigate: (u: string) => navigate(u) }));

import AuthCallbackPage from "@/app/auth/callback/page";

const session = { access_token: "a", refresh_token: "r", user: { id: "u" } };
beforeEach(() => { jest.clearAllMocks(); params = { code: "abc" }; });

it("uses the session the Supabase client already created — does not exchange the one-time code a second time", async () => {
  getSession.mockResolvedValue({ data: { session } });
  authedFetch.mockResolvedValue({ has_org: true, is_new_user: false, mfa_required: false });
  render(<AuthCallbackPage />);
  await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
  expect(exchangeCodeForSession).not.toHaveBeenCalled();
  expect(replace).not.toHaveBeenCalled();
});

it("exchanges the code itself only when there is no session yet", async () => {
  getSession.mockResolvedValue({ data: { session: null } });
  exchangeCodeForSession.mockResolvedValue({ data: { session }, error: null });
  authedFetch.mockResolvedValue({ has_org: true, is_new_user: false, mfa_required: false });
  render(<AuthCallbackPage />);
  await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
  expect(exchangeCodeForSession).toHaveBeenCalledWith("abc");
});

it("sends a user with no organisation to create one", async () => {
  getSession.mockResolvedValue({ data: { session } });
  authedFetch.mockResolvedValue({ has_org: false, is_new_user: true, mfa_required: false });
  render(<AuthCallbackPage />);
  await waitFor(() => expect(navigate).toHaveBeenCalledWith("/create-org"));
});

it("sends a 2FA user to the code step, keeping where they were going", async () => {
  params = { code: "abc", next: "/reports" };
  getSession.mockResolvedValue({ data: { session } });
  authedFetch.mockResolvedValue({ has_org: true, is_new_user: false, mfa_required: true });
  render(<AuthCallbackPage />);
  await waitFor(() => expect(navigate).toHaveBeenCalledWith("/login?step=2fa&next=%2Freports"));
});

it("never follows an off-site ?next=", async () => {
  params = { code: "abc", next: "https://evil.example" };
  getSession.mockResolvedValue({ data: { session } });
  authedFetch.mockResolvedValue({ has_org: true, is_new_user: false, mfa_required: false });
  render(<AuthCallbackPage />);
  await waitFor(() => expect(navigate).toHaveBeenCalledWith("/dashboard"));
});

it("maps provider errors to known codes instead of passing their text through", async () => {
  params = { error: "access_denied" };
  const { unmount } = render(<AuthCallbackPage />);
  await waitFor(() => expect(replace).toHaveBeenCalledWith("/login?error=access_denied"));
  unmount(); replace.mockClear();
  params = { error: "server_error: something <b>odd</b>" };
  render(<AuthCallbackPage />);
  await waitFor(() => expect(replace).toHaveBeenCalledWith("/login?error=auth_failed"));
});
