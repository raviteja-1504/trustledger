import { render, screen, waitFor } from "@testing-library/react";

const push = jest.fn();
jest.mock("next/navigation", () => ({ useRouter: () => ({ push, replace: jest.fn() }), usePathname: () => "/onboarding", useSearchParams: () => new URLSearchParams() }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1", org_slug: "acme", role: "admin", name: "Ada" }, user: { id: "u1" } }) }));
jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn(async () => ({})), getAuthHeader: async () => ({}) }));

import OnboardingPage from "@/app/onboarding/page";

beforeEach(() => { localStorage.removeItem("tl_onboarding_done"); push.mockClear(); });

describe("setup wizard", () => {
  it("a first visit opens at step 1 of the same five steps", async () => {
    render(<OnboardingPage />);
    expect(await screen.findByText(/Step 1 of 5/)).toBeInTheDocument();
    expect(screen.queryByText(/steps? done|of 4 done/)).toBeNull();
  });

  it("reopens at the first unfinished step, still showing all five, with the finished ones counted", async () => {
    localStorage.setItem("tl_onboarding_done", JSON.stringify(["welcome", "github"]));
    render(<OnboardingPage />);
    await waitFor(() => expect(screen.getByText(/Step 3 of 5/)).toBeInTheDocument());
    expect(screen.getByText("Invite Team")).toBeInTheDocument();
    expect(screen.getByText(/2 of 4 done/)).toBeInTheDocument();
  });

  it("'Skip for now' leaves for the overview without completing setup", async () => {
    const { authedFetch } = jest.requireMock("@/lib/useRealData") as { authedFetch: jest.Mock };
    authedFetch.mockClear();
    render(<OnboardingPage />);
    (await screen.findByText(/Skip for now/)).click();
    expect(push).toHaveBeenCalledWith("/dashboard");
    expect(authedFetch).not.toHaveBeenCalledWith("/api/onboarding", expect.objectContaining({ method: "POST" }));
  });
});
