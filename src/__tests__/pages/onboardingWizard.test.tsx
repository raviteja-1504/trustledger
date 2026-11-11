import { render, screen, waitFor } from "@testing-library/react";

const push = jest.fn();
jest.mock("next/navigation", () => ({ useRouter: () => ({ push, replace: jest.fn() }), usePathname: () => "/onboarding", useSearchParams: () => new URLSearchParams() }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1", org_slug: "acme", role: "admin", name: "Ada" }, user: { id: "u1" } }) }));
let githubInfo: unknown = { configured: true, install_url: "https://github.com/apps/trustledger/installations/new" };
let githubInfoFails = false;
jest.mock("@/lib/useRealData", () => ({
  authedFetch: jest.fn(async (url: string) => {
    if (url === "/api/github-app/info") { if (githubInfoFails) throw new Error("boom"); return githubInfo; }
    return {};
  }),
  getAuthHeader: async () => ({}),
}));

import OnboardingPage from "@/app/onboarding/page";

beforeEach(() => {
  localStorage.removeItem("tl_onboarding_done"); push.mockClear();
  githubInfo = { configured: true, install_url: "https://github.com/apps/trustledger/installations/new" }; githubInfoFails = false;
});

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

  describe("Connect GitHub step", () => {
    const openGithubStep = () => { localStorage.setItem("tl_onboarding_done", JSON.stringify(["welcome"])); render(<OnboardingPage />); };

    it("a customer, with the app already set up: one Install button, nothing about creating an app or environment variables", async () => {
      openGithubStep();
      const link = await screen.findByRole("link", { name: /Install on GitHub/ });
      expect(link).toHaveAttribute("href", "https://github.com/apps/trustledger/installations/new");
      expect(screen.queryByText(/Create it for me in one click/)).toBeNull();
      expect(screen.queryByText(/GITHUB_APP_PRIVATE_KEY/)).toBeNull();
      expect(screen.queryByText(/isn.t connected to GitHub yet/)).toBeNull();
    });

    it("no app set up yet: a short note and a link for whoever runs the deployment; the app-creation guide is not in the wizard", async () => {
      githubInfo = { configured: false, install_url: null };
      openGithubStep();
      expect(await screen.findByText(/isn.t connected to GitHub yet/)).toBeInTheDocument();
      expect(screen.getByRole("link", { name: /I run this deployment/ })).toHaveAttribute("href", "/setup/github-app");
      expect(screen.queryByRole("link", { name: /Install on GitHub/ })).toBeNull();
      // creating the app, its permissions and its credentials are the operator's one-time job, on /setup/github-app
      expect(screen.queryByText(/GITHUB_APP_PRIVATE_KEY/)).toBeNull();
      expect(screen.queryByText(/Repository permissions/)).toBeNull();
      expect(screen.queryByText(/Give TrustLedger the app/)).toBeNull();
    });

    it("app set up but its link can't be loaded, or the check fails: a retry, never the creation guide", async () => {
      githubInfo = { configured: true, install_url: null };
      openGithubStep();
      expect(await screen.findByText(/couldn.t get the GitHub install link/)).toBeInTheDocument();
      expect(screen.queryByText(/Create it for me in one click/)).toBeNull();
    });
    it("the check itself failing offers a retry", async () => {
      githubInfoFails = true;
      openGithubStep();
      expect(await screen.findByText(/couldn.t check the GitHub connection/)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    });
  });
});
