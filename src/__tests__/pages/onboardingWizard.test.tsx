import { render, screen, waitFor, fireEvent } from "@testing-library/react";

const push = jest.fn();
jest.mock("next/navigation", () => ({ useRouter: () => ({ push, replace: jest.fn() }), usePathname: () => "/onboarding", useSearchParams: () => new URLSearchParams() }));
let authValue: Record<string, unknown> = { profile: { org_id: "org-1", org_slug: "acme", org_name: "Acme Inc", role: "admin", name: "Ada", email: "ada@acme.dev" }, user: { id: "u1", email: "ada@acme.dev", app_metadata: { provider: "email" } } };
jest.mock("@/lib/auth", () => ({ useAuth: () => authValue }));
let onboardingGet: Record<string, unknown> = { github_org: null, org_name: "Acme Inc" };
let githubInfo: unknown = { configured: true, install_url: "https://github.com/apps/trustledger/installations/new" };
let githubInfoFails = false;
let saveOrgError: string | null = null;
jest.mock("@/lib/useRealData", () => ({
  authedFetch: jest.fn(async (url: string, opts?: { body?: string }) => {
    if (url === "/api/github-app/info") { if (githubInfoFails) throw new Error("boom"); return githubInfo; }
    if (url.startsWith("/api/github-app/installation?id=")) return { login: "acme-corp" };
    if (url === "/api/onboarding" && opts?.body?.includes("save_github_org") && saveOrgError) throw new Error(saveOrgError);
    if (url === "/api/onboarding" && !opts) return onboardingGet;
    return {};
  }),
  getAuthHeader: async () => ({}),
}));

import OnboardingPage from "@/app/onboarding/page";

beforeEach(() => {
  localStorage.removeItem("tl_onboarding_done"); push.mockClear();
  githubInfo = { configured: true, install_url: "https://github.com/apps/trustledger/installations/new" }; githubInfoFails = false;
  saveOrgError = null; window.history.pushState({}, "", "/onboarding");
  onboardingGet = { github_org: null, org_name: "Acme Inc" };
  authValue = { profile: { org_id: "org-1", org_slug: "acme", org_name: "Acme Inc", role: "admin", name: "Ada", email: "ada@acme.dev" }, user: { id: "u1", email: "ada@acme.dev", app_metadata: { provider: "email" } } };
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
      // same tab: GitHub sends the person back to the wizard, rather than leaving this tab behind
      expect(link).not.toHaveAttribute("target");
      expect(screen.queryByText(/Create it for me in one click/)).toBeNull();
      expect(screen.queryByText(/GITHUB_APP_PRIVATE_KEY/)).toBeNull();
      expect(screen.queryByText(/isn.t connected to GitHub yet/)).toBeNull();
      // GitHub uses the account signed in on this browser: the wizard says so and links to sign out first
      expect(screen.getByText(/signed into in this browser/)).toBeInTheDocument();
      expect(screen.getByRole("link", { name: /sign out of GitHub first/ })).toHaveAttribute("href", "https://github.com/logout");
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

    it("returning from GitHub after installing: shows where it was installed, fills in the organisation handle, hides the Install button", async () => {
      window.history.pushState({}, "", "/onboarding?installation_id=123&setup_action=install");
      openGithubStep();
      expect(await screen.findByText(/GitHub App installed on acme-corp/)).toBeInTheDocument();
      expect(screen.getByPlaceholderText("e.g. acme-corp")).toHaveValue("acme-corp");
      expect(screen.queryByRole("link", { name: /^Install on GitHub/ })).toBeNull();
    });

    it("an error the install callback sends back is shown", async () => {
      window.history.pushState({}, "", "/onboarding?error=installation_save_failed");
      openGithubStep();
      expect(await screen.findByText(/couldn.t save the connection/)).toBeInTheDocument();
    });

    it("an install that is waiting for an organisation owner's approval says so, rather than looking installed", async () => {
      window.history.pushState({}, "", "/onboarding?setup_action=request");
      openGithubStep();
      expect(await screen.findByText(/waiting for approval/)).toBeInTheDocument();
      expect(screen.queryByText(/GitHub App installed on/)).toBeNull();
    });

    it("a GitHub organisation another TrustLedger organisation holds: the error is shown and setup does not move on", async () => {
      saveOrgError = "github_org_taken";
      window.history.pushState({}, "", "/onboarding?installation_id=123&setup_action=install");
      openGithubStep();
      await screen.findByText(/GitHub App installed on acme-corp/);
      screen.getByRole("button", { name: /Save and continue/ }).click();
      expect(await screen.findByText(/already linked to another TrustLedger organisation/)).toBeInTheDocument();
      expect(screen.getByText(/Step 2 of 5/)).toBeInTheDocument();
    });

    describe("the GitHub account name field", () => {
      it("explains what the field is, with an example, before asking for it", async () => {
        openGithubStep();
        expect(await screen.findByText("What do I type here?")).toBeInTheDocument();
        expect(screen.getByText(/comes right after/)).toBeInTheDocument();
        expect(screen.getByText(/If it does not match, pull requests are not scanned/)).toBeInTheDocument();
        expect(screen.getByText(/your email address/)).toBeInTheDocument();
        expect(screen.getByLabelText(/GitHub name/)).toBeInTheDocument();
      });

      it("is not pre-filled from the TrustLedger organisation's slug", async () => {
        openGithubStep();
        expect(await screen.findByPlaceholderText("e.g. acme-corp")).toHaveValue("");
      });

      it("is pre-filled with the handle already saved, and says so", async () => {
        onboardingGet = { github_org: "cyberminutetech", org_name: "CyberMinute" };
        openGithubStep();
        await waitFor(() => expect(screen.getByPlaceholderText("e.g. acme-corp")).toHaveValue("cyberminutetech"));
        expect(screen.getByText(/Currently linked/)).toHaveTextContent("github.com/cyberminutetech");
      });

      it("shows what will be saved and which organisation it is for", async () => {
        openGithubStep();
        const box = await screen.findByPlaceholderText("e.g. acme-corp");
        fireEvent.change(box, { target: { value: "Acme-Corp" } });
        expect(screen.getByText(/will be scanned in/)).toHaveTextContent("github.com/acme-corp/…");
        expect(screen.getByText(/will be scanned in/)).toHaveTextContent("Acme Inc");
      });

      it("an email address is refused with a message and is not sent", async () => {
        const { authedFetch } = jest.requireMock("@/lib/useRealData") as { authedFetch: jest.Mock };
        openGithubStep();
        const box = await screen.findByPlaceholderText("e.g. acme-corp");
        authedFetch.mockClear();
        fireEvent.change(box, { target: { value: "ada@acme.dev" } });
        fireEvent.blur(box);
        expect(await screen.findByText(/looks like an email address/)).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: /Save and continue/ }));
        expect(authedFetch).not.toHaveBeenCalledWith("/api/onboarding", expect.objectContaining({ method: "POST" }));
        expect(screen.getByText(/Step 2 of 5/)).toBeInTheDocument();
      });

      it("a pasted repository address is sent as the account name", async () => {
        const { authedFetch } = jest.requireMock("@/lib/useRealData") as { authedFetch: jest.Mock };
        openGithubStep();
        const box = await screen.findByPlaceholderText("e.g. acme-corp");
        fireEvent.change(box, { target: { value: "https://github.com/Acme-Corp/payments-api" } });
        expect(screen.getByText(/We tidied what you typed/)).toBeInTheDocument();
        authedFetch.mockClear();
        fireEvent.click(screen.getByRole("button", { name: /Save and continue/ }));
        await waitFor(() => expect(authedFetch).toHaveBeenCalledWith("/api/onboarding", expect.objectContaining({ body: JSON.stringify({ action: "save_github_org", github_org: "acme-corp" }) })));
      });

      it("asks for one name only: no second, personal-username field", async () => {
        openGithubStep();
        await screen.findByPlaceholderText("e.g. acme-corp");
        expect(screen.queryByText(/personal GitHub username/i)).toBeNull();
        expect(screen.getAllByRole("textbox")).toHaveLength(1);
      });

      it("a person who signed in with GitHub has their own username saved for them, once", async () => {
        const { authedFetch } = jest.requireMock("@/lib/useRealData") as { authedFetch: jest.Mock };
        authValue = { ...authValue, user: { id: "u1", email: "ada@acme.dev", app_metadata: { provider: "github" }, user_metadata: { user_name: "ada-codes" } } };
        openGithubStep();
        fireEvent.change(await screen.findByPlaceholderText("e.g. acme-corp"), { target: { value: "acme-corp" } });
        authedFetch.mockClear();
        fireEvent.click(screen.getByRole("button", { name: /Save and continue/ }));
        await waitFor(() => expect(authedFetch).toHaveBeenCalledWith("/api/onboarding", expect.objectContaining({ body: JSON.stringify({ action: "save_github_login", github_login: "ada-codes" }) })));
      });

      it("one who already has a username saved is not overwritten", async () => {
        const { authedFetch } = jest.requireMock("@/lib/useRealData") as { authedFetch: jest.Mock };
        authValue = { profile: { ...(authValue.profile as object), github_login: "ada-saved" }, user: { id: "u1", email: "ada@acme.dev", app_metadata: { provider: "github" }, user_metadata: { user_name: "ada-codes" } } };
        openGithubStep();
        fireEvent.change(await screen.findByPlaceholderText("e.g. acme-corp"), { target: { value: "acme-corp" } });
        authedFetch.mockClear();
        fireEvent.click(screen.getByRole("button", { name: /Save and continue/ }));
        await waitFor(() => expect(authedFetch).toHaveBeenCalledWith("/api/onboarding", expect.objectContaining({ body: JSON.stringify({ action: "save_github_org", github_org: "acme-corp" }) })));
        expect(authedFetch).not.toHaveBeenCalledWith("/api/onboarding", expect.objectContaining({ body: expect.stringContaining("save_github_login") }));
      });

      it("warns when the name differs from the account the app was installed on, and offers the installed one", async () => {
        window.history.pushState({}, "", "/onboarding?installation_id=123&setup_action=install");
        openGithubStep();
        await screen.findByText(/GitHub App installed on acme-corp/);
        fireEvent.change(screen.getByPlaceholderText("e.g. acme-corp"), { target: { value: "someone-else" } });
        expect(screen.getByText(/would not be scanned/)).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: "Use acme-corp" }));
        expect(screen.getByPlaceholderText("e.g. acme-corp")).toHaveValue("acme-corp");
        expect(screen.queryByText(/would not be scanned/)).toBeNull();
      });
    });
  });

  describe("who is signed in", () => {
    it("shows the person, how they signed in and the organisation, on every step", async () => {
      render(<OnboardingPage />);
      const box = await screen.findByTestId("signed-in-as");
      expect(box).toHaveTextContent("Ada");
      expect(box).toHaveTextContent("ada@acme.dev");
      expect(box).toHaveTextContent("with email and password");
      expect(box).toHaveTextContent("Acme Inc");
    });

    it("a GitHub sign-in shows the GitHub username", async () => {
      authValue = { ...authValue, user: { id: "u1", email: "ada@acme.dev", app_metadata: { provider: "github" }, user_metadata: { user_name: "ada-codes" } } };
      render(<OnboardingPage />);
      expect(await screen.findByTestId("signed-in-as")).toHaveTextContent("with GitHub (@ada-codes)");
    });

    it("'Not you? Sign out' signs out and returns to the login page", async () => {
      const signOut = jest.fn(async () => undefined);
      authValue = { ...authValue, signOut };
      render(<OnboardingPage />);
      fireEvent.click(await screen.findByRole("button", { name: "Not you? Sign out" }));
      await waitFor(() => expect(push).toHaveBeenCalledWith("/login"));
      expect(signOut).toHaveBeenCalled();
    });
  });
});
