import { render, screen, waitFor } from "@testing-library/react";

let info: unknown = { configured: false };
jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn(async () => info) }));

import GithubAppSetupPage from "@/app/setup/github-app/page";

describe("operator page: create the TrustLedger GitHub App", () => {
  beforeEach(() => { info = { configured: false }; });

  it("has the one-click button that creates the app with every field, permission and event filled in", () => {
    render(<GithubAppSetupPage />);
    expect(screen.getAllByRole("button", { name: /Create the GitHub App/ })).toHaveLength(1);
    expect(screen.getByText(/pre-configured with the correct webhook URL/)).toBeInTheDocument();
  });

  it("says so when the deployment already has a GitHub App, and that creating another replaces nothing by itself", async () => {
    info = { configured: true };
    render(<GithubAppSetupPage />);
    expect(await screen.findByText(/This deployment already has a GitHub App/)).toBeInTheDocument();
    expect(screen.getByText(/Customers never need this page/)).toBeInTheDocument();
  });
  it("shows no such note while no app is set up", async () => {
    render(<GithubAppSetupPage />);
    await waitFor(() => expect(screen.getAllByRole("button", { name: /Create the GitHub App/ })).toHaveLength(1));
    expect(screen.queryByText(/already has a GitHub App/)).toBeNull();
  });
});
