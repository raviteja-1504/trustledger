import { fireEvent, render, screen, within } from "@testing-library/react";
import GithubAppGuide from "@/components/onboarding/GithubAppGuide";

describe("setup wizard: Connect GitHub instructions", () => {
  it("offers the one-click creation first", () => {
    render(<GithubAppGuide />);
    expect(screen.getByRole("link", { name: /Create it for me in one click/ })).toHaveAttribute("href", "/setup/github-app");
  });

  it("lists every field of GitHub's form with the value to enter, built from this site's address", () => {
    render(<GithubAppGuide />);
    const origin = window.location.origin;
    expect(screen.getByTestId("f-name")).toHaveTextContent("TrustLedger");
    expect(screen.getByTestId("f-desc")).toHaveTextContent("AI code provenance");
    expect(screen.getByTestId("f-home")).toHaveTextContent(origin);
    expect(screen.getByTestId("f-callback")).toHaveTextContent(`${origin}/api/auth/callback`);
    expect(screen.getByTestId("f-setup")).toHaveTextContent(`${origin}/onboarding`);
    expect(screen.getByTestId("f-webhook")).toHaveTextContent(`${origin}/api/webhook/github`);
    // the checkboxes and defaults to set
    expect(screen.getByText(/Request user authorization \(OAuth\) during installation/)).toBeInTheDocument();
    expect(screen.getByText(/Redirect on update/)).toBeInTheDocument();
    expect(screen.getByText("SSL verification", { exact: false })).toBeInTheDocument();
  });

  it("lists exactly the repository permissions, the access level of each, the events, and where it can be installed", () => {
    render(<GithubAppGuide />);
    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row").slice(1).map(r => within(r).getAllByRole("cell").slice(0, 2).map(c => c.textContent));
    expect(rows).toEqual([
      ["Checks", "Read and write"],
      ["Contents", "Read-only"],
      ["Metadata", "Read-only"],
      ["Pull requests", "Read and write"],
    ]);
    expect(screen.queryByText("Commit statuses")).toBeNull();
    expect(screen.getByText("Pull request")).toBeInTheDocument();
    expect(screen.getByText("Check run")).toBeInTheDocument();
    expect(screen.getByText(/Only on this account/)).toBeInTheDocument();
    expect(screen.getByText(/Organization permissions/)).toBeInTheDocument();
  });

  it("generates a long random webhook secret on request, and says it must also be GITHUB_WEBHOOK_SECRET", () => {
    render(<GithubAppGuide />);
    expect(screen.queryByTestId("f-secret")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Generate a secret" }));
    expect(screen.getByTestId("f-secret").textContent).toMatch(/^[0-9a-f]{48}$/);
    expect(screen.getByText(/same value as GITHUB_WEBHOOK_SECRET/)).toBeInTheDocument();
  });

  it("tells the operator which three values to set, and to install the app on the repositories", () => {
    render(<GithubAppGuide />);
    for (const name of ["GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY", "GITHUB_WEBHOOK_SECRET"]) expect(screen.getAllByText(name).length).toBeGreaterThan(0);
    expect(screen.getByText(/Install App/)).toBeInTheDocument();
  });
});
