import { render, screen, waitFor } from "@testing-library/react";

let status: Record<string, unknown> = { complete: false, org_name: "Acme", members: 1, has_scans: false };
let role = "admin";
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1", role } }) }));
jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn(async () => status) }));

import SetupBanner from "@/components/setup/SetupBanner";

beforeEach(() => { status = { complete: false, org_name: "Acme", members: 1, has_scans: false }; role = "admin"; });

describe("overview setup banner", () => {
  it("is offered to the creator of an organisation whose setup is not finished, linking to the wizard", async () => {
    render(<SetupBanner />);
    const link = await screen.findByRole("link", { name: "Start setup" });
    expect(link).toHaveAttribute("href", "/onboarding");
  });
  it("says how many steps are already done, and offers to continue", async () => {
    localStorage.setItem("tl_onboarding_done", JSON.stringify(["welcome", "github"]));
    render(<SetupBanner />);
    expect(await screen.findByRole("link", { name: "Continue setup" })).toHaveAttribute("href", "/onboarding");
    expect(screen.getByText(/2 of 4 steps done/)).toBeInTheDocument();
    localStorage.removeItem("tl_onboarding_done");
  });
  it("is not shown once setup is complete, to a member of a running organisation, or to a non-admin", async () => {
    status = { complete: true, members: 1 };
    const { unmount } = render(<SetupBanner />);
    await waitFor(() => expect(screen.queryByRole("link", { name: "Start setup" })).toBeNull());
    unmount();
    status = { complete: false, members: 4 };
    const second = render(<SetupBanner />);
    await waitFor(() => expect(screen.queryByRole("link", { name: "Start setup" })).toBeNull());
    second.unmount();
    role = "developer"; status = { complete: false, members: 1 };
    render(<SetupBanner />);
    await new Promise(r => setTimeout(r, 50));
    expect(screen.queryByRole("link", { name: "Start setup" })).toBeNull();
  });
});
