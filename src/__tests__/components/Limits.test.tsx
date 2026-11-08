import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";
import { CapNote, CapNotice, LimitMeter } from "@/components/Limits";

describe("LimitMeter", () => {
  it("shows used / limit and stays quiet while there is room", () => {
    render(<LimitMeter label="Scans this month" noun="scans" used={20} limit={100} />);
    expect(screen.getByText("20 / 100")).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Scans this month" })).toHaveAttribute("aria-valuetext", "20 of 100");
    expect(screen.queryByText(/left on your plan|Over the limit|At the limit/)).toBeNull();
  });

  it("warns from 80% with how many are left and a way to the plans", () => {
    const { container } = render(<LimitMeter label="Members" noun="members" used={17} limit={20} />);
    expect(container.firstElementChild).toHaveAttribute("data-level", "warn");
    expect(screen.getByText(/3 of 20 members left on your plan/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "See plans" })).toHaveAttribute("href", "/billing");
  });

  it("says plainly when the cap is reached, and when it is passed", () => {
    const { container, rerender } = render(<LimitMeter label="Repos" noun="repositories" used={10} limit={10} />);
    expect(container.firstElementChild).toHaveAttribute("data-level", "full");
    expect(screen.getByText(/At the limit: all 10 repositories on your plan are used/)).toBeInTheDocument();
    rerender(<LimitMeter label="Repos" noun="repositories" used={12} limit={10} />);
    expect(container.firstElementChild).toHaveAttribute("data-level", "over");
    expect(screen.getByText(/Over the limit: 12 repositories against 10 on your plan/)).toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "12");
  });

  it("unlimited reads as infinity with no warning and an empty bar", () => {
    render(<LimitMeter label="Scans" noun="scans" used={999_999} limit={-1} />);
    expect(screen.getByText("999,999 / ∞")).toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuetext", "999,999, unlimited");
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("without an upgrade link the nudge is left out entirely", () => {
    render(<LimitMeter label="Members" noun="members" used={20} limit={20} upgradeHref={null} />);
    expect(screen.getByText(/At the limit: all 20 members on your plan are used\./)).toBeInTheDocument();
    expect(screen.queryByText(/Upgrade your plan/)).toBeNull();
    expect(screen.queryByRole("link")).toBeNull();
  });
});

describe("CapNotice", () => {
  it("says how many of the total are shown, why, and what to do", () => {
    render(<CapNotice cap="incidents" shown={1000} total={1432} noun="incidents" />);
    const note = screen.getByRole("status");
    expect(note).toHaveTextContent("Showing 1,000 of 1,432 incidents.");
    expect(note).toHaveTextContent("The incident list shows the most recent 1,000.");
    expect(note).toHaveTextContent("Filter by status or date to see older ones.");
    expect(note).toHaveAttribute("data-cap", "incidents");
  });
  it("without a known total, says the list was cut at the cap", () => {
    render(<CapNotice cap="apiSecurityEndpoints" shown={2000} noun="endpoints" />);
    expect(screen.getByRole("status")).toHaveTextContent("Showing the first 2,000 endpoints.");
  });
  it("renders nothing when nothing was cut", () => {
    const { container, rerender } = render(<CapNotice cap="incidents" shown={40} total={40} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<CapNotice cap="incidents" shown={999} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("CapNote", () => {
  it("states the cap beside the control it limits", () => {
    render(<CapNote cap="baselineFindings" />);
    expect(screen.getByText(/Baseline accepts at most 5,000 findings in one go\. Run Baseline again to accept the rest\./)).toBeInTheDocument();
  });
});
