import React from "react";
import { render, screen, act } from "@testing-library/react";
import PageSkeleton from "@/components/PageSkeleton";

describe("PageSkeleton", () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it("shows skeleton initially, not children", () => {
    render(
      <PageSkeleton>
        <div data-testid="child">Loaded content</div>
      </PageSkeleton>
    );
    expect(screen.queryByTestId("child")).toBeNull();
  });

  it("shows children after 350ms", () => {
    render(
      <PageSkeleton>
        <div data-testid="child">Loaded content</div>
      </PageSkeleton>
    );
    act(() => { jest.advanceTimersByTime(400); });
    expect(screen.getByTestId("child")).toBeInTheDocument();
  });

  it("renders skeleton rows based on rows prop", () => {
    const { container } = render(
      <PageSkeleton rows={3}><div /></PageSkeleton>
    );
    // Skeleton rows are animate-pulse divs — at least some exist before timer fires
    const pulses = container.querySelectorAll(".animate-pulse");
    expect(pulses.length).toBeGreaterThan(0);
  });
});
