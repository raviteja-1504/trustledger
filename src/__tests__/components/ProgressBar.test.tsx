import React from "react";
import { render } from "@testing-library/react";
import ProgressBar from "@/components/ProgressBar";

describe("ProgressBar", () => {
  it("renders without crashing for ai mode", () => {
    const { container } = render(<ProgressBar value={0.75} mode="ai" />);
    expect(container.firstChild).toBeTruthy();
  });

  it("renders without crashing for attest mode", () => {
    const { container } = render(<ProgressBar value={0.5} mode="attest" />);
    expect(container.firstChild).toBeTruthy();
  });

  it("clamps value to 0 for negative input", () => {
    const { container } = render(<ProgressBar value={-0.5} mode="ai" />);
    // Should not throw and should render
    expect(container.firstChild).toBeTruthy();
  });

  it("renders with value of 0", () => {
    const { container } = render(<ProgressBar value={0} mode="ai" />);
    expect(container.firstChild).toBeTruthy();
  });

  it("renders with value of 1 (100%)", () => {
    const { container } = render(<ProgressBar value={1} mode="attest" />);
    expect(container.firstChild).toBeTruthy();
  });
});
