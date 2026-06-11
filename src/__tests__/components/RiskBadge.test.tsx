import React from "react";
import { render, screen } from "@testing-library/react";
import RiskBadge from "@/components/RiskBadge";

describe("RiskBadge", () => {
  it("renders CRITICAL label", () => {
    render(<RiskBadge level="CRITICAL" />);
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
  });

  it("renders HIGH label", () => {
    render(<RiskBadge level="HIGH" />);
    expect(screen.getByText("HIGH")).toBeInTheDocument();
  });

  it("renders MEDIUM label", () => {
    render(<RiskBadge level="MEDIUM" />);
    expect(screen.getByText("MEDIUM")).toBeInTheDocument();
  });

  it("renders LOW label", () => {
    render(<RiskBadge level="LOW" />);
    expect(screen.getByText("LOW")).toBeInTheDocument();
  });

  it("renders UNKNOWN label", () => {
    render(<RiskBadge level="UNKNOWN" />);
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
  });

  it("does not throw for any valid level", () => {
    const levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
    levels.forEach(l => {
      expect(() => render(<RiskBadge level={l} />)).not.toThrow();
    });
  });
});
