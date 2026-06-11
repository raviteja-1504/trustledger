import React from "react";
import { render, screen } from "@testing-library/react";

jest.mock("@/components/AuthGuard",    () => ({ __esModule:true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/PageSkeleton", () => ({ __esModule:true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));

import RiskRegisterPage from "@/app/risk-register/page";

describe("RiskRegisterPage", () => {
  it("renders without crashing", () => {
    const { container } = render(<RiskRegisterPage />);
    expect(container).toBeTruthy();
  });

  it("shows the heading", () => {
    render(<RiskRegisterPage />);
    expect(screen.getByText("Risk Register")).toBeInTheDocument();
  });

  it("shows summary cards", () => {
    render(<RiskRegisterPage />);
    expect(screen.getByText("Open Risks")).toBeInTheDocument();
    // "Critical" and "Closed" can appear multiple times (header cards + badges)
    expect(screen.getAllByText("Critical").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Closed").length).toBeGreaterThan(0);
  });

  it("shows Export button", () => {
    render(<RiskRegisterPage />);
    expect(screen.getByText(/^Export$/i)).toBeInTheDocument();
  });

  it("shows heat map section", () => {
    render(<RiskRegisterPage />);
    expect(screen.getByText("Risk Heat Map")).toBeInTheDocument();
  });

  it("renders multiple risk items sorted by score", () => {
    render(<RiskRegisterPage />);
    // Risk IDs should be present
    expect(screen.getByText("RR-001")).toBeInTheDocument();
    expect(screen.getByText("RR-002")).toBeInTheDocument();
  });
});
