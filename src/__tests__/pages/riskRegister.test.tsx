import React from "react";
import { render, screen } from "@testing-library/react";

jest.mock("@/components/AuthGuard",    () => ({ __esModule:true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/PageSkeleton", () => ({ __esModule:true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/toast", () => ({
  useToast:        () => ({ toast: null, setToast: jest.fn() }),
  useToastHelpers: () => ({ success: jest.fn(), error: jest.fn(), info: jest.fn(), warn: jest.fn() }),
  ToastProvider:   ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

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

  it("shows an empty state when no risks are loaded", () => {
    // No network/auth in this render, so deriveRisks() never runs and the
    // register is genuinely empty -- this asserts the real empty-state
    // copy rather than hardcoded risk IDs the app no longer produces
    // (risks are now derived from live scan data, see deriveRisks()).
    render(<RiskRegisterPage />);
    expect(screen.getByText("No risks match this filter")).toBeInTheDocument();
  });
});
