import React from "react";
import { render, screen } from "@testing-library/react";

// Mock AuthGuard and PageSkeleton so they just render children
jest.mock("@/components/AuthGuard",    () => ({ __esModule:true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/PageSkeleton", () => ({ __esModule:true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/toast", () => ({
  useToast:        () => ({ toast: null, setToast: jest.fn() }),
  useToastHelpers: () => ({ success: jest.fn(), error: jest.fn(), info: jest.fn(), warn: jest.fn() }),
  ToastProvider:   ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

import ViolationsPage from "@/app/violations/page";

describe("ViolationsPage", () => {
  it("renders without crashing", () => {
    const { container } = render(<ViolationsPage />);
    expect(container).toBeTruthy();
  });

  it("shows the page heading", () => {
    render(<ViolationsPage />);
    expect(screen.getByText("Policy Violations")).toBeInTheDocument();
  });

  it("shows summary stat cards", () => {
    render(<ViolationsPage />);
    expect(screen.getByText("Open Violations")).toBeInTheDocument();
    expect(screen.getByText("Critical Active")).toBeInTheDocument();
  });

  it("shows at least one violation by default (open filter)", () => {
    render(<ViolationsPage />);
    // At least one item labelled open should be present
    expect(screen.getAllByText(/unattested|blocked|awaiting|breach/i).length).toBeGreaterThan(0);
  });
});
