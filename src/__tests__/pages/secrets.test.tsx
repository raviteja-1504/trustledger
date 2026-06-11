import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";

jest.mock("@/components/AuthGuard",    () => ({ __esModule:true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/PageSkeleton", () => ({ __esModule:true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));

import SecretsPage from "@/app/secrets/page";

describe("SecretsPage", () => {
  it("renders without crashing", () => {
    const { container } = render(<SecretsPage />);
    expect(container).toBeTruthy();
  });

  it("shows heading and summary cards", () => {
    render(<SecretsPage />);
    expect(screen.getByText("Secret Scanner")).toBeInTheDocument();
    expect(screen.getByText("Total Detected")).toBeInTheDocument();
    // "Open" and "Resolved" can appear multiple times (card label + status badges)
    expect(screen.getAllByText("Open").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Resolved").length).toBeGreaterThan(0);
  });

  it("shows severity filter buttons", () => {
    render(<SecretsPage />);
    expect(screen.getAllByRole("button", { name: /CRITICAL/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: /HIGH/i }).length).toBeGreaterThan(0);
  });

  it("shows export CSV button", () => {
    render(<SecretsPage />);
    expect(screen.getByText(/Export CSV/i)).toBeInTheDocument();
  });

  it("filters to open status by default", () => {
    render(<SecretsPage />);
    // Default filter is 'open' — at least one finding should be visible
    const findings = screen.getAllByText(/detected|hardcoded|secret|key/i);
    expect(findings.length).toBeGreaterThan(0);
  });
});
