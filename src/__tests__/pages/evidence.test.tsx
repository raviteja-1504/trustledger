import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";

jest.mock("@/components/AuthGuard",    () => ({ __esModule:true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/PageSkeleton", () => ({ __esModule:true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));

import EvidencePage from "@/app/evidence/page";

describe("EvidencePage", () => {
  it("renders without crashing", () => {
    const { container } = render(<EvidencePage />);
    expect(container).toBeTruthy();
  });

  it("shows the heading", () => {
    render(<EvidencePage />);
    expect(screen.getByText("Evidence Locker")).toBeInTheDocument();
  });

  it("shows three framework selector cards", () => {
    render(<EvidencePage />);
    expect(screen.getByText("SOC 2")).toBeInTheDocument();
    expect(screen.getByText("EU AI Act")).toBeInTheDocument();
    expect(screen.getByText("PCI-DSS")).toBeInTheDocument();
  });

  it("shows SOC 2 controls by default", () => {
    render(<EvidencePage />);
    expect(screen.getByText("CC6.1")).toBeInTheDocument();
    expect(screen.getByText("CC8.1")).toBeInTheDocument();
  });

  it("switches to EU AI Act controls on click", () => {
    render(<EvidencePage />);
    const euBtn = screen.getAllByText("EU AI Act")[0];
    fireEvent.click(euBtn);
    expect(screen.getByText("Art.9")).toBeInTheDocument();
    expect(screen.getByText("Art.14")).toBeInTheDocument();
  });

  it("shows evidence status badges", () => {
    render(<EvidencePage />);
    expect(screen.getAllByText("Collected").length).toBeGreaterThan(0);
  });
});
