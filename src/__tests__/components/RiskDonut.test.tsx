import React from "react";
import { render, screen } from "@testing-library/react";
import RiskDonut from "@/components/RiskDonut";

// Recharts' ResponsiveContainer needs real layout dimensions jsdom doesn't
// provide; mock it to just render children so the surrounding labels
// (which is what these tests actually check) still render.
jest.mock("recharts", () => {
  const actual = jest.requireActual("recharts");
  return {
    ...actual,
    ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  };
});

describe("RiskDonut", () => {
  it("prefers exact `totals` over summing the (row-limited) trend array", () => {
    // Trend array under-counts (as it would for a vulnerability-dense org
    // whose per-week breakdown got capped) -- totals should win regardless.
    const data = [{ date: "2026-01-05", critical_count: 1, high_count: 1, medium_count: 1 }];
    const totals = { critical_count: 140, high_count: 385, medium_count: 475 };

    render(<RiskDonut data={data} attestationRate={0.5} totals={totals} />);

    expect(screen.getByText("1000")).toBeInTheDocument(); // center total
    expect(screen.getByText("140")).toBeInTheDocument();
    expect(screen.getByText("385")).toBeInTheDocument();
    expect(screen.getByText("475")).toBeInTheDocument();
  });

  it("falls back to summing `data` when totals is not provided", () => {
    const data = [
      { date: "2026-01-05", critical_count: 2, high_count: 3, medium_count: 1 },
      { date: "2026-01-12", critical_count: 1, high_count: 0, medium_count: 2 },
    ];

    render(<RiskDonut data={data} attestationRate={0.5} />);

    expect(screen.getByText("9")).toBeInTheDocument(); // center total: 3+3+3
  });

  it("shows the all-clear state when there are no risk files", () => {
    render(<RiskDonut data={[]} attestationRate={1} totals={{ critical_count: 0, high_count: 0, medium_count: 0 }} />);
    expect(screen.getByText("All clear")).toBeInTheDocument();
  });
});
