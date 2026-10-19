/**
 * Dashboard pieces rebuilt on real data: the Audit evidence card, recent activity without invented events, and the
 * Trust Score tile's top action.
 */
import { render, screen } from "@testing-library/react";
import { AuditEvidenceView } from "@/components/dashboard/AuditEvidenceCard";
import { deriveActivity } from "@/lib/dashboardActivity";
import { topAction } from "@/lib/governanceScore";
import type { EvidenceOverview } from "@/lib/evidenceEngine";
import type { DashboardData } from "@/types";

jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn() }));

const counts = (pass: number, partial = 0, fail = 0, not_tested = 0) => ({ pass, partial, fail, not_tested });

describe("Audit evidence card", () => {
  const overview: EvidenceOverview = {
    period_start: "a", period_end: "b", generated_at: "c",
    frameworks: [
      { id: "soc2", name: "SOC 2", short: "SOC 2", status_counts: counts(3, 1), controls: [] as never },
      { id: "iso27001", name: "ISO/IEC 27001:2022", short: "ISO 27001", status_counts: counts(5, 0, 1), controls: [] as never },
      { id: "aigov", name: "AI code governance", short: "AI governance", status_counts: counts(2, 0, 0, 2), controls: [] as never },
    ].map(f => ({ ...f, controls: Array.from({ length: Object.values(f.status_counts).reduce((a, b) => a + b, 0) }, (_, i) => ({ control_id: `c${i}`, control_name: "x", status: "pass" as const })) })),
    gaps: [
      { key: "independent_review", label: "Reviewer is not the author", status: "fail", gaps: ["2 self-approvals: the author signed off their own change", "second gap"] },
      { key: "review", label: "High-risk changes reviewed", status: "partial", gaps: ["3 high-risk files not yet reviewed"] },
    ],
  };

  it("shows evidence counts per framework, never a compliance percentage", () => {
    render(<AuditEvidenceView overview={overview} />);
    const card = screen.getByRole("region", { name: "Audit evidence" });
    expect(card).toHaveTextContent("SOC 2");
    expect(card).toHaveTextContent("3 of 4 controls with evidence");
    expect(card).toHaveTextContent("5 of 6 controls with evidence");
    expect(card).toHaveTextContent("1 with gaps");
    expect(card).toHaveTextContent("1 failing");
    expect(card).toHaveTextContent("2 no evidence yet");
    expect(card.textContent).not.toMatch(/\d+%|compliant|audit-ready/i);
    expect(screen.getByRole("link", { name: /SOC 2/ })).toHaveAttribute("href", "/reports?fw=SOC2");
    expect(screen.getByRole("link", { name: /AI code governance/ })).toHaveAttribute("href", "/reports?fw=AIGOV");
  });

  it("lists the first gap of each failing check, and says what it is not", () => {
    render(<AuditEvidenceView overview={overview} />);
    expect(screen.getByText(/2 self-approvals/)).toBeInTheDocument();
    expect(screen.getByText(/3 high-risk files not yet reviewed/)).toBeInTheDocument();
    expect(screen.queryByText(/second gap/)).not.toBeInTheDocument();
    expect(screen.getByText(/not a SOC 2 report/)).toBeInTheDocument();
    expect(screen.getByText(/EU AI Act isn.t assessed/)).toBeInTheDocument();
  });

  it("with no gaps says so", () => {
    render(<AuditEvidenceView overview={{ ...overview, gaps: [] }} />);
    expect(screen.getByText(/No gaps found/)).toBeInTheDocument();
  });
});

describe("recent activity", () => {
  const data = {
    repos: [
      { repo: "acme/api", latest_scan_id: "s1", last_scan: "2026-10-18", ai_pct: 0.4, attestation_rate: 0.2, file_count: 100, scan_count: 3 },
      { repo: "acme/never", latest_scan_id: "s2", last_scan: null, ai_pct: 0, attestation_rate: 0, file_count: 0, scan_count: 0 },
    ],
    top_risk_files: [
      { repo: "acme/api", file_path: "src/a.ts", ai_pct: 0.9, risk_score: "HIGH", attested: true, attested_at: "2026-10-19T08:00:00Z", attested_by: "carol@acme.test", scan_id: "s1", pr_number: 12 },
      { repo: "acme/api", file_path: "src/b.ts", ai_pct: 0.9, risk_score: "HIGH", attested: true, scan_id: "s1", pr_number: 12 },
      { repo: "acme/api", file_path: "src/c.ts", ai_pct: 0.9, risk_score: "CRITICAL", attested: false, scan_id: "s1", pr_number: 12 },
    ],
    risk_trend: [{ date: "2026-10-01", high_count: 9, critical_count: 9, medium_count: 1 }],
  } as unknown as DashboardData;

  it("only real events: no invented PR numbers, risk levels, file counts or padding", () => {
    const ev = deriveActivity(data);
    expect(ev).toHaveLength(2);
    expect(ev[0]).toMatchObject({ type: "attestation", file_path: "src/a.ts", pr_number: 12, reviewer_email: "carol@acme.test", timestamp: "2026-10-19T08:00:00Z" });
    expect(ev[1]).toMatchObject({ type: "scan", repo: "acme/api", pr_number: 0, overall_risk: "", file_count: 0, scan_id: "s1" });
  });

  it("caps the list", () => {
    expect(deriveActivity(data, 1)).toHaveLength(1);
  });
});

describe("Trust Score top action", () => {
  it("picks the single action worth the most points", () => {
    expect(topAction([
      { actions: [{ label: "a", href: "/a", gain: 10 }, { label: "b", href: "/b", gain: 40 }] },
      { actions: [{ label: "c", href: "/c", gain: 25 }] },
      {},
    ])).toEqual({ label: "b", href: "/b", gain: 40 });
    expect(topAction([{ actions: [{ label: "z", href: "/z", gain: 0 }] }])).toBeNull();
    expect(topAction([])).toBeNull();
  });
});
