/**
 * Dashboard: the Security Health gauge shows its real inputs, and the single "Needs attention" panel.
 */
import { fireEvent, render, screen } from "@testing-library/react";
import HealthScoreGauge, { healthScoreParts } from "@/components/HealthScoreGauge";
import AttentionPanel from "@/components/dashboard/AttentionPanel";
import type { DashboardData } from "@/types";

describe("health score", () => {
  it("is the sum of three real parts: attestation (60), human-written share (25), clean deploys (15)", () => {
    expect(healthScoreParts({ attestation_rate: 0.71, ai_pct: 0.6, blocked_deploys: 9 })).toMatchObject({ total: 53 });
    expect(healthScoreParts({ attestation_rate: 1, ai_pct: 0, blocked_deploys: 0 }).total).toBe(100);
    expect(healthScoreParts({ attestation_rate: 0, ai_pct: 1, blocked_deploys: 2 })).toMatchObject({ attestation: 0, human: 0, deploys: 9, total: 9 });
  });

  it("the gauge shows each factor's actual value and points — not numbers back-derived from the total", () => {
    render(<HealthScoreGauge score={53} inputs={{ attestation_rate: 0.71, ai_pct: 0.6, blocked_deploys: 9 }} />);
    expect(screen.getByText("· 71% attested")).toBeInTheDocument();
    expect(screen.getByText("43/60")).toBeInTheDocument();
    expect(screen.getByText("· 40% of code")).toBeInTheDocument();
    expect(screen.getByText("10/25")).toBeInTheDocument();
    expect(screen.getByText("· 9 repos waiting")).toBeInTheDocument();
    expect(screen.getByText("0/15")).toBeInTheDocument();
    expect(screen.queryByText("88%")).not.toBeInTheDocument();
  });
});

function data(over: Partial<DashboardData> = {}): DashboardData {
  return {
    repos: [], overall_ai_pct: 0.3, attestation_rate: 0.7, unattested_deploy_count: 0, scan_count: 0, file_count: 0,
    risk_trend: [], top_risk_files: [], sla_breach_files: [],
    ...over,
  } as unknown as DashboardData;
}
const risky = (risk: "CRITICAL" | "HIGH", attested = false) => ({ repo: "acme/api", file_path: `src/${risk}.ts`, ai_pct: 0.9, risk_score: risk, pr_number: 1, attested });
const breach = (i: number) => ({ scan_id: `s${i}`, file_path: `src/f${i}.ts`, repo: "acme/api", risk_score: i % 2 ? "HIGH" : "CRITICAL", sla_deadline: new Date(Date.now() - 5 * 3600_000).toISOString() });

describe("Needs attention panel", () => {
  it("renders nothing when nothing needs attention", () => {
    const { container } = render(<AttentionPanel data={data()} violationStatuses={{}} openSecrets={0} unresolvedRepoScans={[]} sla={{ crit: 0, high: 0, total: 0 }} showQueues />);
    expect(container).toBeEmptyDOMElement();
  });

  it("puts deploys awaiting sign-off, SLA breaches and the open queues in one panel", () => {
    render(<AttentionPanel
      data={data({ unattested_deploy_count: 2, top_risk_files: [risky("CRITICAL"), risky("HIGH"), risky("HIGH", true)] as never, sla_breach_files: [breach(1), breach(2)] as never })}
      violationStatuses={{}} openSecrets={3}
      unresolvedRepoScans={[{ repoName: "api", scanId: "s1" }]}
      sla={{ crit: 1, high: 1, total: 2 }} showQueues />);
    const panel = screen.getByRole("region", { name: "Needs attention" });
    expect(panel).toHaveTextContent("2 repos awaiting sign-off");
    expect(screen.getByRole("link", { name: "api →" })).toHaveAttribute("href", "/pr/s1");
    expect(panel).toHaveTextContent("Attestation SLA breached");
    expect(panel).toHaveTextContent("1 CRITICAL · 24 h");
    expect(screen.getByRole("link", { name: /1 CRITICAL unattested/ })).toHaveAttribute("href", "/violations");
    expect(screen.getByRole("link", { name: /1 HIGH unattested/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /3 open secrets/ })).toHaveAttribute("href", "/secrets");
    // The deploy count is a row, not repeated again as a chip.
    expect(screen.queryByRole("link", { name: /deploys blocked/ })).not.toBeInTheDocument();
    expect(screen.getAllByText(/repos? awaiting sign-off/)).toHaveLength(1);
  });

  it("lists the first three overdue files and expands to the rest", () => {
    render(<AttentionPanel data={data({ sla_breach_files: [1, 2, 3, 4, 5].map(breach) as never })} violationStatuses={{}} openSecrets={0}
      unresolvedRepoScans={[]} sla={{ crit: 2, high: 3, total: 5 }} showQueues />);
    expect(screen.getAllByText(/h overdue/)).toHaveLength(3);
    fireEvent.click(screen.getByRole("button", { name: "Show 2 more files →" }));
    expect(screen.getAllByText(/h overdue/)).toHaveLength(5);
  });

  it("developers see their deploys and SLA rows, without the org-wide queues", () => {
    render(<AttentionPanel data={data({ unattested_deploy_count: 1, top_risk_files: [risky("CRITICAL")] as never })} violationStatuses={{}} openSecrets={4}
      unresolvedRepoScans={[]} sla={null} showQueues={false} />);
    expect(screen.getByText("1 repo awaiting sign-off")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /open secrets/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /CRITICAL unattested/ })).not.toBeInTheDocument();
  });
});
