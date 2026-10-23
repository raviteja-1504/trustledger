/**
 * Dashboard building blocks: each turns real data into what's shown, and says so when data is missing rather than
 * inventing it.
 */
import { fireEvent, render, screen, within } from "@testing-library/react";
import TrustHero, { bandFor, scoreDelta, topActions } from "@/components/dashboard/TrustHero";
import KpiStrip, { buildKpis, type KpiInput } from "@/components/dashboard/KpiStrip";
import ReviewQueue, { buildQueue } from "@/components/dashboard/ReviewQueue";
import { EvidencePanel, SecretsPanel, ShadowAiPanel, countSecrets } from "@/components/dashboard/GovernancePanels";
import RepoTable, { buildRepoRows, sortRepoRows } from "@/components/dashboard/RepoTable";
import RiskPanel, { fillTrendWeeks, riskDirection } from "@/components/dashboard/RiskPanel";
import ActivityList from "@/components/dashboard/ActivityList";
import NeedsAttention, { buildAttention, type AttentionInput } from "@/components/dashboard/NeedsAttention";
import { activityKey, deriveActivity, mergeActivity } from "@/lib/dashboardActivity";
import type { GovernanceScore, Dimension } from "@/lib/governanceScore";
import type { ShadowSummary } from "@/lib/shadowAi";
import type { EvidenceOverview } from "@/lib/evidenceEngine";
import type { DashboardData, RepoStat, TopRiskFile } from "@/types";

jest.mock("next/dynamic", () => () => () => null);

const dim = (key: Dimension["key"], label: string, value: number, grade: Dimension["grade"], actions: Dimension["actions"] = []): Dimension =>
  ({ key, label, weight: 0.2, value, points: Math.round(value * 200), max_points: 200, gain: 0, grade, formula: "", facts: [], actions });

const score: GovernanceScore = {
  total: 640, band: "Fair", computed_at: "2026-10-19T00:00:00Z", repos: [],
  dimensions: [
    dim("exposure", "Open risk", 0.5, "F", [{ label: "Fix 3 CRITICAL findings in api", href: "/violations?repo=api", gain: 90 }]),
    dim("review", "Human review of risky code", 0.7, "C", [{ label: "Review 4 high-risk files", href: "/violations", gain: 60 }, { label: "Fix 3 CRITICAL findings in api", href: "/x", gain: 10 }]),
    dim("secrets", "Leaked secrets", 1, "A", []),
    dim("sla", "Fix deadlines met", 0.9, "A", [{ label: "Resolve 1 overdue finding", href: "/sla", gain: 15 }, { label: "Tiny", href: "/t", gain: 2 }]),
  ],
};

describe("Trust Score hero", () => {
  it("shows the score, band, every dimension with its grade, and the top actions by points", () => {
    render(<TrustHero score={score} history={[{ day: "2026-10-10", total: 600 }, { day: "2026-10-19", total: 640 }]} />);
    const hero = screen.getByRole("region", { name: "Trust Score" });
    expect(screen.getByRole("img", { name: "Trust Score 640 out of 1000" })).toBeInTheDocument();
    expect(hero).toHaveTextContent("Fair");
    expect(hero).toHaveTextContent("▲ 40 pts in 7 days");
    expect(hero).toHaveTextContent("Human review of risky code");
    const actions = within(hero).getAllByRole("link").filter(a => /\+\d+/.test(a.textContent ?? ""));
    expect(actions.map(a => a.textContent)).toEqual(["1Fix 3 CRITICAL findings in api+90 pts", "2Review 4 high-risk files+60 pts", "3Resolve 1 overdue finding+15 pts"]);
    expect(actions[0]).toHaveAttribute("href", "/violations?repo=api");
  });

  it("demo mode shows only the estimated total", () => {
    render(<TrustHero score={null} history={[]} demoTotal={720} />);
    expect(screen.getByRole("img", { name: "Trust Score 720 out of 1000" })).toBeInTheDocument();
    expect(screen.getByText("Good")).toBeInTheDocument();
    expect(screen.queryByText("Open risk")).not.toBeInTheDocument();
  });

  it("helpers: bands, deltas against the snapshot a week back, deduplicated actions", () => {
    expect([850, 849, 700, 550, 400, 399].map(bandFor)).toEqual(["Excellent", "Good", "Good", "Fair", "Poor", "Critical"]);
    expect(scoreDelta([{ day: "2026-10-01", total: 500 }, { day: "2026-10-11", total: 560 }, { day: "2026-10-19", total: 600 }])).toBe(40);
    expect(scoreDelta([{ day: "2026-10-18", total: 500 }, { day: "2026-10-19", total: 520 }])).toBe(20);
    expect(scoreDelta([{ day: "2026-10-19", total: 500 }])).toBeNull();
    expect(topActions(score.dimensions, 5).map(a => a.gain)).toEqual([90, 60, 15, 2]);
    expect(topActions([{ actions: [{ label: "a", href: "/a", gain: 5 }, { label: "b", href: "/b", gain: 50 }] }], 1)[0].label).toBe("b");
  });
});

const kpiBase: KpiInput = {
  unreviewedHighRisk: 0, unreviewedCritical: 0, awaitingSignoffRepos: 0, slaBreaches: 0,
  openSecrets: 0, openCriticalSecrets: 0, reviewCoverage: 1, reviewedFiles: 4, totalHighRiskFiles: 4,
  scanCoverage: 1, reposScanned7d: 3, reposConnected: 3,
};

describe("headline numbers", () => {
  it("all clear → every tile good", () => {
    expect(buildKpis(kpiBase).map(k => k.tone)).toEqual(["good", "good", "good", "good", "good", "good"]);
  });

  it("tone follows the number: critical work is bad, other open work is a warning", () => {
    const k = Object.fromEntries(buildKpis({
      ...kpiBase, unreviewedHighRisk: 5, unreviewedCritical: 1, awaitingSignoffRepos: 2, slaBreaches: 1,
      openSecrets: 2, openCriticalSecrets: 0, reviewCoverage: 0.6, reviewedFiles: 3, totalHighRiskFiles: 5,
      scanCoverage: 0.4, reposScanned7d: 2, reposConnected: 5,
    }).map(x => [x.key, x]));
    expect(k.unreviewed).toMatchObject({ tone: "bad", value: "5", sub: "1 critical · need sign-off" });
    expect(k.signoff.tone).toBe("warn");
    expect(k.sla.tone).toBe("bad");
    expect(k.secrets).toMatchObject({ tone: "warn", value: "2" });
    expect(k.review).toMatchObject({ tone: "warn", value: "60%", sub: "3 of 5 files", progress: 0.6 });
    expect(k.coverage).toMatchObject({ tone: "bad", value: "40%", sub: "2 of 5 repos" });
    expect(buildKpis({ ...kpiBase, unreviewedHighRisk: 2 })[0].tone).toBe("warn");
    expect(buildKpis({ ...kpiBase, openSecrets: 1, openCriticalSecrets: 1 })[3].tone).toBe("bad");
  });

  it("unknown values stay unknown", () => {
    const k = buildKpis({ ...kpiBase, openSecrets: null, openCriticalSecrets: null, reviewCoverage: null, totalHighRiskFiles: null });
    expect(k[3]).toMatchObject({ value: "—", tone: "neutral" });
    expect(k[4]).toMatchObject({ value: "—", tone: "neutral", sub: "No high-risk files in this period" });
  });

  it("each tile links to where it's handled", () => {
    render(<KpiStrip kpis={buildKpis(kpiBase)} />);
    expect(screen.getByRole("link", { name: /Open secrets/ })).toHaveAttribute("href", "/secrets");
    expect(screen.getByRole("link", { name: /Past fix deadline/ })).toHaveAttribute("href", "/sla");
    // Review work stays on the dashboard: the queue and the repositories table, not the violations list.
    expect(screen.getByRole("link", { name: /Unreviewed high-risk/ })).toHaveAttribute("href", "#review-queue");
    expect(screen.getByRole("link", { name: /High-risk reviewed/ })).toHaveAttribute("href", "#review-queue");
    expect(screen.getByRole("link", { name: /Repos awaiting sign-off/ })).toHaveAttribute("href", "#repositories");
  });
});

const file = (over: Partial<TopRiskFile>): TopRiskFile => ({ repo: "acme/api", file_path: "src/a.ts", ai_pct: 0.5, risk_score: "HIGH", attested: false, scan_id: "s1", pr_number: 4, ...over });

describe("review queue", () => {
  const now = Date.parse("2026-10-19T12:00:00Z");
  const data = {
    top_risk_files: [
      file({ file_path: "src/high.ts", ai_pct: 0.9 }),
      file({ file_path: "src/crit.ts", risk_score: "CRITICAL", ai_pct: 0.1 }),
      file({ file_path: "src/late.ts", ai_pct: 0.2 }),
      file({ file_path: "src/done.ts", attested: true }),
      file({ file_path: "src/med.ts", risk_score: "MEDIUM" }),
      file({ file_path: "src/taken.ts", risk_score: "CRITICAL" }),
    ],
    sla_breach_files: [{ file_path: "src/late.ts", scan_id: "s1", repo: "acme/api", risk_score: "HIGH" as const, sla_deadline: "2026-10-17T12:00:00Z" }],
  };

  it("overdue first, then CRITICAL, then most AI-written; signed-off, medium and picked-up files left out", () => {
    const q = buildQueue(data, now, f => f.file_path === "src/taken.ts");
    expect(q.map(f => f.file_path)).toEqual(["src/late.ts", "src/crit.ts", "src/high.ts"]);
    expect(q[0].overdueHours).toBe(48);
    // Same tier: the more AI-written file first.
    const tie = buildQueue({ top_risk_files: [file({ file_path: "low.ts", ai_pct: 0.1 }), file({ file_path: "hi.ts", ai_pct: 0.8 })], sla_breach_files: [] }, now);
    expect(tie.map(f => f.file_path)).toEqual(["hi.ts", "low.ts"]);
  });

  it("rows open the file's sign-off on its PR page", () => {
    render(<ReviewQueue items={buildQueue(data, now)} limit={2} />);
    expect(screen.getByRole("link", { name: /late\.ts/ })).toHaveAttribute("href", "/pr/s1?attest=src%2Flate.ts");
    expect(screen.getByText("2d overdue")).toBeInTheDocument();
    // "View all" expands the queue in place instead of leaving for the violations page.
    expect(screen.queryByRole("link", { name: /View all/ })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /taken\.ts/ })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /high\.ts/ })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "View all 4" }));
    expect(screen.getByRole("link", { name: /high\.ts/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Show less" })).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(screen.getByRole("button", { name: "Show less" }));
    expect(screen.queryByRole("link", { name: /high\.ts/ })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "+2 more waiting" }));
    expect(screen.getByRole("link", { name: /high\.ts/ })).toBeInTheDocument();
  });

  it("empty queue says so", () => {
    render(<ReviewQueue items={[]} />);
    expect(screen.getByText("All high-risk files are signed off")).toBeInTheDocument();
  });
});

describe("governance panels", () => {
  const summary = {
    policy_configured: true, open_violations: 2, violations: 3, approved_usage: 5, unreviewed: 0, unidentified: 0, hints: 1,
    developers_with_violations: 1, compliance: 0.75,
    by_tool: [
      { tool: "copilot", label: "GitHub Copilot", detections: 6, violations: 0, approval: "approved" },
      { tool: "cursor", label: "Cursor", detections: 2, violations: 2, approval: "unapproved" },
    ],
  } as ShadowSummary;

  it("AI tool usage: open detections, approved share, tools by evidence", () => {
    render(<ShadowAiPanel summary={summary} />);
    const p = screen.getByRole("region", { name: "AI tool usage" });
    expect(p).toHaveTextContent("2unapproved-tool detections open");
    expect(p).toHaveTextContent("75%");
    expect(within(p).getAllByText(/GitHub Copilot|Cursor/).map(n => n.textContent)).toEqual(["GitHub Copilot", "Cursor"]);
    expect(p).not.toHaveTextContent("No approved-tools policy");
  });

  it("AI tool usage without a policy says nothing is flagged", () => {
    render(<ShadowAiPanel summary={{ ...summary, policy_configured: false, compliance: null }} />);
    expect(screen.getByText(/No approved-tools policy yet/)).toBeInTheDocument();
  });

  it("secrets by severity", () => {
    const counts = countSecrets([{ severity: "CRITICAL" }, { severity: "high" }, { severity: "MEDIUM" }, { severity: null }]);
    expect(counts).toEqual({ CRITICAL: 1, HIGH: 1, MEDIUM: 2 });
    render(<SecretsPanel counts={counts} />);
    expect(screen.getByRole("region", { name: "Leaked secrets" })).toHaveTextContent("4open credentials found in code");
  });

  it("audit evidence expanded: every control of every framework with its status, then every gap", () => {
    const overview: EvidenceOverview = {
      period_start: "a", period_end: "b", generated_at: "c",
      frameworks: [
        { id: "soc2", name: "SOC 2", short: "SOC 2", status_counts: { pass: 1, partial: 1, fail: 0, not_tested: 0 },
          controls: [{ control_id: "CC8.1", control_name: "Changes are authorised, tested and approved", status: "partial" }, { control_id: "CC7.2", control_name: "Activity is logged", status: "pass" }] },
        { id: "aigov", name: "AI code governance", short: "AI governance", status_counts: { pass: 0, partial: 0, fail: 1, not_tested: 0 },
          controls: [{ control_id: "AIG-1", control_name: "Only approved AI tools are used", status: "fail" }] },
      ],
      gaps: [
        { key: "independent_review", label: "Reviewer is not the author", status: "fail", gaps: ["2 self-approvals", "1 couldn't be checked"] },
        { key: "review", label: "High-risk changes reviewed", status: "partial", gaps: ["3 high-risk files not yet reviewed"] },
        { key: "scanning", label: "Changes scanned automatically", status: "partial", gaps: ["1 repo not scanned"] },
        { key: "secrets", label: "Leaked secrets resolved", status: "partial", gaps: ["2 secrets open"] },
      ],
    };
    render(<EvidencePanel overview={overview} />);
    const p = screen.getByRole("region", { name: "Audit evidence" });
    // Dashboard shows stats only: per framework a count and its issues, no control-by-control list.
    expect(within(p).getByRole("link", { name: /SOC 2/ })).toHaveTextContent("SOC 21/2controls with evidence1 with gaps");
    expect(within(p).getByRole("link", { name: /SOC 2/ })).toHaveAttribute("href", "/reports?fw=SOC2");
    expect(within(p).getByRole("link", { name: /AI code governance/ })).toHaveTextContent("1 failing");
    expect(p).not.toHaveTextContent("CC8.1");
    expect(p).not.toHaveTextContent("Only approved AI tools are used");
    // Only the top three gaps, first detail each, and a link to the rest.
    expect(p).toHaveTextContent("Reviewer is not the author: 2 self-approvals");
    expect(p).not.toHaveTextContent("1 couldn't be checked");
    expect(p).toHaveTextContent("Changes scanned automatically: 1 repo not scanned");
    expect(p).not.toHaveTextContent("Leaked secrets resolved");
    expect(within(p).getByRole("link", { name: /\+1 more on the Compliance page/ })).toHaveAttribute("href", "/compliance");
    expect(p).toHaveTextContent("not a certification");
  });

  it("loading and unavailable states", () => {
    const { rerender } = render(<SecretsPanel counts={null} />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading this panel…");
    rerender(<SecretsPanel counts="unavailable" />);
    expect(screen.getByText(/Couldn.t load this right now/)).toBeInTheDocument();
  });
});

describe("repositories", () => {
  const repo = (name: string, over: Partial<RepoStat> = {}): RepoStat =>
    ({ repo: `acme/${name}`, ai_pct: 0.3, attestation_rate: 1, last_scan: "2026-10-18", scan_count: 2, file_count: 10, latest_scan_id: `s-${name}`, ...over });
  const repos = [repo("api", { high_crit_count: 4, attestation_rate: 0.5 }), repo("web", { high_crit_count: 1 }), repo("docs", { ai_pct: 0.9, last_scan: "2026-10-19" })];

  it("joins per-repo Trust Scores and sorts worst first", () => {
    const rows = buildRepoRows(repos, [{ repo: "acme/api", score: 410, open_critical: 1, open_high: 3, review_coverage: 0.5, open_secrets: 0, last_scan: null }]);
    expect(rows[0]).toMatchObject({ score: 410, openCritical: 1, openHigh: 3 });
    expect(rows[1]).toMatchObject({ score: null, highCrit: 1 });
    expect(sortRepoRows(rows, "risk").map(r => r.repo)).toEqual(["acme/api", "acme/web", "acme/docs"]);
    // Open risk outranks review coverage: web has more open risk though docs is less reviewed.
    const byRisk = sortRepoRows(buildRepoRows([repo("web", { high_crit_count: 3 }), repo("docs", { high_crit_count: 0, attestation_rate: 0.1 })], null), "risk");
    expect(byRisk.map(r => r.repo)).toEqual(["acme/web", "acme/docs"]);
    expect(sortRepoRows(rows, "ai")[0].repo).toBe("acme/docs");
    expect(sortRepoRows(rows, "recent")[0].repo).toBe("acme/docs");
    expect(sortRepoRows(rows, "score")[0].repo).toBe("acme/api");
  });

  it("renders the table, with the Trust Score column only when scores are loaded", () => {
    const { rerender } = render(<RepoTable rows={buildRepoRows(repos, null)} />);
    expect(screen.queryByRole("columnheader", { name: "Trust Score" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "api" })).toHaveAttribute("href", "/repo/acme/api");
    rerender(<RepoTable rows={buildRepoRows(repos, [{ repo: "acme/api", score: 410, open_critical: 1, open_high: 3, review_coverage: 0.5, open_secrets: 0, last_scan: null }])} />);
    expect(screen.getByRole("columnheader", { name: "Trust Score" })).toBeInTheDocument();
    expect(screen.getByText("410")).toBeInTheDocument();
  });
});

describe("needs attention", () => {
  const none: AttentionInput = {
    slaOverdue: 0, overdueFiles: [], unreviewedCritical: [], unreviewedHigh: [], awaitingRepos: [],
    openCriticalSecrets: 0, openOtherSecrets: 0, unapprovedAiTools: 0, failingControls: 0,
  };
  const ref = (file: string, extra: { overdueHours?: number } = {}) => ({ file: `src/${file}`, scanId: `s-${file}`, repo: "acme/api", ...extra });

  it("nothing to do → all clear", () => {
    expect(buildAttention(none)).toEqual([]);
    render(<NeedsAttention items={[]} ready />);
    expect(screen.getByRole("region", { name: "Needs attention" })).toHaveTextContent("All clear");
  });

  it("lists every open item, critical first, naming the files and repos with direct links", () => {
    const items = buildAttention({
      slaOverdue: 2, overdueFiles: [ref("pay.ts", { overdueHours: 72 }), ref("auth.ts", { overdueHours: 5 })],
      unreviewedCritical: [ref("crit.ts")], unreviewedHigh: [ref("a.ts"), ref("b.ts"), ref("c.ts"), ref("d.ts")],
      awaitingRepos: [{ repo: "acme/api", repoName: "api", scanId: "s1" }, { repo: "acme/web", repoName: "web", scanId: "s2" }, { repo: "acme/a", repoName: "a", scanId: "s3" }, { repo: "acme/b", repoName: "b", scanId: "s4" }],
      openCriticalSecrets: 1, openOtherSecrets: 2, unapprovedAiTools: 1, failingControls: 1,
    });
    expect(items.map(i => [i.key, i.severity, i.count])).toEqual([
      ["sla", "critical", 2], ["secrets-critical", "critical", 1], ["critical", "critical", 1],
      ["repos", "high", 4], ["high", "high", 4], ["ai", "high", 1], ["secrets", "medium", 2], ["controls", "medium", 1],
    ]);
    // Deadlines: the heading opens the oldest overdue file; each file opens its own sign-off.
    expect(items[0]).toMatchObject({ title: "files past the fix deadline", href: "/pr/s-pay.ts?attest=src%2Fpay.ts", all: { href: "/sla" }, more: 0 });
    expect(items[0].links).toEqual([
      { label: "pay.ts", href: "/pr/s-pay.ts?attest=src%2Fpay.ts", note: "3d overdue" },
      { label: "auth.ts", href: "/pr/s-auth.ts?attest=src%2Fauth.ts", note: "5h overdue" },
    ]);
    // Files awaiting attestation go to their sign-off, never to the violations list.
    expect(items[2]).toMatchObject({ title: "CRITICAL file awaiting attestation", href: "/pr/s-crit.ts?attest=src%2Fcrit.ts", all: { href: "#review-queue" } });
    expect(items[4]).toMatchObject({ title: "HIGH-risk files awaiting attestation", href: "/pr/s-a.ts?attest=src%2Fa.ts", more: 1 });
    // Repos go straight to the pull request waiting for sign-off.
    expect(items[3]).toMatchObject({ title: "repos pending sign-off", href: "#repositories", more: 1 });
    expect(items[3].links!.map(l => [l.label, l.href])).toEqual([["api", "/pr/s1"], ["web", "/pr/s2"], ["a", "/pr/s3"]]);
    expect(items.some(i => i.href === "/violations" || i.links?.some(l => l.href === "/violations"))).toBe(false);

    render(<NeedsAttention items={items} ready />);
    const region = screen.getByRole("region", { name: "Needs attention" });
    // Grouped into labelled columns, each with its own count, worst first.
    expect(within(region).getAllByRole("group").map(g => g.getAttribute("aria-label"))).toEqual(["Act now: 3", "Next up: 3", "Plan for: 2"]);
    expect(region).toHaveTextContent("3 need action now");
    // One row per item, worst first, each tagged with its group and a verb for what you'll do there.
    const rows = within(region).getAllByRole("listitem");
    expect(rows).toHaveLength(8);
    expect(rows[0]).toHaveTextContent("Act now");
    expect(rows[7]).toHaveTextContent("Plan for");
    expect(within(rows[0]).getByRole("link", { name: /Fix now/ })).toHaveAttribute("href", "/pr/s-pay.ts?attest=src%2Fpay.ts");
    expect(within(rows[1]).getByRole("link", { name: /Rotate/ })).toHaveAttribute("href", "/secrets");
    expect(within(rows[3]).getByRole("link", { name: /Open/ })).toHaveAttribute("href", "#repositories");
    expect(within(region).getByRole("link", { name: /^pay\.ts/ })).toHaveAttribute("href", "/pr/s-pay.ts?attest=src%2Fpay.ts");
    expect(within(region).getByRole("link", { name: "web" })).toHaveAttribute("href", "/pr/s2");
    expect(within(region).getAllByRole("link", { name: "+1 more" }).map(a => a.getAttribute("href"))).toEqual(["#repositories", "#review-queue"]);
    expect(within(region).getByRole("link", { name: /critical secret exposed/ })).toHaveAttribute("href", "/secrets");
  });

  it("a single pending repo opens its pull request directly; only groups with items are shown", () => {
    const items = buildAttention({ ...none, awaitingRepos: [{ repo: "acme/api", repoName: "api", scanId: "s1" }] });
    expect(items[0]).toMatchObject({ title: "repo pending sign-off", href: "/pr/s1" });
    // no scan on record: the repository page
    expect(buildAttention({ ...none, awaitingRepos: [{ repo: "acme/api", repoName: "api", scanId: "" }] })[0].href).toBe("/repo/acme/api");
    render(<NeedsAttention items={items} ready />);
    const region = screen.getByRole("region", { name: "Needs attention" });
    expect(within(region).getAllByRole("group").map(g => g.getAttribute("aria-label"))).toEqual(["Next up: 1"]);
    expect(region).toHaveTextContent("Nothing urgent, but reviewers are needed");
  });

  it("a viewer who can't sign a file off (a developer) is linked to the file, never its attestation", () => {
    const file = (n: string, risk: string) => ({ file: `src/${n}`, scanId: `s-${n}`, repo: "acme/api", risk });
    const items = buildAttention({
      ...none, slaOverdue: 1, overdueFiles: [{ ...file("late.ts", "CRITICAL"), overdueHours: 5 }],
      unreviewedCritical: [file("crit.ts", "CRITICAL")], unreviewedHigh: [file("high.ts", "HIGH")],
      // may attest HIGH, not CRITICAL
      canAttestRisk: r => r === "HIGH",
    });
    const by = (k: string) => items.find(i => i.key === k)!;
    expect(by("sla")).toMatchObject({ href: "/pr/s-late.ts?file=src%2Flate.ts", links: [expect.objectContaining({ href: "/pr/s-late.ts?file=src%2Flate.ts" })] });
    expect(by("critical")).toMatchObject({ href: "/pr/s-crit.ts?file=src%2Fcrit.ts", links: [expect.objectContaining({ href: "/pr/s-crit.ts?file=src%2Fcrit.ts" })] });
    expect(by("high")).toMatchObject({ href: "/pr/s-high.ts?attest=src%2Fhigh.ts", links: [expect.objectContaining({ href: "/pr/s-high.ts?attest=src%2Fhigh.ts" })] });
  });

  it("unknown sources add nothing; not ready shows a placeholder, not 'all clear'", () => {
    expect(buildAttention({ ...none, openCriticalSecrets: null, openOtherSecrets: null, unapprovedAiTools: null, failingControls: null })).toEqual([]);
    expect(buildAttention({ ...none, slaOverdue: 1 })[0]).toMatchObject({ href: "/sla", links: [], more: 0 });
    render(<NeedsAttention items={[]} ready={false} />);
    expect(screen.queryByText("All clear")).not.toBeInTheDocument();
  });
});

describe("no cut-off text", () => {
  it("no dashboard block truncates or clamps its text (it wraps instead)", () => {
    const now = Date.parse("2026-10-19T12:00:00Z");
    const q = buildQueue({ top_risk_files: [file({ file_path: "src/a/very/long/path/to/some_really_long_file_name_here.ts" })], sla_breach_files: [] }, now);
    const { container } = render(<>
      <TrustHero score={score} history={[]} />
      <KpiStrip kpis={buildKpis(kpiBase)} />
      <NeedsAttention ready items={buildAttention({
        slaOverdue: 1, overdueFiles: [{ file: "src/x.ts", scanId: "s", repo: "acme/api", overdueHours: 3 }], unreviewedCritical: [], unreviewedHigh: [],
        awaitingRepos: [{ repo: "acme/a-very-long-repository-name", repoName: "a-very-long-repository-name", scanId: "s" }],
        openCriticalSecrets: 1, openOtherSecrets: 1, unapprovedAiTools: 1, failingControls: 1,
      })} />
      <ReviewQueue items={q} />
      <RepoTable rows={buildRepoRows([{ repo: "acme/x", ai_pct: 0, attestation_rate: 1, last_scan: "2026-10-18", scan_count: 1, file_count: 1, latest_scan_id: "s" }], null)} />
      <ActivityList events={[]} />
    </>);
    expect(container.querySelectorAll(".truncate, [class*='line-clamp']")).toHaveLength(0);
  });
});

describe("risk trend weeks", () => {
  const now = Date.parse("2026-10-19T12:00:00Z"); // a Monday
  const pt = (date: string, c = 0, h = 0, m = 0) => ({ date, critical_count: c, high_count: h, medium_count: m });

  it("covers the whole period to today, with empty weeks as zeros", () => {
    const w = fillTrendWeeks([pt("2026-09-28", 1, 2, 3)], { start: "2026-09-16", end: "2026-10-19" }, now);
    expect(w.map(x => x.date)).toEqual(["2026-09-14", "2026-09-21", "2026-09-28", "2026-10-05", "2026-10-12", "2026-10-19"]);
    expect(w.map(x => x.critical_count + x.high_count + x.medium_count)).toEqual([0, 0, 6, 0, 0, 0]);
    expect(w[w.length - 1]).toMatchObject({ label: "Today", range: "Oct 19" });
    expect(w[0]).toMatchObject({ label: "Sep 14", range: "Sep 16 – Sep 20" });
    expect(w[4].range).toBe("Oct 12 – Oct 18");
  });

  it("the server's relabelled current week (today's date) lands in the current week", () => {
    const tue = Date.parse("2026-10-21T12:00:00Z");
    const w = fillTrendWeeks([pt("2026-10-12", 1), pt("2026-10-21", 0, 4)], { start: "2026-10-12", end: "2026-10-21" }, tue);
    expect(w.map(x => [x.date, x.critical_count, x.high_count, x.label])).toEqual([
      ["2026-10-12", 1, 0, "Oct 12"], ["2026-10-19", 0, 4, "Today"]]);
    expect(w[1].range).toBe("Oct 19 – Oct 21 (so far)");
  });

  it("the panel covers the dashboard's whole period, not just weeks with findings", () => {
    render(<RiskPanel data={{ risk_trend: [pt("2026-10-12", 1)], risk_totals: { critical_count: 1, high_count: 0, medium_count: 0 }, period: { start: "2026-07-21", end: "2026-10-19" } }} periodLabel="last 90 days" />);
    expect(screen.getByRole("region", { name: "Risk trend" })).toHaveTextContent("last 90 days · Jul 21 to today");
  });

  it("without a period it starts at the first data point; no data and no period → nothing", () => {
    expect(fillTrendWeeks([pt("2026-10-05", 1)], undefined, now).map(x => x.date)).toEqual(["2026-10-05", "2026-10-12", "2026-10-19"]);
    expect(fillTrendWeeks([], undefined, now)).toEqual([]);
  });
});

describe("risk direction", () => {
  const pt = (c: number, h: number) => ({ date: "d", critical_count: c, high_count: h, medium_count: 9 });
  it("second half vs first half of CRITICAL+HIGH; too little data → none", () => {
    expect(riskDirection([pt(1, 1), pt(1, 1), pt(2, 2), pt(2, 2)])).toEqual({ pct: 100, dir: "up" });
    expect(riskDirection([pt(2, 2), pt(2, 2), pt(1, 1), pt(1, 1)])).toEqual({ pct: 50, dir: "down" });
    expect(riskDirection([pt(2, 0), pt(2, 0), pt(2, 0), pt(2, 0)])).toEqual({ pct: 0, dir: "flat" });
    expect(riskDirection([pt(0, 0), pt(0, 0), pt(1, 0), pt(1, 0)])).toBeNull();
    expect(riskDirection([pt(1, 1), pt(1, 1), pt(1, 1)])).toBeNull();
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
    expect(ev[0]).toMatchObject({ type: "attestation", file_path: "src/a.ts", pr_number: 12, reviewer_email: "carol@acme.test" });
    expect(ev[1]).toMatchObject({ type: "scan", repo: "acme/api", pr_number: 0, overall_risk: "", file_count: 0, scan_id: "s1" });
    expect(deriveActivity(data, 1)).toHaveLength(1);
  });

  it("a scan shows at its own time with its own AI share (it showed midnight and the repo's average)", () => {
    const withLatest = { ...data, repos: [{ ...data.repos[0], last_scan: "2026-10-23T16:31:50Z", latest_ai_pct: 0.38 }] } as DashboardData;
    expect(deriveActivity(withLatest).find(e => e.type === "scan")).toMatchObject({ timestamp: "2026-10-23T16:31:50.000Z", total_ai_pct: 0.38 });
    // a payload cached before latest_ai_pct existed still shows something real: the average
    expect(deriveActivity(data).find(e => e.type === "scan")?.total_ai_pct).toBe(0.4);
  });

  it("each sign-off and scan appears once: the PR page's local copy (browser clock) and the server's merge", () => {
    const server = deriveActivity(data);
    const local = [
      // Same sign-off as the server's, recorded locally a few seconds earlier: must not show twice.
      { ...server[0], timestamp: "2026-10-19T07:59:55Z", reviewer_email: "carol@acme.test" },
      // Same sign-off recorded twice locally (attested again).
      { ...server[0], timestamp: "2026-10-19T07:59:58Z" },
      // A sign-off the server doesn't have yet: shown.
      { ...server[0], file_path: "src/c.ts", timestamp: "2026-10-19T09:00:00Z" },
      // Another org's repo, left in this browser's storage: dropped.
      { ...server[0], repo: "other/repo", file_path: "x.ts", timestamp: "2026-10-19T10:00:00Z" },
    ];
    const merged = mergeActivity(server, local, new Set(["acme/api", "acme/never"]));
    expect(merged.map(e => [e.type, e.file_path, e.timestamp])).toEqual([
      ["attestation", "src/c.ts", "2026-10-19T09:00:00Z"],
      ["attestation", "src/a.ts", "2026-10-19T08:00:00Z"],   // the server's copy won
      ["scan", "", "2026-10-18T00:00:00.000Z"],
    ]);
    // Without a repo list (seed/demo), nothing is filtered, but duplicates still collapse.
    expect(mergeActivity(server, local).filter(e => e.file_path === "src/a.ts")).toHaveLength(1);
    expect(mergeActivity(server, local, undefined, 2)).toHaveLength(2);
    expect(activityKey({ type: "scan", scan_id: "s1", file_path: "" })).not.toBe(activityKey({ type: "attestation", scan_id: "s1", file_path: "" }));
  });

  it("renders sign-offs and scans", () => {
    render(<ActivityList events={deriveActivity(data)} />);
    expect(screen.getByRole("link", { name: "Signed off a.ts" })).toHaveAttribute("href", "/pr/s1");
    expect(screen.getByRole("link", { name: "Scanned api" })).toBeInTheDocument();
  });
});
