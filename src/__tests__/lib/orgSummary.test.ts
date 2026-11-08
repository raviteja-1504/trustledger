import { filterOrgs, orgAttention, orgHealth, portfolioTotals, scanTrend, sortOrgs, STALE_DAYS, type ListedOrg, type OrgMetrics } from "@/lib/orgSummary";

const NOW = new Date("2026-06-30T12:00:00Z");
const daysAgo = (d: number) => new Date(NOW.getTime() - d * 86_400_000).toISOString();
const org = (over: Partial<OrgMetrics> = {}): OrgMetrics => ({
  plan: "growth", created_at: daysAgo(200), scans_30d: 40, scans_prev_30d: 40, scans_this_month: 40, open_violations: 3, open_critical: 0, overdue: 0,
  member_count: 5, repo_count: 8, latest_risk: "LOW", latest_ai_pct: 0.2, last_scan: daysAgo(1), ...over,
});
const texts = (o: OrgMetrics) => orgAttention(o, NOW).map(a => a.text);

describe("orgAttention", () => {
  it("flags nothing for a healthy organisation", () => {
    expect(orgAttention(org(), NOW)).toEqual([]);
  });
  it("critical violations and SLA overdue come first, with correct grammar", () => {
    const a = orgAttention(org({ open_critical: 1, overdue: 3, repo_count: 0 }), NOW);
    expect(a.map(x => x.text)).toEqual([
      "1 critical violation still open",
      "3 violations past their SLA deadline",
      "No repositories connected yet. Import repositories to start scanning.",
    ]);
    expect(a.map(x => x.level)).toEqual(["critical", "critical", "warning"]);
    expect(texts(org({ overdue: 1 }))).toEqual(["1 violation past its SLA deadline"]);
  });
  it("quiet scanning: stale after the threshold, never-scanned only once the org is no longer brand new", () => {
    expect(texts(org({ last_scan: daysAgo(STALE_DAYS - 1) }))).toEqual([]);
    expect(texts(org({ last_scan: daysAgo(STALE_DAYS) }))).toEqual([`No scan in ${STALE_DAYS} days`]);
    expect(texts(org({ last_scan: null, created_at: daysAgo(30) }))).toEqual(["Repositories are connected but no scan has run"]);
    expect(texts(org({ last_scan: null, created_at: daysAgo(2) }))).toEqual([]);                  // give it a few days
  });
  it("plan limits: info near the cap, warning at or over it", () => {
    expect(texts(org({ plan: "starter", member_count: 4, repo_count: 2 }))).toEqual(["Members at 80% of the plan limit (4 of 5)"]);
    expect(texts(org({ plan: "starter", member_count: 5, repo_count: 2 }))).toEqual(["Members at the plan limit (5)"]);
    expect(texts(org({ plan: "starter", scans_this_month: 1_200, repo_count: 2, member_count: 2 }))).toEqual(["Scans over the plan limit (1200 of 1000)"]);
    expect(orgAttention(org({ plan: "starter", member_count: 4, repo_count: 2 }), NOW)[0].level).toBe("info");
    expect(orgAttention(org({ plan: "starter", member_count: 5, repo_count: 2 }), NOW)[0].level).toBe("warning");
  });
  it("enterprise is unlimited: no plan warnings however much is used", () => {
    expect(texts(org({ plan: "enterprise", scans_this_month: 9e6, member_count: 900, repo_count: 900 }))).toEqual([]);
  });
  it("a sharp drop in scan activity is noted, but not from a tiny base", () => {
    expect(texts(org({ scans_prev_30d: 100, scans_30d: 40 }))).toEqual(["Scan activity down 60% on the previous 30 days"]);
    expect(texts(org({ scans_prev_30d: 8, scans_30d: 1 }))).toEqual([]);
  });
});

describe("orgHealth", () => {
  const h = (o: OrgMetrics) => orgHealth(o, orgAttention(o, NOW), NOW);
  it("at risk when anything critical is flagged", () => {
    expect(h(org({ open_critical: 2 }))).toBe("at_risk");
    expect(h(org({ overdue: 1 }))).toBe("at_risk");
  });
  it("watch for warnings, healthy when clear", () => {
    expect(h(org({ last_scan: daysAgo(20) }))).toBe("watch");
    expect(h(org())).toBe("healthy");
    expect(h(org({ plan: "starter", member_count: 4, repo_count: 2 }))).toBe("healthy");               // an info note alone isn't a problem
  });
  it("inactive when scanning stopped long ago or never started; new in the first week", () => {
    expect(h(org({ last_scan: daysAgo(STALE_DAYS * 2) }))).toBe("inactive");
    expect(h(org({ last_scan: null, created_at: daysAgo(40) }))).toBe("inactive");
    expect(h(org({ last_scan: null, repo_count: 0, created_at: daysAgo(1) }))).toBe("new");
  });
});

describe("scanTrend", () => {
  it("compares with the previous period", () => {
    expect(scanTrend(150, 100)).toEqual({ dir: "up", pct: 50 });
    expect(scanTrend(40, 100)).toEqual({ dir: "down", pct: -60 });
    expect(scanTrend(100, 100)).toEqual({ dir: "flat", pct: 0 });
  });
  it("has no percentage when there is nothing to compare with", () => {
    expect(scanTrend(10, 0)).toEqual({ dir: "up", pct: null });
    expect(scanTrend(0, 0)).toEqual({ dir: "flat", pct: null });
  });
});

describe("sort, filter and totals", () => {
  const listed = (name: string, over: Partial<OrgMetrics> = {}, extra: Partial<ListedOrg> = {}): ListedOrg => {
    const m = org(over); const attention = orgAttention(m, NOW);
    return { ...m, id: name, name, slug: name.toLowerCase(), github_org: null, health: orgHealth(m, attention, NOW), attention, ...extra };
  };
  const all = [
    listed("Beta"), listed("Alpha", { open_critical: 3, open_violations: 9, latest_risk: "CRITICAL" }),
    listed("Gamma", { last_scan: daysAgo(30) }), listed("Delta", { open_critical: 1, open_violations: 20, last_scan: daysAgo(5), latest_risk: "HIGH" }),
  ];

  it("attention puts at-risk first (most critical first), then the ones to watch, healthy last", () => {
    expect(sortOrgs(all, "attention").map(o => o.name)).toEqual(["Alpha", "Delta", "Gamma", "Beta"]);
  });
  it("other sorts: name, risk, last scan (newest first), open violations (most first)", () => {
    expect(sortOrgs(all, "name").map(o => o.name)).toEqual(["Alpha", "Beta", "Delta", "Gamma"]);
    expect(sortOrgs(all, "risk").map(o => o.name)).toEqual(["Alpha", "Delta", "Beta", "Gamma"]);
    expect(sortOrgs(all, "last_scan").map(o => o.name)).toEqual(["Alpha", "Beta", "Delta", "Gamma"]);   // Alpha and Beta tie: by name
    expect(sortOrgs(all, "violations").map(o => o.name)).toEqual(["Delta", "Alpha", "Beta", "Gamma"]);
  });
  it("sorting never mutates its input", () => {
    const copy = [...all]; sortOrgs(all, "name"); expect(all).toEqual(copy);
  });
  it("filters by text (name, slug, GitHub handle) and by health", () => {
    const withGh = [...all, listed("Eps", {}, { github_org: "eps-corp" })];
    expect(filterOrgs(withGh, "eps-corp", "all").map(o => o.name)).toEqual(["Eps"]);
    expect(filterOrgs(withGh, "  ALP ", "all").map(o => o.name)).toEqual(["Alpha"]);
    expect(filterOrgs(withGh, "", "at_risk").map(o => o.name)).toEqual(["Alpha", "Delta"]);
    expect(filterOrgs(withGh, "alp", "healthy")).toEqual([]);
  });
  it("totals across the portfolio", () => {
    expect(portfolioTotals(all)).toEqual({ orgs: 4, needAttention: 2, atRisk: 2, openCritical: 4, openViolations: 3 + 9 + 3 + 20, scans30d: 160 });
  });
});
