import { buildOverview, dedupeAlerts, ACTION_LIMIT, type FiringAlert } from "@/lib/threatOverview";
import { tabFromSearch, threatsHref } from "@/lib/threatRoutes";
import type { DashboardData } from "@/types";

const NOW = new Date("2026-11-08T12:00:00Z").getTime();
const hoursAgo = (h: number) => new Date(NOW - h * 3600_000).toISOString();

const file = (file_path: string, risk_score: string, detected_hours_ago: number, extra: object = {}) => ({
  repo: "o/api", file_path, scan_id: "s1", ai_pct: 0.5, risk_score, pr_number: 7, attested: false,
  detected_at: hoursAgo(detected_hours_ago), ...extra,
});
const data = (files: ReturnType<typeof file>[]) => ({
  repos: [{ repo: "o/api", attestation_rate: 0, high_crit_count: files.length }], top_risk_files: files, attestation_rate: 0, unattested_deploy_count: files.length,
  overall_ai_pct: 0.5, risk_trend: [], scan_count: 1, file_count: 10,
}) as unknown as DashboardData;

const alert = (o: Partial<FiringAlert> & { id: string }): FiringAlert => ({ title: o.id, severity: "P2", fired_at: hoursAgo(1), ...o });

describe("dedupeAlerts", () => {
  it("keeps the first alert per pull request and source, and every alert without a scan", () => {
    const got = dedupeAlerts([
      alert({ id: "a1", scan_id: "s1" }), alert({ id: "a2", scan_id: "s1" }), alert({ id: "a3", scan_id: "s1", source: "secret" }), alert({ id: "a4" }), alert({ id: "a5" }),
    ]);
    expect(got.map(a => a.id)).toEqual(["a1", "a3", "a4", "a5"]);
  });
});

describe("buildOverview", () => {
  it("counts each stage from the same sources as the sidebar", () => {
    const o = buildOverview({
      data: data([file("a.ts", "CRITICAL", 30), file("b.ts", "HIGH", 5), file("c.ts", "HIGH", 5)]), statuses: {},
      alerts: [alert({ id: "x", severity: "P1", scan_id: "s1" }), alert({ id: "y", scan_id: "s2", acknowledged_by: "ana@x.com" })],
      incidentsOpen: 2, now: NOW,
    });
    // 3 files, plus the one "repositories blocked from deploying" violation that deriveViolations adds for the CRITICAL file
    expect(o.violations).toMatchObject({ open: 4, critical: 2, high: 2 });
    expect(o.alerts).toEqual({ firing: 2, p1: 1, unacknowledged: 1 });
    expect(o.incidents.open).toBe(2);
    expect(o.clear).toBe(false);
  });

  it("flags violations past their deadline (a CRITICAL file is due 24 hours after detection)", () => {
    const o = buildOverview({ data: data([file("late.ts", "CRITICAL", 30), file("fresh.ts", "CRITICAL", 2)]), statuses: {}, alerts: [], incidentsOpen: 0, now: NOW });
    expect(o.violations.slaBreached).toBe(2);                                       // the late file, and the deploy-blocked violation it causes
    expect(o.actions.find(a => a.key === "sla")?.text).toBe("2 violations past their fix deadline");
    expect(o.actions.find(a => a.key === "sla")?.detail).toContain("late.ts");
  });

  it("leads with incidents, then deadlines, then critical, then alerts", () => {
    const o = buildOverview({
      data: data([file("late.ts", "CRITICAL", 30), file("h.ts", "HIGH", 1)]), statuses: {},
      alerts: [alert({ id: "p", severity: "P1", scan_id: "s1" })], incidentsOpen: 1, now: NOW,
    });
    expect(o.actions.map(a => a.key)).toEqual(["incidents", "sla", "critical", "p1", "high"]);
    expect(o.actions.map(a => a.tab)).toEqual(["incidents", "violations", "violations", "alerts", "violations"]);
  });

  it("an alert nobody acknowledged is called out when it is not already a P1", () => {
    const o = buildOverview({ data: null, statuses: {}, alerts: [alert({ id: "a", scan_id: "s1" })], incidentsOpen: 0, now: NOW });
    expect(o.actions.map(a => a.key)).toEqual(["unack"]);
  });

  it("a violation resolved on the Violations page is no longer open", () => {
    const d = data([file("a.ts", "HIGH", 1)]);
    const open = buildOverview({ data: d, statuses: {}, alerts: [], incidentsOpen: 0, now: NOW });
    expect(open.violations.open).toBe(2);                                           // the file, and the deploy-blocked violation
    const closed = buildOverview({ data: d, statuses: { "high::s1::a.ts": "resolved", "deploy::blocked": "resolved" }, alerts: [], incidentsOpen: 0, now: NOW });
    expect(closed.violations.open).toBe(0);
    expect(closed.clear).toBe(true);
    expect(closed.violations.closedWithoutAttestation).toBeGreaterThanOrEqual(0);
  });

  it("never lists more actions than the limit", () => {
    expect(ACTION_LIMIT).toBe(5);
    const o = buildOverview({ data: data([file("late.ts", "CRITICAL", 30), file("h.ts", "HIGH", 1)]), statuses: {}, alerts: [alert({ id: "p", severity: "P1", scan_id: "s1" }), alert({ id: "q", scan_id: "s2" })], incidentsOpen: 3, now: NOW });
    expect(o.actions.length).toBeLessThanOrEqual(ACTION_LIMIT);
  });

  it("no data at all is clear, not an error", () => {
    const o = buildOverview({ data: null, statuses: {}, alerts: [], incidentsOpen: 0, now: NOW });
    expect(o).toMatchObject({ clear: true, actions: [], violations: { open: 0 } });
  });
});

describe("threat routes", () => {
  it("reads the tab, defaulting to the overview", () => {
    expect(tabFromSearch("?tab=alerts")).toBe("alerts");
    expect(tabFromSearch("?tab=incidents")).toBe("incidents");
    expect(tabFromSearch("?tab=nope")).toBe("overview");
    expect(tabFromSearch("")).toBe("overview");
  });
  it("builds the address of a tab and keeps the rest of the query string", () => {
    expect(threatsHref("overview")).toBe("/threats");
    expect(threatsHref("violations")).toBe("/threats?tab=violations");
    expect(threatsHref("alerts", { id: "a1", tag: ["x", "y"], skip: undefined })).toBe("/threats?tab=alerts&id=a1&tag=x&tag=y");
    expect(threatsHref("incidents", { tab: "ignored" })).toBe("/threats?tab=incidents");
  });
});
