/**
 * The Threats overview: violations, alerts and incidents on one screen. They are three stages of the same problem
 * (a file out of policy, a notification about it, an escalation when it was not handled), so the overview counts each
 * stage and says what to do first. Pure; the numbers come from the same sources as the sidebar badges.
 */
import { deriveViolations, type Violation } from "./violations";
import { violationStatus } from "./violations";
import type { DashboardData } from "@/types";

export interface FiringAlert { id: string; title: string; severity: "P1" | "P2" | "P3" | "P4"; scan_id?: string; source?: string; repo?: string; pr_number?: number; fired_at: string; acknowledged_by?: string }

export interface ThreatAction { key: string; tab: "violations" | "alerts" | "incidents"; text: string; detail: string; tone: "bad" | "warn" | "info"; href?: string }

export interface ThreatOverview {
  violations: { open: number; critical: number; high: number; medium: number; slaBreached: number; unassigned: number; closedWithoutAttestation: number };
  alerts: { firing: number; p1: number; unacknowledged: number };
  incidents: { open: number };
  /** The things to do first, most urgent first. */
  actions: ThreatAction[];
  /** Everything is clear. */
  clear: boolean;
}

/** One alert per pull request and source (the latest), as the Alerts view and the sidebar badge count them. */
export function dedupeAlerts<T extends { id: string; scan_id?: string; source?: string }>(alerts: readonly T[]): T[] {
  const seen = new Map<string, T>();
  for (const a of alerts) {
    const key = a.scan_id ? `${a.scan_id}::${a.source ?? "policy"}` : a.id;
    if (!seen.has(key)) seen.set(key, a);
  }
  return [...seen.values()];
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
export const ACTION_LIMIT = 5;

export function buildOverview(input: {
  data: DashboardData | null;
  statuses: Record<string, string>;
  assigned?: Record<string, string>;
  alerts: readonly FiringAlert[];
  incidentsOpen: number;
  now?: number;
}): ThreatOverview {
  const now = input.now ?? Date.now();
  const all: Violation[] = input.data ? deriveViolations(input.data, input.statuses) : [];
  const open = all.filter(v => violationStatus(v.id, input.statuses) === "open");
  const sev = (s: string) => open.filter(v => v.severity === s).length;
  const breached = open.filter(v => v.sla_deadline && new Date(v.sla_deadline).getTime() < now);
  const alerts = dedupeAlerts(input.alerts);
  const p1 = alerts.filter(a => a.severity === "P1");
  const unack = alerts.filter(a => !a.acknowledged_by);

  const actions: ThreatAction[] = [];
  if (input.incidentsOpen > 0) actions.push({ key: "incidents", tab: "incidents", tone: "bad", text: `${plural(input.incidentsOpen, "open incident")}`, detail: "Something went wrong and is still being handled. Open each to see its owner, timeline and playbook." });
  if (breached.length > 0) actions.push({ key: "sla", tab: "violations", tone: "bad", text: `${plural(breached.length, "violation")} past ${breached.length === 1 ? "its" : "their"} fix deadline`, detail: `${breached.slice(0, 3).map(v => v.file ?? v.title).join(", ")}${breached.length > 3 ? ` and ${breached.length - 3} more` : ""}. A CRITICAL file left past its deadline becomes an incident.` });
  const critical = sev("CRITICAL");
  if (critical > 0) actions.push({ key: "critical", tab: "violations", tone: "bad", text: `${plural(critical, "CRITICAL violation")} blocking merges`, detail: "Attest each file after review, or fix it and rescan. Closing without a review keeps the merge blocked." });
  if (p1.length > 0) actions.push({ key: "p1", tab: "alerts", tone: "warn", text: `${plural(p1.length, "P1 alert")} firing`, detail: p1.slice(0, 2).map(a => a.title).join(" · ") });
  if (unack.length > 0 && unack.length !== p1.length) actions.push({ key: "unack", tab: "alerts", tone: "warn", text: `${plural(unack.length, "alert")} nobody has acknowledged`, detail: "Acknowledge an alert so the team knows it is being looked at." });
  const high = sev("HIGH");
  if (high > 0) actions.push({ key: "high", tab: "violations", tone: "info", text: `${plural(high, "HIGH violation")} awaiting review`, detail: "Review and attest, in the order of their deadlines." });

  const unassigned = input.assigned ? open.filter(v => !input.assigned![v.id]).length : 0;
  const result: ThreatOverview = {
    violations: {
      open: open.length, critical, high, medium: sev("MEDIUM"), slaBreached: breached.length, unassigned,
      closedWithoutAttestation: all.filter(v => v.closed_without_attestation).length,
    },
    alerts: { firing: alerts.length, p1: p1.length, unacknowledged: unack.length },
    incidents: { open: input.incidentsOpen },
    actions: actions.slice(0, ACTION_LIMIT),
    clear: false,
  };
  result.clear = open.length === 0 && alerts.length === 0 && input.incidentsOpen === 0;
  return result;
}
