/**
 * What a risk manager needs from the register at a glance, computed from the merged risks (lib/riskRegister.ts):
 * how many are open and how bad, which are overdue or have nobody responsible, where the exposure sits, how fast
 * risks are being worked down, and the few to act on first. Pure; every figure is counted from the risks.
 */
import type { RiskCategory, RiskItem } from "./riskRegister";

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export const inherent = (r: Pick<RiskItem, "likelihood" | "impact">) => r.likelihood * r.impact;
export const residual = (r: Pick<RiskItem, "residual_likelihood" | "residual_impact">) =>
  r.residual_likelihood && r.residual_impact ? r.residual_likelihood * r.residual_impact : null;

/** Score bands: LOW < 6, MEDIUM 6-11, HIGH 12-19, CRITICAL >= 20 (Likelihood x Impact on 1-5 scales). */
export function levelOf(score: number): RiskLevel {
  return score >= 20 ? "CRITICAL" : score >= 12 ? "HIGH" : score >= 6 ? "MEDIUM" : "LOW";
}

const DAY = 86_400_000;
/** Whole days from `now` to a YYYY-MM-DD due date: negative when overdue, 0 on the day. */
export function daysUntil(due: string | undefined, now: Date): number | null {
  if (!due) return null;
  const t = new Date(`${due.slice(0, 10)}T00:00:00Z`).getTime();
  if (Number.isNaN(t)) return null;
  return Math.round((t - Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())) / DAY);
}

export interface FocusItem { id: string; title: string; score: number; level: RiskLevel; reasons: string[]; repo?: string }
export interface Exposure { key: string; active: number; critical: number; score: number }

export interface RiskInsights {
  total: number;
  open: number; mitigating: number; accepted: number; closed: number;
  active: number;                       // not closed
  critical: number;                     // active with score >= 20
  high: number;                         // active with score 12-19
  overdue: number;                      // active, due date passed
  dueSoon: number;                      // active, due within 7 days
  unassigned: number;                   // active, nobody owns it
  highWithoutDueDate: number;           // active critical/high with no due date
  acceptedUnexplained: number;          // accepted with neither a note nor a plan saying why
  avgInherent: number | null;
  avgResidual: number | null;
  /** Average drop from inherent to residual, over risks that have a residual score. */
  reductionPct: number | null;
  withResidual: number;
  autoDerived: number;                  // of all, derived from scan data
  autoClosed: number;                   // derived risks now closed (evidence attested, fixed, or closed by a person)
  avgAgeDays: number | null;            // active risks, from when each was identified
  oldest: { id: string; title: string; days: number } | null;
  byRepo: Exposure[];                   // most exposed first, top 5
  byCategory: Exposure[];
  focus: FocusItem[];                   // up to 5, most urgent first
}

const avg = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
const round1 = (n: number | null) => (n == null ? null : Math.round(n * 10) / 10);

export const FOCUS_LIMIT = 5;
const exposure = (rows: RiskItem[], keyOf: (r: RiskItem) => string | undefined): Exposure[] => {
  const m = new Map<string, Exposure>();
  for (const r of rows) {
    const key = keyOf(r);
    if (!key) continue;
    const e = m.get(key) ?? { key, active: 0, critical: 0, score: 0 };
    e.active++; e.score += inherent(r);
    if (inherent(r) >= 20) e.critical++;
    m.set(key, e);
  }
  return [...m.values()].sort((a, b) => b.score - a.score || a.key.localeCompare(b.key));
};

export function computeInsights(risks: readonly RiskItem[], now = new Date()): RiskInsights {
  const active = risks.filter(r => r.status !== "closed");
  const count = (s: RiskItem["status"]) => risks.filter(r => r.status === s).length;
  const due = (r: RiskItem) => daysUntil(r.due_date, now);
  const withRes = active.filter(r => residual(r) != null);
  const resAvg = avg(withRes.map(r => residual(r)!));
  const inhAvgOfRes = avg(withRes.map(inherent));

  const ageOf = (r: RiskItem) => {
    const t = new Date(`${r.identified_at.slice(0, 10)}T00:00:00Z`).getTime();
    return Number.isNaN(t) ? null : Math.max(0, Math.round((Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) - t) / DAY));
  };
  const ages = active.map(r => ({ r, d: ageOf(r) })).filter((x): x is { r: RiskItem; d: number } => x.d != null);
  const oldest = ages.sort((a, b) => b.d - a.d)[0];

  const focus = active.map(r => {
    const score = inherent(r), d = due(r), reasons: string[] = [];
    let rank = score;
    if (d != null && d < 0) { reasons.push(`Overdue by ${-d} day${-d === 1 ? "" : "s"}`); rank += 100; }
    else if (d != null && d <= 7) { reasons.push(d === 0 ? "Due today" : `Due in ${d} day${d === 1 ? "" : "s"}`); rank += 30; }
    if (score >= 20) { reasons.push(`Critical (${score})`); rank += 50; }
    else if (score >= 12) { reasons.push(`High (${score})`); rank += 20; }
    if (r.owner === "unassigned") { reasons.push("Nobody owns it"); rank += 15; }
    if (d == null && score >= 12) reasons.push("No due date");
    return { r, rank, reasons };
  }).filter(x => x.reasons.length > 0 && (x.rank >= 20 || x.reasons.some(s => s.startsWith("Overdue"))))
    .sort((a, b) => b.rank - a.rank || a.r.id.localeCompare(b.r.id))
    .slice(0, FOCUS_LIMIT)
    .map(({ r, reasons }): FocusItem => ({ id: r.id, title: r.title, score: inherent(r), level: levelOf(inherent(r)), reasons, repo: r.repo }));

  return {
    total: risks.length,
    open: count("open"), mitigating: count("mitigating"), accepted: count("accepted"), closed: count("closed"),
    active: active.length,
    critical: active.filter(r => inherent(r) >= 20).length,
    high: active.filter(r => inherent(r) >= 12 && inherent(r) < 20).length,
    overdue: active.filter(r => (due(r) ?? 0) < 0).length,
    dueSoon: active.filter(r => { const d = due(r); return d != null && d >= 0 && d <= 7; }).length,
    unassigned: active.filter(r => r.owner === "unassigned").length,
    highWithoutDueDate: active.filter(r => inherent(r) >= 12 && !r.due_date).length,
    acceptedUnexplained: risks.filter(r => r.status === "accepted" && r.notes.length === 0 && (r.auto_derived || !r.mitigation.trim())).length,
    avgInherent: round1(avg(active.map(inherent))),
    avgResidual: round1(resAvg),
    reductionPct: resAvg != null && inhAvgOfRes ? Math.round((1 - resAvg / inhAvgOfRes) * 100) : null,
    withResidual: withRes.length,
    autoDerived: risks.filter(r => r.auto_derived).length,
    autoClosed: risks.filter(r => r.auto_derived && r.status === "closed").length,
    avgAgeDays: round1(avg(ages.map(a => a.d))),
    oldest: oldest ? { id: oldest.r.id, title: oldest.r.title, days: oldest.d } : null,
    byRepo: exposure(active, r => r.repo).slice(0, 5),
    byCategory: exposure(active, r => r.category as RiskCategory),
    focus,
  };
}
