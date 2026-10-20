/**
 * Analytics in plain words: the same measured numbers (lib/orgAnalytics.ts), said the way people say them --
 * "half were signed off within 5 hours" rather than "median 5h", "9 in 10 within 2 days" rather than "p90". Pure.
 */

const n = (x: number, one: string, many = `${one}s`) => `${x} ${x === 1 ? one : many}`;

/** "12 minutes", "5 hours", "2 days" -- rounded the way you'd say it. */
export function duration(h: number | null | undefined): string {
  if (h == null || !Number.isFinite(h)) return "—";
  if (h < 1) return n(Math.max(1, Math.round(h * 60)), "minute");
  if (h < 48) return n(Math.round(h), "hour");
  return n(Math.round(h / 24), "day");
}

/** Compact form for big numbers on cards: "12 min", "5 h", "2 days". */
export function shortDuration(h: number | null | undefined): string {
  if (h == null || !Number.isFinite(h)) return "—";
  if (h < 1) return `${Math.max(1, Math.round(h * 60))} min`;
  if (h < 48) return `${Math.round(h)} h`;
  return n(Math.round(h / 24), "day");
}

export interface ReviewTimeLike { severity: string; count: number; median_hours: number | null; p90_hours: number | null; on_time: number; with_deadline: number }

/** One or two sentences about how fast files of one severity were signed off. */
export function reviewSentence(r: ReviewTimeLike): string {
  if (r.count === 0) return `No ${r.severity} files were signed off in this period.`;
  const speed = r.count === 1
    ? `The one ${r.severity} sign-off came ${duration(r.median_hours)} after the scan.`
    : `Half of the ${r.count} ${r.severity} sign-offs came within ${duration(r.median_hours)} of the scan, and 9 in 10 within ${duration(r.p90_hours)}.`;
  const deadline = r.with_deadline ? ` ${r.on_time} of ${r.with_deadline} were signed off before their fix deadline.` : "";
  return speed + deadline;
}

/** What the change in open findings means. */
export function backlogSentence(opened: number, closed: number): string {
  const net = opened - closed;
  if (opened === 0 && closed === 0) return "No findings were opened or closed in this period.";
  if (net > 0) return `${n(net, "more finding")} opened than closed — open work grew.`;
  if (net < 0) return `${n(-net, "more finding")} closed than opened — open work shrank.`;
  return "As many findings were closed as opened — open work held steady.";
}

/** How long the current open findings would take to clear at this period's pace. `closed` is the period's count
 *  (the per-day rate is rounded and reads 0 for a slow month, so the pace is said from the count). */
export function clearSentence(open: number, closed: number, periodDays: number, daysToClear: number | null): string {
  if (open === 0) return "Nothing is waiting — every finding is closed.";
  if (daysToClear == null || closed <= 0) return `${n(open, "finding")} open, and none were closed this period, so there's no pace to measure yet.`;
  const perDay = closed / Math.max(periodDays, 1);
  const pace = perDay >= 1 ? `about ${Math.round(perDay * 10) / 10} closed a day` : `${n(closed, "finding")} closed in ${n(periodDays, "day")}`;
  return `At this period's pace (${pace}), the ${n(open, "open finding")} would all be closed in about ${n(Math.max(1, Math.round(daysToClear)), "day")}.`;
}
