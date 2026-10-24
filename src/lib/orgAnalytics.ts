/**
 * Analytics: what actually happened in a period, measured from records -- scans, findings opened and closed, how long
 * high-risk files waited for a reviewer, the backlog's age, AI content over time, who reviews.
 *
 * Nothing is estimated: review time is attestation time minus the time the file's scan ran; "closed" is a finding's
 * resolved_at; backlog age is a finding's created_at. Pure: /api/analytics loads the rows.
 */

export interface AnalyticsRows {
  now: string;
  start: string;   // ISO, inclusive
  end: string;     // ISO, inclusive
  scans: ReadonlyArray<{ id: string; repo: string; pr_number: number | null; pr_author: string | null; created_at: string; total_ai_percentage: number; file_count: number }>;
  /** Findings opened in the period, resolved in the period, or still open. */
  violations: ReadonlyArray<{ id: string; scan_id: string; file_path: string; risk_score: string; status: string; created_at: string; resolved_at: string | null; sla_deadline: string | null }>;
  /** Sign-offs made in the period. Their scans must be in `scans` (or in `extraScans`) to measure review time. */
  attestations: ReadonlyArray<{ scan_id: string; file_path: string; risk_score: string; reviewer_email: string | null; reviewer_github: string | null; created_at: string }>;
  /** Scans outside the period that attestations in the period refer to (for review time only). */
  extraScans?: AnalyticsRows["scans"];
  /** Every scan of the pull requests above (id, repo, PR, time): which scan is each PR's latest. Defaults to the
   *  scans above. */
  prScans?: ReadonlyArray<{ id: string; repo: string; pr_number: number | null; created_at: string }>;
}

export interface AnalyticsWeek {
  week: string;        // Monday, YYYY-MM-DD
  label: string;       // "Oct 12" or "This week"
  range: string;       // "Oct 12 – Oct 18"
  scans: number;
  prs: number;
  files: number;
  /** Files-weighted AI share of the week's scans, 0-1; null when nothing was scanned. */
  ai_share: number | null;
  opened: { critical: number; high: number; medium: number; total: number };
  closed: number;
  signoffs: number;
}

export interface ReviewTime {
  severity: "CRITICAL" | "HIGH";
  count: number;
  median_hours: number | null;
  p90_hours: number | null;
  /** Sign-offs of files whose finding had a deadline, and how many were made before it. */
  with_deadline: number;
  on_time: number;
}

export interface Analytics {
  period: { start: string; end: string; days: number };
  weeks: AnalyticsWeek[];
  totals: { scans: number; prs: number; files: number; opened: number; closed: number; signoffs: number; ai_share: number | null };
  review_time: ReviewTime[];
  backlog: {
    open: number;
    overdue: number;
    by_age: Array<{ key: "lt1d" | "d1_2" | "d2_7" | "gt7d"; label: string; count: number }>;
    /** Findings closed per day over the period. */
    closed_per_day: number;
    /** Days to clear the open backlog at that pace; null when nothing was closed. */
    days_to_clear: number | null;
  };
  reviewers: Array<{ reviewer: string; signoffs: number; median_hours: number | null }>;
  self_approvals: number;
  repos: Array<{ repo: string; scans: number; prs: number; opened: number; closed: number; open: number; ai_share: number | null }>;
}

const DAY = 86400_000;
const HOUR = 3600_000;
const OPEN = new Set(["open", "in_review"]);
const mondayOf = (ms: number) => { const d = new Date(ms); const dow = d.getUTCDay(); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - ((dow + 6) % 7) * DAY; };
const fmt = (ms: number) => new Date(ms).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
const round1 = (n: number) => Math.round(n * 10) / 10;

export function quantile(sorted: readonly number[], q: number): number | null {
  if (!sorted.length) return null;
  const pos = (sorted.length - 1) * q, lo = Math.floor(pos), hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}

function weightedAi(scans: ReadonlyArray<{ total_ai_percentage: number; file_count: number }>): number | null {
  const files = scans.reduce((a, s) => a + Math.max(0, s.file_count), 0);
  if (!files) return scans.length ? scans.reduce((a, s) => a + s.total_ai_percentage, 0) / scans.length : null;
  return scans.reduce((a, s) => a + s.total_ai_percentage * Math.max(0, s.file_count), 0) / files;
}

const prKey = (s: { repo: string; pr_number: number | null; id: string }) => s.pr_number != null && s.pr_number > 0 ? `${s.repo}#${s.pr_number}` : `${s.repo}@${s.id}`;

export function computeAnalytics(rows: AnalyticsRows): Analytics {
  const now = Date.parse(rows.now), start = Date.parse(rows.start), end = Math.min(Date.parse(rows.end), now);
  const inPeriod = (iso: string | null) => { if (!iso) return false; const t = Date.parse(iso); return t >= start && t <= end; };
  const scanById = new Map([...(rows.extraScans ?? []), ...rows.scans].map(s => [s.id, s]));
  const periodScans = rows.scans.filter(s => inPeriod(s.created_at));

  // ── Weeks ──
  const weeks = new Map<number, AnalyticsWeek>();
  const weekOf = (iso: string) => weeks.get(mondayOf(Date.parse(iso)));
  for (let m = mondayOf(start); m <= mondayOf(end); m += 7 * DAY) {
    const from = Math.max(m, start), to = Math.min(m + 6 * DAY, end);
    const current = m === mondayOf(now);
    weeks.set(m, {
      week: new Date(m).toISOString().slice(0, 10), label: current ? "This week" : fmt(m),
      range: fmt(from) === fmt(to) ? fmt(from) : `${fmt(from)} – ${fmt(to)}`,
      scans: 0, prs: 0, files: 0, ai_share: null, opened: { critical: 0, high: 0, medium: 0, total: 0 }, closed: 0, signoffs: 0,
    });
  }
  const weekScans = new Map<number, typeof periodScans>();
  for (const s of periodScans) {
    const k = mondayOf(Date.parse(s.created_at));
    const w = weeks.get(k); if (!w) continue;
    w.scans++; w.files += Math.max(0, s.file_count);
    weekScans.set(k, [...(weekScans.get(k) ?? []), s]);
  }
  for (const [k, list] of weekScans) {
    const w = weeks.get(k)!;
    w.prs = new Set(list.map(prKey)).size;
    w.ai_share = weightedAi(list);
  }
  // A FILE, not a row: every scan of a pull request -- each push, each rescan -- records its still-flagged files
  // again, and one sign-off resolves the file's row in every scan of the same content. Counting rows counted a
  // 79-file PR scanned three times as 237 found. Found = a file first flagged in the period (once, when first
  // flagged); closed = a file closed in the period (once, when first closed).
  const fileOf = (v: { scan_id: string; file_path: string }) => `${scanById.get(v.scan_id)?.repo ?? ""}::${v.file_path}`;
  const firstFlag = new Map<string, AnalyticsRows["violations"][number]>();
  const firstClose = new Map<string, AnalyticsRows["violations"][number]>();
  for (const v of rows.violations) {
    const k = fileOf(v);
    const f = firstFlag.get(k);
    if (!f || v.created_at < f.created_at) firstFlag.set(k, v);
    if (v.resolved_at && inPeriod(v.resolved_at) && !OPEN.has(v.status)) {
      const c = firstClose.get(k);
      if (!c || v.resolved_at < c.resolved_at!) firstClose.set(k, v);
    }
  }
  const openedRows = [...firstFlag.values()].filter(v => inPeriod(v.created_at));
  const closedRows = [...firstClose.values()];
  let opened = 0, closed = 0;
  for (const v of openedRows) {
    const w = weekOf(v.created_at);
    if (!w) continue;
    const sev = v.risk_score.toUpperCase();
    if (sev === "CRITICAL") w.opened.critical++; else if (sev === "HIGH") w.opened.high++; else if (sev === "MEDIUM") w.opened.medium++;
    w.opened.total++; opened++;
  }
  for (const v of closedRows) { const w = weekOf(v.resolved_at!); if (w) { w.closed++; closed++; } }
  const periodAttestations = rows.attestations.filter(a => inPeriod(a.created_at));
  for (const a of periodAttestations) { const w = weekOf(a.created_at); if (w) w.signoffs++; }

  // ── Review time: sign-off time minus the scan that flagged the file ──
  const deadlineOf = new Map(rows.violations.filter(v => v.sla_deadline).map(v => [`${v.scan_id}::${v.file_path}`, Date.parse(v.sla_deadline!)]));
  const review_time: ReviewTime[] = (["CRITICAL", "HIGH"] as const).map(severity => {
    const hours: number[] = [];
    let with_deadline = 0, on_time = 0;
    for (const a of periodAttestations) {
      if (a.risk_score.toUpperCase() !== severity) continue;
      const scan = scanById.get(a.scan_id);
      if (!scan) continue;
      const h = (Date.parse(a.created_at) - Date.parse(scan.created_at)) / HOUR;
      if (h < 0) continue;
      hours.push(h);
      const dl = deadlineOf.get(`${a.scan_id}::${a.file_path}`);
      if (dl != null) { with_deadline++; if (Date.parse(a.created_at) <= dl) on_time++; }
    }
    hours.sort((x, y) => x - y);
    const med = quantile(hours, 0.5), p90 = quantile(hours, 0.9);
    return { severity, count: hours.length, median_hours: med == null ? null : round1(med), p90_hours: p90 == null ? null : round1(p90), with_deadline, on_time };
  });

  // ── Backlog: open findings in each pull request's LATEST scan, one per (repo, file) -- the same files the
  // dashboard and Trust Score count as waiting. A file a newer scan no longer flags has no row there; its open row
  // from an older scan used to keep counting (84 here vs 79 there). Aged from when the file was first flagged:
  // a rescan doesn't make it new.
  const latestByPr = new Map<string, { id: string; created_at: string }>();
  for (const s of rows.prScans ?? [...scanById.values()]) {
    const k = prKey(s);
    const cur = latestByPr.get(k);
    if (!cur || s.created_at > cur.created_at) latestByPr.set(k, s);
  }
  const latestIds = new Set([...latestByPr.values()].map(s => s.id));
  const open = new Map<string, AnalyticsRows["violations"][number] & { repo: string }>();
  for (const v of rows.violations) {
    if (!OPEN.has(v.status) || !latestIds.has(v.scan_id)) continue;
    const repo = scanById.get(v.scan_id)?.repo ?? "";
    const k = `${repo}::${v.file_path}`;
    if (!open.has(k)) open.set(k, { ...v, repo });
  }
  const openNow = [...open.values()];
  const firstSeen = (v: { scan_id: string; file_path: string; created_at: string }) => firstFlag.get(fileOf(v))?.created_at ?? v.created_at;
  const age = (v: { scan_id: string; file_path: string; created_at: string }) => (now - Date.parse(firstSeen(v))) / DAY;
  const by_age: Analytics["backlog"]["by_age"] = [
    { key: "lt1d", label: "Under 1 day", count: openNow.filter(v => age(v) < 1).length },
    { key: "d1_2", label: "1–2 days", count: openNow.filter(v => age(v) >= 1 && age(v) < 2).length },
    { key: "d2_7", label: "2–7 days", count: openNow.filter(v => age(v) >= 2 && age(v) < 7).length },
    { key: "gt7d", label: "Over 7 days", count: openNow.filter(v => age(v) >= 7).length },
  ];
  const days = Math.max(1, Math.round((end - start) / DAY));
  const closedPerDay = closed / days;

  // ── Reviewers ──
  const byReviewer = new Map<string, number[]>();
  let self_approvals = 0;
  for (const a of periodAttestations) {
    const who = a.reviewer_email || a.reviewer_github || "unknown";
    const scan = scanById.get(a.scan_id);
    const h = scan ? (Date.parse(a.created_at) - Date.parse(scan.created_at)) / HOUR : NaN;
    byReviewer.set(who, [...(byReviewer.get(who) ?? []), h]);
    if (scan?.pr_author && a.reviewer_github && scan.pr_author.toLowerCase() === a.reviewer_github.trim().toLowerCase()) self_approvals++;
  }
  const reviewers = [...byReviewer.entries()].map(([reviewer, hs]) => {
    const valid = hs.filter(h => Number.isFinite(h) && h >= 0).sort((x, y) => x - y);
    const med = quantile(valid, 0.5);
    return { reviewer, signoffs: hs.length, median_hours: med == null ? null : round1(med) };
  }).sort((a, b) => b.signoffs - a.signoffs || a.reviewer.localeCompare(b.reviewer));

  // ── Repositories ──
  const repoStats = new Map<string, { scans: typeof periodScans; opened: number; closed: number; open: number }>();
  const repo = (name: string) => { let r = repoStats.get(name); if (!r) { r = { scans: [], opened: 0, closed: 0, open: 0 }; repoStats.set(name, r); } return r; };
  for (const s of periodScans) repo(s.repo).scans.push(s);
  for (const v of openedRows) { const name = scanById.get(v.scan_id)?.repo; if (name) repo(name).opened++; }
  for (const v of closedRows) { const name = scanById.get(v.scan_id)?.repo; if (name) repo(name).closed++; }
  for (const v of openNow) if (v.repo) repo(v.repo).open++;
  const repos = [...repoStats.entries()].map(([name, r]) => ({
    repo: name, scans: r.scans.length, prs: new Set(r.scans.map(prKey)).size, opened: r.opened, closed: r.closed, open: r.open, ai_share: weightedAi(r.scans),
  })).sort((a, b) => b.open - a.open || b.scans - a.scans || a.repo.localeCompare(b.repo));

  return {
    period: { start: new Date(start).toISOString(), end: new Date(end).toISOString(), days },
    weeks: [...weeks.values()],
    totals: {
      scans: periodScans.length, prs: new Set(periodScans.map(prKey)).size, files: periodScans.reduce((a, s) => a + Math.max(0, s.file_count), 0),
      opened, closed, signoffs: periodAttestations.length, ai_share: weightedAi(periodScans),
    },
    review_time,
    backlog: {
      open: openNow.length,
      overdue: openNow.filter(v => v.sla_deadline && Date.parse(v.sla_deadline) < now).length,
      by_age,
      closed_per_day: round1(closedPerDay),
      days_to_clear: openNow.length === 0 ? 0 : closedPerDay > 0 ? Math.ceil(openNow.length / closedPerDay) : null,
    },
    reviewers,
    self_approvals,
    repos,
  };
}
