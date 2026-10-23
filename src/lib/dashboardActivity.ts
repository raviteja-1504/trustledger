/**
 * Dashboard "Recent activity", from what the dashboard payload actually records: each repository's latest scan and
 * each signed-off high-risk file. Nothing is filled in: no invented PR numbers, risk levels, file counts or extra
 * events to pad the list -- an event without a real timestamp is left out.
 */
import type { ActivityEvent, DashboardData } from "@/types";

/** One identity per real event: a sign-off on a file of a scan, or a scan. Timestamps differ between the copy the PR
 * page records locally (browser clock) and the server's, so they can't be part of the key. */
export const activityKey = (e: Pick<ActivityEvent, "type" | "scan_id" | "file_path">) =>
  e.type === "attestation" ? `att::${e.scan_id}::${e.file_path}` : `scan::${e.scan_id}`;

/**
 * Merge server events with sign-offs recorded locally on the PR page (shown before the server data catches up).
 * Each event appears once; the server's copy wins. Local events for repos outside the current data (another org,
 * or outside the developer's scope) are dropped when `repos` is given.
 */
export function mergeActivity(server: readonly ActivityEvent[], local: readonly ActivityEvent[], repos?: ReadonlySet<string>, limit = 15): ActivityEvent[] {
  const seen = new Set<string>();
  const out: ActivityEvent[] = [];
  for (const e of server) { const k = activityKey(e); if (!seen.has(k)) { seen.add(k); out.push(e); } }
  for (const e of local) {
    if (repos && !repos.has(e.repo)) continue;
    const k = activityKey(e);
    if (!seen.has(k)) { seen.add(k); out.push(e); }
  }
  return out.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).slice(0, limit);
}

export function deriveActivity(data: DashboardData, limit = 15): ActivityEvent[] {
  const events: ActivityEvent[] = [];

  for (const r of data.repos) {
    if (!r.latest_scan_id || !r.last_scan) continue;
    events.push({
      type: "scan", timestamp: new Date(r.last_scan).toISOString(), repo: r.repo,
      pr_number: 0, scan_id: r.latest_scan_id,
      // this scan's own AI share; the repo's period average only for payloads cached before it was sent
      overall_risk: "", file_count: 0, total_ai_pct: r.latest_ai_pct ?? r.ai_pct,
      file_path: "", reviewer_email: "",
    });
  }

  for (const f of data.top_risk_files) {
    if (!f.attested || !f.attested_at) continue;
    events.push({
      type: "attestation", timestamp: f.attested_at, repo: f.repo,
      pr_number: f.pr_number, scan_id: f.scan_id,
      overall_risk: f.risk_score, file_count: 0, total_ai_pct: f.ai_pct,
      file_path: f.file_path, reviewer_email: f.attested_by ?? "",
    });
  }

  return events
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, limit);
}
