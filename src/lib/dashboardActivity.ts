/**
 * Dashboard "Recent activity", from what the dashboard payload actually records: each repository's latest scan and
 * each signed-off high-risk file. Nothing is filled in: no invented PR numbers, risk levels, file counts or extra
 * events to pad the list -- an event without a real timestamp is left out.
 */
import type { ActivityEvent, DashboardData } from "@/types";

export function deriveActivity(data: DashboardData, limit = 15): ActivityEvent[] {
  const events: ActivityEvent[] = [];

  for (const r of data.repos) {
    if (!r.latest_scan_id || !r.last_scan) continue;
    events.push({
      type: "scan", timestamp: new Date(r.last_scan).toISOString(), repo: r.repo,
      pr_number: 0, scan_id: r.latest_scan_id,
      overall_risk: "", file_count: 0, total_ai_pct: r.ai_pct,
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
