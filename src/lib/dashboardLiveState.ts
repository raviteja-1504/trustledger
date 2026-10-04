/**
 * Applies review state the dashboard learned after its data loaded (violation statuses changed on this page or
 * elsewhere) to the dashboard numbers: which repos still await sign-off, and the attestation rates.
 */
import type { DashboardData } from "@/types";

export interface LiveReviewState {
  effectiveData: DashboardData | null;
  firstUnresolvedScanId: string | null;
  unresolvedRepoScans: { repo: string; repoName: string; scanId: string }[];
}

export function applyLiveReviewState(data: DashboardData | null, violationStatuses: Record<string, string>): LiveReviewState {
  if (!data) return { effectiveData: null, firstUnresolvedScanId: null, unresolvedRepoScans: [] };

    // Only CRITICAL and HIGH files gate a deploy — MEDIUM/LOW don't block merges
    const riskPrefix = (r: string) =>
      r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";

    const unresolvedFiles = data.top_risk_files.filter(f => {
      if (f.attested) return false;
      if (f.risk_score !== "CRITICAL" && f.risk_score !== "HIGH") return false;
      const pfx    = riskPrefix(f.risk_score);
      const status = violationStatuses[`${pfx}::${f.scan_id}::${f.file_path}`];
      const handled = status === "resolved" || status === "in_review";
      return !handled;
    });

    // Group by REPO — a repo clears once all its CRITICAL/HIGH files are attested.
    const unresolvedRepos = new Set(unresolvedFiles.map(f => f.repo));

    // "Review now →" links to the first scan from the first repo that still has work to do
    const firstUnresolvedScanId = unresolvedFiles[0]?.scan_id ?? null;

    // One chip per unresolved repo — preserve order of first occurrence in unresolvedFiles
    const seenRepos = new Map<string, string>();
    for (const f of unresolvedFiles) {
      if (!seenRepos.has(f.repo)) seenRepos.set(f.repo, f.scan_id);
    }
    const unresolvedRepoScans = Array.from(seenRepos.entries()).map(([repo, scanId]) => ({
      repo,
      repoName: repo.split("/").pop() ?? repo,
      scanId,
    }));

    // Use the client-side count directly — it's derived from top_risk_files
    // (a direct scan_files query) which is more reliable than the server's
    // unattested_deploy_count (derived from the separate violations table).
    // Previously this was capped via Math.min(data.unattested_deploy_count, ...),
    // which could suppress the banner entirely right after a new PR is raised:
    // if the scan-worker's violations insert lags behind its scan_files insert
    // (async QStash timing), the server count could read 0 while top_risk_files
    // already shows the new unattested CRITICAL/HIGH file — Math.min(0, N) = 0
    // hid both the banner and its repo-name chips even though real data existed.
    const adjusted = unresolvedRepos.size;

    // A file counts as signed off when it has an attestation, or its violation was resolved (e.g. accepted /
    // false positive) since the data loaded. "In review" is NOT signed off: it stays out of the "awaiting"
    // list above (someone is on it) but doesn't raise the attestation rate.
    const patchedTopRisk = data.top_risk_files.map(f => {
      if (f.attested) return f;
      const status = violationStatuses[`${riskPrefix(f.risk_score)}::${f.scan_id}::${f.file_path}`];
      return status === "resolved" ? { ...f, attested: true } : f;
    });

    // Attestation from the files themselves — per repo and org-wide: signed-off ÷ all HIGH/CRITICAL files.
    // (It used to take the HIGHER of this and the server's figure, so it could only ever round up.)
    const isHighCrit = (f: { risk_score: string }) => f.risk_score === "CRITICAL" || f.risk_score === "HIGH";
    const patchedRepos = data.repos.map(repo => {
      const repoFiles = patchedTopRisk.filter(f => f.repo === repo.repo && isHighCrit(f));
      if (repoFiles.length === 0) return repo;
      const rate = repoFiles.filter(f => f.attested).length / repoFiles.length;
      return rate === repo.attestation_rate ? repo : { ...repo, attestation_rate: rate };
    });
    const critHighAll = patchedTopRisk.filter(isHighCrit);
    const attestedAll = critHighAll.filter(f => f.attested).length;

    return {
      effectiveData: {
        ...data,
        attestation_rate:        critHighAll.length > 0 ? attestedAll / critHighAll.length : data.attestation_rate,
        attested_high_crit:      critHighAll.length > 0 ? attestedAll : data.attested_high_crit,
        total_high_crit:         critHighAll.length > 0 ? critHighAll.length : data.total_high_crit,
        // Repos whose latest scan still has HIGH/CRITICAL files nobody has signed off (or is reviewing).
        unattested_deploy_count: adjusted,
        top_risk_files:          patchedTopRisk,
        repos:                   patchedRepos,
      },
      firstUnresolvedScanId,
      unresolvedRepoScans,
    };
}
