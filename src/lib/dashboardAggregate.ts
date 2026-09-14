/**
 * Core dashboard aggregate query — moved out of api/dashboard/route.ts so it
 * can also be called from lib/autoIncidents.ts. Next.js route.ts files may
 * only export the reserved HTTP-method handlers (GET/POST/etc.) plus a small
 * fixed set of config exports, so a plain helper function can't live there.
 *
 * prAuthorFilter: when set, restricts to scans opened by this GitHub login.
 */

import { createServiceClient } from "@/lib/supabase";

export async function fetchDashboard(org_id: string, days: number, prAuthorFilter: string | null) {
  const db    = createServiceClient();
  const since = new Date(Date.now() - days * 86400_000).toISOString();

  // Aggregate per-repo stats from scans
  // When prAuthorFilter is set (developer role), restrict to that author's PRs.
  let scansQuery = db
    .from("scans")
    .select("id, repo_full_name, overall_risk, total_ai_percentage, file_count, created_at")
    .eq("org_id", org_id)
    .gte("created_at", since)
    .order("created_at", { ascending: false });
  if (prAuthorFilter) scansQuery = scansQuery.eq("pr_author", prAuthorFilter);
  const { data: scansRaw } = await scansQuery;

  // All scans for this org (no date filter) — used for violation dedup.
  let allScansQuery = db
    .from("scans")
    .select("id, repo_full_name, created_at")
    .eq("org_id", org_id);
  if (prAuthorFilter) allScansQuery = allScansQuery.eq("pr_author", prAuthorFilter);
  const { data: allScansRaw } = await allScansQuery;

  // Exclude repos with no corresponding active `repositories` row. Under
  // normal operation every scan's repo has one (the webhook handler upserts
  // it alongside every scan), so this only ever filters out repos that were
  // explicitly deactivated or removed -- without it, a removed repo's old
  // scan headers (which can outlive the repo record; attestations referencing
  // them are permanently undeletable, which transitively blocks deleting the
  // scans too) would resurface here forever with stale zeroed-out stats.
  const { data: activeRepoRows } = await db
    .from("repositories")
    .select("repo_full_name")
    .eq("org_id", org_id)
    .eq("is_active", true);
  const activeRepoNames = new Set((activeRepoRows ?? []).map(r => r.repo_full_name));
  const scans    = (scansRaw ?? []).filter(s => activeRepoNames.has(s.repo_full_name));
  const allScans = (allScansRaw ?? []).filter(s => activeRepoNames.has(s.repo_full_name));

  // Compute the latest scan per repo (from date-filtered scans, not allScans
  // which would pull in repos scanned months ago and cause ghost banners).
  // Done BEFORE attestations/violations queries so we can scope them to only
  // these scan_ids — avoiding Supabase's server-side row limit (which can be
  // as low as 1000 and cannot be overridden by .limit() from the client when
  // the project has a max_rows setting). Scoping to ~4 repos × ~100 files
  // = ~400 rows eliminates the limit problem permanently regardless of how
  // many historical scans or backfilled attestation rows the org accumulates.
  const latestScanIdPerRepo = (() => {
    const m = new Map<string, { id: string; created_at: string }>();
    for (const s of scans ?? []) {
      const existing = m.get(s.repo_full_name);
      if (!existing || s.created_at > existing.created_at) {
        m.set(s.repo_full_name, { id: s.id, created_at: s.created_at });
      }
    }
    return [...m.values()].map(v => v.id);
  })();

  // Attestations scoped to latest scan per repo AND filtered to CRITICAL/HIGH.
  // attestedFileSet is only checked against top_risk_files which is already
  // CRITICAL/HIGH only. attestedRepoFiles (SLA dedup) only needs to suppress
  // breaches on CRITICAL/HIGH violations (now also filtered to that risk level).
  // This brings attestation rows from ~83/repo (all risk levels) to ~72/repo
  // (CRITICAL/HIGH only), matching violations and riskFiles — all three queries
  // now scale at the same rate and the bottleneck is ~13 repos before any hits
  // the server-side row cap.
  const { data: attests } = latestScanIdPerRepo.length === 0 ? { data: [] } : await db
    .from("attestations")
    .select("scan_id, file_path, reviewer_email, created_at")
    .in("scan_id", latestScanIdPerRepo)
    .in("risk_score", ["CRITICAL", "HIGH"]);

  // Violations scoped to latest scan per repo AND filtered to CRITICAL/HIGH
  // only — the dashboard only uses violations for unattested_deploy_count and
  // SLA breach detection, both of which already filter to CRITICAL/HIGH. MEDIUM
  // violations are never shown in either banner or SLA section. Filtering here
  // halves the row count (MEDIUM files make up ~half of violations), giving 2x
  // more headroom before hitting the server-side max_rows limit as more repos
  // are connected.
  const { data: violations } = latestScanIdPerRepo.length === 0 ? { data: [] } : await db
    .from("violations")
    .select("id, scan_id, file_path, risk_score, status, sla_deadline")
    .in("scan_id", latestScanIdPerRepo)
    .in("risk_score", ["CRITICAL", "HIGH"]);

  const { data: riskFiles } = latestScanIdPerRepo.length === 0 ? { data: null } : await db
    .from("scan_files")
    .select("scan_id, file_path, ai_percentage, risk_score, risk_indicators, created_at, scans(repo_full_name, pr_number)")
    .eq("org_id", org_id)
    .in("risk_score", ["CRITICAL", "HIGH"])
    .in("scan_id", latestScanIdPerRepo)
    .order("ai_percentage", { ascending: false })
    .limit(1000) as { data: Array<{ scan_id: string; file_path: string; ai_percentage: number; risk_score: string; risk_indicators: string[]; created_at: string; scans: { repo_full_name: string; pr_number: number } | null }> | null };


  // Build repo stats
  const repoMap = new Map<string, {
    ai_sum: number; ai_count: number; scan_count: number;
    file_count: number; last_scan: string; latest_scan_id: string;
  }>();

  const attestedFileSet = new Set((attests ?? []).map(a => `${a.scan_id}::${a.file_path}`));
  const attestationByFile = new Map(
    (attests ?? []).map(a => [`${a.scan_id}::${a.file_path}`, { reviewer_email: a.reviewer_email, created_at: a.created_at }]),
  );

  scans.forEach(s => {
    const r = repoMap.get(s.repo_full_name) ?? {
      ai_sum: 0, ai_count: 0, scan_count: 0, file_count: 0,
      last_scan: s.created_at, latest_scan_id: s.id,
    };
    r.ai_sum   += s.total_ai_percentage;
    r.ai_count += 1;
    r.scan_count += 1;
    r.file_count += s.file_count;
    if (s.created_at > r.last_scan) { r.last_scan = s.created_at; r.latest_scan_id = s.id; }
    repoMap.set(s.repo_full_name, r);
  });

  // Count attested files per repo by joining attestations → scans → repo
  const scanToRepo = new Map(scans.map(s => [s.id, s.repo_full_name]));
  const attestedPerRepo = new Map<string, number>();
  (attests ?? []).forEach(a => {
    const repo = scanToRepo.get(a.scan_id);
    if (repo) attestedPerRepo.set(repo, (attestedPerRepo.get(repo) ?? 0) + 1);
  });

  // Denominator for attestation rate must be CRITICAL/HIGH files in the
  // latest scan (same scope as `attests` above and the app-wide formula:
  // "attested_high_crit_files ÷ total_high_crit_files") -- this previously
  // divided by r.file_count, which is EVERY file across EVERY scan in the
  // date range regardless of risk level. Since most files in a scan are
  // LOW/MEDIUM and never need attestation, that denominator was 10-100x too
  // large, so every repo showed ~0% even when 100% of its actual CRITICAL/
  // HIGH files were attested. riskFiles is already fetched (CRITICAL/HIGH,
  // scoped to latestScanIdPerRepo) for top_risk_files -- reuse it here.
  const highCritPerRepo = new Map<string, number>();
  (riskFiles ?? []).forEach(f => {
    const repo = f.scans?.repo_full_name;
    if (repo) highCritPerRepo.set(repo, (highCritPerRepo.get(repo) ?? 0) + 1);
  });

  const repos = Array.from(repoMap.entries()).map(([repo, r]) => {
    const attested    = attestedPerRepo.get(repo) ?? 0;
    const highCrit     = highCritPerRepo.get(repo) ?? 0;
    const attestRate  = highCrit === 0 ? 1 : Math.min(1, attested / highCrit);
    return {
      repo,
      ai_pct:           r.ai_count === 0 ? 0 : r.ai_sum / r.ai_count,
      attestation_rate: attestRate,
      last_scan:        r.last_scan.split("T")[0],
      scan_count:       r.scan_count,
      file_count:       r.file_count,
      latest_scan_id:   r.latest_scan_id,
      // CRITICAL/HIGH file count in the latest scan -- already computed
      // above for attestRate's denominator; exposing it lets the UI rank
      // repos by concentration of actionable risk (see "Top Risk Repos").
      high_crit_count:  highCrit,
    };
  });

  // Risk trend (group by ISO week — Monday-anchored)
  //
  // Previously counted whole SCANS (one per PR/commit), tagged by that
  // scan's single overall_risk -- despite every consumer of this data
  // (RiskTrendChart's tooltip, RiskDonut's "risk files" label and center
  // count, the dashboard's own "HIGH, CRITICAL & MEDIUM files over time"
  // caption) presenting it as a FILE count. A scan with 50 CRITICAL files
  // still only ever added "1" to critical for that week, so both charts
  // read far lower than the real number of at-risk files -- worse for
  // repos with large PRs, since one heavy scan is one data point either way.
  //
  // Then fixed by counting scan_files rows directly and bucketing by week
  // in JS -- but that still fetched up to 5000 raw rows, and Supabase's
  // server-side max_rows setting on this project silently caps every query
  // at 1000 regardless of the client's .limit() (same cap called out below
  // for risk_totals). A single day's scanning burst can fill all 1000 rows
  // with one week's data, collapsing the whole chart down to one point --
  // which is exactly what "Peak/Current/Weekly Average all read 1000, only
  // one x-axis tick shown" means. Now computed via get_risk_trend(), a
  // Postgres function that does the GROUP BY server-side (see migration
  // 20260914_risk_trend_rpc.sql) -- it returns at most 10 rows (one per
  // week) no matter how many scan_files rows exist underneath it, so it's
  // both exact and immune to the row cap.
  const toMonday = (iso: string) => {
    const d = new Date(iso);
    const dow = d.getUTCDay(); // 0=Sun
    d.setUTCDate(d.getUTCDate() - (dow === 0 ? 6 : dow - 1));
    return d.toISOString().slice(0, 10);
  };
  const scanIdsInRange = scans.map(s => s.id);
  const { data: trendRows } = scanIdsInRange.length === 0 ? { data: [] } : await db
    .rpc("get_risk_trend", { p_scan_ids: scanIdsInRange }) as {
      data: Array<{ week_start: string; critical_count: number; high_count: number; medium_count: number }> | null;
    };
  const risk_trend = (trendRows ?? [])
    .slice()
    .sort((a, b) => a.week_start.localeCompare(b.week_start))
    .map(t => ({ date: t.week_start, high_count: t.high_count, critical_count: t.critical_count, medium_count: t.medium_count }));

  // If the most recent bucket is the CURRENT (still in-progress) week,
  // relabel it with today's actual date instead of that week's Monday.
  // Otherwise the chart's rightmost point can look stale -- e.g. showing
  // "09-07" as the last tick when today is "09-12" -- even though that
  // point already includes everything scanned today; only the label was
  // anchored to the week's start rather than how far the week has run.
  if (risk_trend.length > 0) {
    const todayIso = new Date().toISOString();
    const currentWeekMonday = toMonday(todayIso);
    const last = risk_trend[risk_trend.length - 1];
    if (last.date === currentWeekMonday) {
      last.date = todayIso.slice(0, 10);
    }
  }

  // Risk Distribution totals — deliberately NOT derived by summing
  // risk_trend above. That array is a row-limited, per-week breakdown (it
  // has to fetch actual rows to bucket by week); summing it silently
  // truncates at whatever the row limit happens to be. A vulnerability-
  // dense org blew straight through 1000 and the donut displayed exactly
  // "1000" -- a dead giveaway it was hitting the cap rather than showing
  // the real total. These are separate, exact COUNT queries (head:true --
  // no rows transferred, so PostgREST's max_rows row-transfer cap doesn't
  // apply), one per risk level, so the distribution is always accurate
  // regardless of how many files that entails.
  const countByRisk = async (risk: string): Promise<number> => {
    if (scanIdsInRange.length === 0) return 0;
    const { count } = await db
      .from("scan_files")
      .select("id", { count: "exact", head: true })
      .in("scan_id", scanIdsInRange)
      .eq("risk_score", risk);
    return count ?? 0;
  };
  const [criticalTotal, highTotal, mediumTotal] = await Promise.all([
    countByRisk("CRITICAL"), countByRisk("HIGH"), countByRisk("MEDIUM"),
  ]);
  const risk_totals = { critical_count: criticalTotal, high_count: highTotal, medium_count: mediumTotal };

  // Top risk files — dedupe by repo+file_path, keeping each file's most
  // recent scan (riskFiles is ordered created_at desc), then rank by AI%.
  const seenFiles = new Set<string>();
  const top_risk_files = (riskFiles ?? [])
    .filter(f => {
      const scan = f.scans as { repo_full_name: string; pr_number: number } | null;
      const key  = `${scan?.repo_full_name ?? ""}::${f.file_path}`;
      if (seenFiles.has(key)) return false;
      seenFiles.add(key);
      return true;
    })
    .sort((a, b) => b.ai_percentage - a.ai_percentage)
    .map(f => {
      const scan = f.scans as { repo_full_name: string; pr_number: number } | null;
      const key  = `${f.scan_id}::${f.file_path}`;
      const attested = attestedFileSet.has(key);
      const attestation = attestationByFile.get(key);
      return {
        repo:       scan?.repo_full_name ?? "",
        file_path:  f.file_path,
        ai_pct:     f.ai_percentage,
        risk_score: f.risk_score,
        attested,
        scan_id:    f.scan_id,
        pr_number:  scan?.pr_number ?? 0, // 0 = no PR (direct push); UI guards with > 0
        attested_by: attestation?.reviewer_email,
        attested_at: attestation?.created_at,
      };
    });

  const totalFiles   = scans.reduce((s, sc) => s + sc.file_count, 0);
  const avgAI        = scans.length === 0 ? 0 : scans.reduce((s, sc) => s + sc.total_ai_percentage, 0) / scans.length;

  // Dedupe violations by repo+file_path, keeping only the most recent scan's
  // violation for that file. A still-open violation from an earlier scan is
  // superseded once a later scan (and possibly its attestation) exists for
  // the same file — only the latest scan's status should drive SLA breaches.
  const scanCreatedAtAll = new Map((allScans ?? []).map(s => [s.id, s.created_at]));
  const scanToRepoAll    = new Map((allScans ?? []).map(s => [s.id, s.repo_full_name]));
  const latestViolationByFile = new Map<string, NonNullable<typeof violations>[number]>();
  (violations ?? []).forEach(v => {
    const repo = scanToRepoAll.get(v.scan_id);
    if (!repo) return;
    const key      = `${repo}::${v.file_path}`;
    const created  = scanCreatedAtAll.get(v.scan_id) ?? "";
    const existing = latestViolationByFile.get(key);
    if (!existing || created > (scanCreatedAtAll.get(existing.scan_id) ?? "")) {
      latestViolationByFile.set(key, v);
    }
  });
  // Build a set of attested repo+file_path combinations so we can suppress
  // false SLA breaches for files that are attested in any scan for the same
  // repo (violation.status may lag behind if attestation happened via an
  // older flow that only resolved the specific scan's violation).
  // Use scanToRepoAll (no date filter) so attestations on older scans outside
  // the current period window still suppress false SLA breaches.
  const attestedRepoFiles = new Set(
    (attests ?? []).map(a => `${scanToRepoAll.get(a.scan_id) ?? scanToRepo.get(a.scan_id) ?? ""}::${a.file_path}`)
  );

  const currentViolations = Array.from(latestViolationByFile.values())
    .filter(v => {
      if (v.status !== "open" && v.status !== "in_review") return false;
      // Suppress if the file already has an attestation in this repo
      const repo = scanToRepoAll.get(v.scan_id) ?? "";
      if (attestedRepoFiles.has(`${repo}::${v.file_path}`)) return false;
      return true;
    });

  const unattested = currentViolations.filter(v => v.risk_score === "CRITICAL" || v.risk_score === "HIGH").length;

  // SLA breaches: open CRITICAL/HIGH violations whose deadline has passed.
  const now = Date.now();
  const breached = currentViolations.filter(
    v => v.sla_deadline && new Date(v.sla_deadline).getTime() < now,
  );
  const sla_breach_critical_count = breached.filter(v => v.risk_score === "CRITICAL").length;
  const sla_breach_high_count     = breached.filter(v => v.risk_score === "HIGH").length;
  const sla_breach_files = breached
    .filter(v => v.risk_score === "CRITICAL" || v.risk_score === "HIGH")
    .map(v => ({
      file_path:  v.file_path,
      risk_score: v.risk_score,
      repo:       scanToRepoAll.get(v.scan_id) ?? "",
      scan_id:    v.scan_id,
      sla_deadline: v.sla_deadline as string,
    }));

  return {
    repos,
    overall_ai_pct:          avgAI,
    attestation_rate:        repos.length === 0 ? 0 : repos.reduce((s, r) => s + r.attestation_rate, 0) / repos.length,
    unattested_deploy_count: unattested,
    risk_trend,
    risk_totals,
    scan_count:   scans.length,
    file_count:   totalFiles,
    top_risk_files,
    sla_breach_critical_count,
    sla_breach_high_count,
    sla_breach_files,
  };
}

/**
 * Lean subset of fetchDashboard for callers that only need unattested-risk
 * state (currently just lib/autoIncidents.ts) -- skips risk_trend (a row
 * fetch of up to 5000 scan_files for per-week bucketing), risk_totals
 * (3 separate exact-COUNT queries), and SLA breach computation, none of
 * which incident auto-generation uses. This runs on every scan completion
 * and every attestation (single + bulk), so avoiding the full aggregate's
 * cost there matters -- the full version is meant for the dashboard page
 * itself, which is cached and polled far less often per event.
 */
export async function fetchUnattestedRiskState(org_id: string) {
  const db = createServiceClient();

  const { data: scansRaw } = await db
    .from("scans")
    .select("id, repo_full_name, created_at")
    .eq("org_id", org_id);

  const { data: activeRepoRows } = await db
    .from("repositories")
    .select("repo_full_name")
    .eq("org_id", org_id)
    .eq("is_active", true);
  const activeRepoNames = new Set((activeRepoRows ?? []).map(r => r.repo_full_name));
  const scans = (scansRaw ?? []).filter(s => activeRepoNames.has(s.repo_full_name));

  const latestScanIdPerRepo = (() => {
    const m = new Map<string, { id: string; created_at: string }>();
    for (const s of scans) {
      const existing = m.get(s.repo_full_name);
      if (!existing || s.created_at > existing.created_at) {
        m.set(s.repo_full_name, { id: s.id, created_at: s.created_at });
      }
    }
    return [...m.values()].map(v => v.id);
  })();

  if (latestScanIdPerRepo.length === 0) {
    return { top_risk_files: [] as { repo: string; file_path: string; ai_pct: number; risk_score: string; pr_number: number; attested: boolean }[], unattested_deploy_count: 0, repos: [] as { repo: string; attestation_rate: number }[], attestation_rate: 0 };
  }

  const { data: attests } = await db
    .from("attestations")
    .select("scan_id, file_path")
    .in("scan_id", latestScanIdPerRepo)
    .in("risk_score", ["CRITICAL", "HIGH"]);
  const attestedFileSet = new Set((attests ?? []).map(a => `${a.scan_id}::${a.file_path}`));

  const { data: violations } = await db
    .from("violations")
    .select("scan_id, file_path, risk_score, status")
    .in("scan_id", latestScanIdPerRepo)
    .in("risk_score", ["CRITICAL", "HIGH"]);

  const { data: riskFiles } = await db
    .from("scan_files")
    .select("scan_id, file_path, ai_percentage, risk_score, scans(repo_full_name, pr_number)")
    .eq("org_id", org_id)
    .in("risk_score", ["CRITICAL", "HIGH"])
    .in("scan_id", latestScanIdPerRepo)
    .limit(1000) as { data: Array<{ scan_id: string; file_path: string; ai_percentage: number; risk_score: string; scans: { repo_full_name: string; pr_number: number } | null }> | null };

  const scanToRepo = new Map(scans.map(s => [s.id, s.repo_full_name]));
  const attestedPerRepo = new Map<string, number>();
  (attests ?? []).forEach(a => {
    const repo = scanToRepo.get(a.scan_id);
    if (repo) attestedPerRepo.set(repo, (attestedPerRepo.get(repo) ?? 0) + 1);
  });
  const highCritPerRepo = new Map<string, number>();
  (riskFiles ?? []).forEach(f => {
    const repo = f.scans?.repo_full_name;
    if (repo) highCritPerRepo.set(repo, (highCritPerRepo.get(repo) ?? 0) + 1);
  });
  const repos = [...new Set(scans.map(s => s.repo_full_name))].map(repo => {
    const attested = attestedPerRepo.get(repo) ?? 0;
    const highCrit = highCritPerRepo.get(repo) ?? 0;
    return { repo, attestation_rate: highCrit === 0 ? 1 : Math.min(1, attested / highCrit) };
  });

  const seenFiles = new Set<string>();
  const top_risk_files = (riskFiles ?? [])
    .filter(f => {
      const key = `${f.scans?.repo_full_name ?? ""}::${f.file_path}`;
      if (seenFiles.has(key)) return false;
      seenFiles.add(key);
      return true;
    })
    .map(f => ({
      repo: f.scans?.repo_full_name ?? "",
      file_path: f.file_path,
      ai_pct: f.ai_percentage,
      risk_score: f.risk_score,
      pr_number: f.scans?.pr_number ?? 0,
      attested: attestedFileSet.has(`${f.scan_id}::${f.file_path}`),
    }));

  const latestViolationByFile = new Map<string, { status: string; risk_score: string }>();
  (violations ?? []).forEach(v => {
    const repo = scanToRepo.get(v.scan_id);
    if (!repo) return;
    latestViolationByFile.set(`${repo}::${v.file_path}`, { status: v.status, risk_score: v.risk_score });
  });
  const unattested = [...latestViolationByFile.values()].filter(v => v.status === "open" || v.status === "in_review").length;

  return {
    top_risk_files,
    unattested_deploy_count: unattested,
    repos,
    attestation_rate: repos.length === 0 ? 0 : repos.reduce((s, r) => s + r.attestation_rate, 0) / repos.length,
  };
}
