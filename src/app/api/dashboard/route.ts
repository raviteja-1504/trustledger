import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { cached, cacheDel, cacheKeys, TTL } from "@/lib/cache";

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url   = new URL(req.url);
  const days  = parseInt(url.searchParams.get("days") ?? "90");
  const noCache = url.searchParams.get("nocache") === "1";

  // Cache key includes org + period
  const cacheKey = cacheKeys.dashboard(org_id, days);
  if (!noCache) {
    const hit = await cached(cacheKey, TTL.DASHBOARD, () => fetchDashboard(org_id, days));
    return NextResponse.json(hit, {
      headers: { "X-Cache": "HIT", "Cache-Control": `s-maxage=${TTL.DASHBOARD}` },
    });
  }
  const result = await fetchDashboard(org_id, days);
  return NextResponse.json(result, {
    headers: { "X-Cache": "MISS", "Cache-Control": `s-maxage=${TTL.DASHBOARD}` },
  });
}

// ── Core dashboard query (separated so it can be cached) ──────────────────

async function fetchDashboard(org_id: string, days: number) {
  const db    = createServiceClient();
  const since = new Date(Date.now() - days * 86400_000).toISOString();

  // Aggregate per-repo stats from scans
  const { data: scans } = await db
    .from("scans")
    .select("id, repo_full_name, overall_risk, total_ai_percentage, file_count, created_at")
    .eq("org_id", org_id)
    .gte("created_at", since)
    .order("created_at", { ascending: false });

  // Attestations in period
  const { data: attests } = await db
    .from("attestations")
    .select("scan_id, file_path, reviewer_email, created_at")
    .eq("org_id", org_id)
    .gte("created_at", since);

  // All violations for this org (no status filter) — needed so that, per
  // file, we can tell whether an older scan's still-open violation has been
  // superseded by a later scan/attestation of that same file (see dedup below).
  const { data: violations } = await db
    .from("violations")
    .select("id, scan_id, file_path, risk_score, status, sla_deadline")
    .eq("org_id", org_id);

  // All scans for this org (no date filter) — used to find each file's most
  // recent scan when deduping violations across repeated scans.
  const { data: allScans } = await db
    .from("scans")
    .select("id, repo_full_name, created_at")
    .eq("org_id", org_id);

  // Scan files for top risk. Fetch recent-first so that, once deduped by
  // repo+file_path below, we keep each file's most recent occurrence.
  const { data: riskFiles } = await db
    .from("scan_files")
    .select("scan_id, file_path, ai_percentage, risk_score, risk_indicators, created_at, scans(repo_full_name, pr_number)")
    .eq("org_id", org_id)
    .in("risk_score", ["CRITICAL", "HIGH"])
    .gte("created_at", since)
    .order("created_at", { ascending: false })
    .limit(200) as { data: Array<{ scan_id: string; file_path: string; ai_percentage: number; risk_score: string; risk_indicators: string[]; created_at: string; scans: { repo_full_name: string; pr_number: number } | null }> | null };

  if (!scans) return { repos:[], overall_ai_pct:0, attestation_rate:0, unattested_deploy_count:0, risk_trend:[], scan_count:0, file_count:0, top_risk_files:[] };

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

  const repos = Array.from(repoMap.entries()).map(([repo, r]) => {
    const attested   = attestedPerRepo.get(repo) ?? 0;
    const attestRate = r.file_count === 0 ? 1 : Math.min(1, attested / r.file_count);
    return {
      repo,
      ai_pct:           r.ai_count === 0 ? 0 : r.ai_sum / r.ai_count,
      attestation_rate: attestRate,
      last_scan:        r.last_scan.split("T")[0],
      scan_count:       r.scan_count,
      file_count:       r.file_count,
      latest_scan_id:   r.latest_scan_id,
    };
  });

  // Risk trend (group by ISO week — Monday-anchored)
  const toMonday = (iso: string) => {
    const d = new Date(iso);
    const dow = d.getUTCDay(); // 0=Sun
    d.setUTCDate(d.getUTCDate() - (dow === 0 ? 6 : dow - 1));
    return d.toISOString().slice(0, 10);
  };
  const trendMap = new Map<string, { high: number; critical: number; medium: number }>();
  scans.forEach(s => {
    const week = toMonday(s.created_at);
    const t = trendMap.get(week) ?? { high: 0, critical: 0, medium: 0 };
    if (s.overall_risk === "CRITICAL") t.critical++;
    else if (s.overall_risk === "HIGH") t.high++;
    else if (s.overall_risk === "MEDIUM") t.medium++;
    trendMap.set(week, t);
  });
  const risk_trend = Array.from(trendMap.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(-10)
    .map(([date, t]) => ({ date, high_count: t.high, critical_count: t.critical, medium_count: t.medium }));

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
  const currentViolations = Array.from(latestViolationByFile.values())
    .filter(v => v.status === "open" || v.status === "in_review");

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
    scan_count:   scans.length,
    file_count:   totalFiles,
    top_risk_files,
    sla_breach_critical_count,
    sla_breach_high_count,
    sla_breach_files,
  };
}
