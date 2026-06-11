/**
 * Advanced Analytics API — Trend, Velocity & Prediction data
 * GET /api/analytics/trends?days=90&repo=...
 *
 * Returns:
 *   - risk_trend:    weekly risk level counts (existing)
 *   - ai_trend:      weekly avg AI % per repo
 *   - velocity:      attestation speed (hours from scan to attest)
 *   - sla_breach_rate: % of violations that breach SLA
 *   - top_indicators: most common risk indicator types
 *   - prediction:    projected risk trajectory (linear regression)
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { cached, cacheKeys, TTL } from "@/lib/cache";

// Simple linear regression for trend prediction
function linearRegression(points: number[]): { slope: number; intercept: number; next: number } {
  const n = points.length;
  if (n < 2) return { slope: 0, intercept: points[0] ?? 0, next: points[0] ?? 0 };
  const xMean = (n - 1) / 2;
  const yMean = points.reduce((a, b) => a + b, 0) / n;
  let num = 0, den = 0;
  points.forEach((y, x) => { num += (x - xMean) * (y - yMean); den += (x - xMean) ** 2; });
  const slope     = den === 0 ? 0 : num / den;
  const intercept = yMean - slope * xMean;
  const next      = slope * n + intercept;
  return { slope, intercept, next: Math.max(0, next) };
}

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url  = new URL(req.url);
  const days = parseInt(url.searchParams.get("days") ?? "90");
  const repo = url.searchParams.get("repo");

  const cacheKey = `analytics:${org_id}:${days}:${repo ?? "all"}`;

  const data = await cached(cacheKey, TTL.DASHBOARD, async () => {
    const db    = createServiceClient();
    const since = new Date(Date.now() - days * 86400_000).toISOString();

    // Build base query
    let scansQuery = db
      .from("scans")
      .select("id, repo_full_name, overall_risk, total_ai_percentage, created_at")
      .eq("org_id", org_id)
      .gte("created_at", since)
      .order("created_at", { ascending: true });

    if (repo) scansQuery = scansQuery.ilike("repo_full_name", `%${repo}%`) as typeof scansQuery;

    const [rScans, rAttests, rViolations, rFiles] = await Promise.all([
      scansQuery,
      db.from("attestations").select("scan_id, created_at").eq("org_id", org_id).gte("created_at", since),
      db.from("violations").select("id, risk_score, status, sla_deadline, created_at, resolved_at").eq("org_id", org_id).gte("created_at", since),
      db.from("scan_files").select("risk_indicators").eq("org_id", org_id).gte("created_at", since).limit(2000),
    ]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const scans     = rScans.data     as Array<{ id:string; repo_full_name:string; overall_risk:string; total_ai_percentage:number; created_at:string }> | null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const attests   = rAttests.data   as Array<{ scan_id:string; created_at:string }> | null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const violations= rViolations.data as Array<{ id:string; risk_score:string; status:string; sla_deadline:string|null; created_at:string; resolved_at:string|null }> | null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const files     = rFiles.data     as Array<{ risk_indicators:string[] }> | null;

    // ── Weekly risk trend ─────────────────────────────────────────────────────
    const weekMap: Record<string, { high:number; critical:number; medium:number; low:number; total:number; ai_sum:number }> = {};
    (scans ?? []).forEach(s => {
      const week = s.created_at.slice(0, 10); // approximate by day (group by week in display)
      if (!weekMap[week]) weekMap[week] = { high:0, critical:0, medium:0, low:0, total:0, ai_sum:0 };
      weekMap[week].total++;
      weekMap[week].ai_sum += s.total_ai_percentage;
      if (s.overall_risk === "CRITICAL") weekMap[week].critical++;
      else if (s.overall_risk === "HIGH") weekMap[week].high++;
      else if (s.overall_risk === "MEDIUM") weekMap[week].medium++;
      else weekMap[week].low++;
    });

    const risk_trend = Object.entries(weekMap)
      .sort(([a],[b]) => a.localeCompare(b))
      .slice(-14) // last 14 data points
      .map(([date, v]) => ({
        date,
        high_count:     v.high,
        critical_count: v.critical,
        medium_count:   v.medium,
        low_count:      v.low,
        scan_count:     v.total,
        avg_ai_pct:     v.total > 0 ? v.ai_sum / v.total : 0,
      }));

    // ── Attestation velocity (median hours scan → first attestation) ──────────
    const attestScanMap: Record<string, string> = {};
    (attests ?? []).forEach(a => {
      if (!attestScanMap[a.scan_id]) attestScanMap[a.scan_id] = a.created_at;
    });

    const scanTimeMap: Record<string, string> = {};
    (scans ?? []).forEach(s => { scanTimeMap[s.id] = s.created_at; });

    const velocities = Object.entries(attestScanMap)
      .filter(([scanId]) => scanTimeMap[scanId])
      .map(([scanId, attestTime]) => {
        const scanTime = new Date(scanTimeMap[scanId]).getTime();
        const attTime  = new Date(attestTime).getTime();
        return (attTime - scanTime) / 3600_000; // hours
      })
      .filter(h => h >= 0 && h < 24 * 30) // exclude outliers
      .sort((a, b) => a - b);

    const medianVelocity = velocities.length > 0
      ? velocities[Math.floor(velocities.length / 2)]
      : null;

    // ── SLA breach rate ───────────────────────────────────────────────────────
    const v = violations ?? [];
    const breachedCount = v.filter(viol => {
      if (!viol.sla_deadline) return false;
      const deadline = new Date(viol.sla_deadline).getTime();
      const resolvedAt = viol.resolved_at ? new Date(viol.resolved_at).getTime() : Date.now();
      return resolvedAt > deadline;
    }).length;
    const sla_breach_rate = v.length > 0 ? (breachedCount / v.length) * 100 : 0;

    // ── Top risk indicators ───────────────────────────────────────────────────
    const indicatorCounts: Record<string, number> = {};
    (files ?? []).forEach(f => {
      (f.risk_indicators ?? []).forEach(ind => {
        indicatorCounts[ind] = (indicatorCounts[ind] ?? 0) + 1;
      });
    });
    const top_indicators = Object.entries(indicatorCounts)
      .sort(([,a],[,b]) => b - a)
      .slice(0, 10)
      .map(([indicator, count]) => ({ indicator, count }));

    // ── Risk trajectory prediction (linear regression on critical counts) ─────
    const criticalPoints = risk_trend.map(t => t.critical_count);
    const regression     = linearRegression(criticalPoints);
    const prediction = {
      direction:    regression.slope > 0.1 ? "worsening" : regression.slope < -0.1 ? "improving" : "stable",
      slope:        Math.round(regression.slope * 100) / 100,
      next_period:  Math.round(Math.max(0, regression.next)),
      confidence:   criticalPoints.length >= 4 ? "medium" : "low",
    };

    // ── Per-repo AI trend ─────────────────────────────────────────────────────
    const repoAI: Record<string, number[]> = {};
    (scans ?? []).forEach(s => {
      if (!repoAI[s.repo_full_name]) repoAI[s.repo_full_name] = [];
      repoAI[s.repo_full_name].push(s.total_ai_percentage);
    });
    const ai_by_repo = Object.entries(repoAI)
      .map(([repo_name, pcts]) => ({
        repo:    repo_name,
        avg_ai:  pcts.reduce((a,b) => a+b, 0) / pcts.length,
        trend:   linearRegression(pcts).slope,
        samples: pcts.length,
      }))
      .sort((a,b) => b.avg_ai - a.avg_ai)
      .slice(0, 10);

    return {
      period_days:       days,
      total_scans:       (scans ?? []).length,
      risk_trend,
      ai_by_repo,
      attestation_velocity_hours: medianVelocity,
      sla_breach_rate:   Math.round(sla_breach_rate * 10) / 10,
      top_indicators,
      prediction,
      generated_at:      new Date().toISOString(),
    };
  });

  return NextResponse.json(data, {
    headers: { "Cache-Control":`s-maxage=${TTL.DASHBOARD}` },
  });
}
