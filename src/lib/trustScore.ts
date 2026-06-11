import type { DashboardData } from "@/types";

// ── Shared patching ───────────────────────────────────────────────────────────
// Apply locally-stored violation statuses on top of raw API data so every
// page that computes trust scores reflects the same in-session attestations.

function riskPrefix(r: string): string {
  return r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";
}

export function patchDataWithAttestations(data: DashboardData, injectedStatuses?: Record<string, string>): DashboardData {
  let statuses: Record<string, string> = injectedStatuses ?? {};
  if (!injectedStatuses) {
    try {
      statuses = JSON.parse(
        (typeof window !== "undefined" ? localStorage.getItem("tl_violation_statuses") : null) ?? "{}"
      ) as Record<string, string>;
    } catch { /* keep empty */ }
  }

  if (Object.keys(statuses).length === 0) return data;

  const patchedTopRisk = data.top_risk_files.map(f => {
    if (f.attested) return f;
    const key = `${riskPrefix(f.risk_score)}::${f.scan_id}::${f.file_path}`;
    const handled = statuses[key] === "resolved";
    return handled ? { ...f, attested: true } : f;
  });

  const patchedRepos = data.repos.map(repo => {
    const repoFiles = patchedTopRisk.filter(
      f => f.repo === repo.repo && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH")
    );
    if (repoFiles.length === 0) return repo;
    const nowAttested = repoFiles.filter(f => f.attested).length;
    const blended = Math.max(repo.attestation_rate, nowAttested / repoFiles.length);
    return blended === repo.attestation_rate ? repo : { ...repo, attestation_rate: blended };
  });

  const critHighAll  = patchedTopRisk.filter(f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH");
  const patchedRate  = critHighAll.length > 0
    ? critHighAll.filter(f => f.attested).length / critHighAll.length
    : data.attestation_rate;

  return {
    ...data,
    attestation_rate: Math.max(data.attestation_rate, patchedRate),
    top_risk_files:   patchedTopRisk,
    repos:            patchedRepos,
  };
}

export interface ScoreDimension {
  key:    string;
  label:  string;
  weight: number;
  value:  number;
  score:  number;
  grade:  "A" | "B" | "C" | "D" | "F";
  trend:  "up" | "down" | "flat";
  detail: string;
}

export function gradeFromValue(v: number): "A" | "B" | "C" | "D" | "F" {
  if (v >= 0.90) return "A";
  if (v >= 0.75) return "B";
  if (v >= 0.60) return "C";
  if (v >= 0.45) return "D";
  return "F";
}

export function computeTrustScore(data: DashboardData): { total: number; dimensions: ScoreDimension[] } {
  const attRate = data.attestation_rate ?? 0;
  const aiPct   = data.overall_ai_pct   ?? 0;
  const repos   = data.repos            ?? [];
  const topRisk = data.top_risk_files   ?? [];

  // D1: Attestation Coverage
  const d1 = attRate;

  // D2: Policy Compliance — full credit at ≤40% AI, zero at ≥65% AI.
  // Tighter than 80% cap: exceeding the threshold by 25pp means total non-compliance.
  const D2_ZERO = 0.65;
  const d2 = aiPct <= 0.40 ? 1.0 : aiPct < D2_ZERO ? (D2_ZERO - aiPct) / (D2_ZERO - 0.40) : 0;

  // D3: Critical/High risk resolution
  const critFiles    = topRisk.filter(f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH");
  const critAttested = critFiles.filter(f => f.attested).length;
  const d3 = critFiles.length === 0 ? 1.0 : critAttested / critFiles.length;

  // D4: Cross-repo consistency — three signals combined
  // (a) attestation spread: high stddev = uneven governance
  // (b) neglect floor: any repo < 40% att is a governance gap regardless of average
  // (c) AI% alignment: wildly different AI% across repos signals patchwork tooling
  let d4: number;
  let d4LaggingRepos: string[] = [];
  const statsArr = (a: number[]) => {
    const m = a.reduce((s, v) => s + v, 0) / a.length;
    return { mean: m, std: Math.sqrt(a.reduce((s, v) => s + (v - m) ** 2, 0) / a.length) };
  };
  if (repos.length > 0) {
    const attRates = repos.map(r => r.attestation_rate);
    const aiPcts   = repos.map(r => r.ai_pct);
    const attStats = statsArr(attRates);
    const aiStats  = statsArr(aiPcts);
    const spreadScore  = Math.max(0, 1 - attStats.std * 2);
    const minAtt       = Math.min(...attRates);
    const neglectScore = minAtt < 0.40 ? minAtt / 0.40 : 1.0;
    const aiScore      = Math.max(0, 1 - aiStats.std * 1.5);
    d4 = spreadScore * 0.50 + neglectScore * 0.35 + aiScore * 0.15;
    d4LaggingRepos = repos
      .filter(r => r.attestation_rate < 0.60)
      .sort((a, b) => a.attestation_rate - b.attestation_rate)
      .map(r => r.repo.split("/").pop() ?? r.repo);
  } else {
    d4 = 0.5;
  }

  // D5: Scan freshness
  const now = Date.now();
  const freshnessScores = repos.map(r => {
    const ms = new Date(r.last_scan).getTime();
    if (isNaN(ms)) return 0.1;
    const age = (now - ms) / (1000 * 3600);
    return age <= 24 ? 1.0 : age <= 72 ? 0.7 : age <= 168 ? 0.4 : 0.1;
  });
  const d5 = freshnessScores.length > 0
    ? freshnessScores.reduce((a, b) => a + b, 0) / freshnessScores.length
    : 0.5;

  const WEIGHTS = [0.30, 0.25, 0.20, 0.15, 0.10];
  const values  = [d1, d2, d3, d4, d5];
  const total   = Math.round(values.reduce((s, v, i) => s + v * WEIGHTS[i], 0) * 1000);

  const dimensions: ScoreDimension[] = [
    {
      key: "attestation", label: "Attestation Coverage",
      weight: WEIGHTS[0], value: d1,
      score: Math.round(d1 * WEIGHTS[0] * 1000),
      grade: gradeFromValue(d1), trend: d1 > 0.8 ? "up" : d1 < 0.6 ? "down" : "flat",
      detail: `${Math.round(d1 * 100)}% of AI-generated code has been reviewed and attested by a human`,
    },
    {
      key: "policy", label: "Policy Compliance",
      weight: WEIGHTS[1], value: d2,
      score: Math.round(d2 * WEIGHTS[1] * 1000),
      grade: gradeFromValue(d2), trend: d2 > 0.7 ? "up" : "down",
      detail: aiPct <= 0.40
        ? `${Math.round(aiPct * 100)}% overall AI content — within the 40% governance threshold`
        : aiPct >= D2_ZERO
          ? `${Math.round(aiPct * 100)}% overall AI content — ${Math.round((aiPct - 0.40) * 100)}pp over the 40% limit; score zeroed at ≥${Math.round(D2_ZERO * 100)}%`
          : `${Math.round(aiPct * 100)}% overall AI content — ${Math.round((aiPct - 0.40) * 100)}pp over the 40% limit; score zeroes at ${Math.round(D2_ZERO * 100)}% AI`,
    },
    {
      key: "critical", label: "Critical Risk Resolution",
      weight: WEIGHTS[2], value: d3,
      score: Math.round(d3 * WEIGHTS[2] * 1000),
      grade: gradeFromValue(d3), trend: d3 > 0.7 ? "up" : "down",
      detail: `${critAttested}/${critFiles.length} critical/high-risk AI files have been attested`,
    },
    {
      key: "consistency", label: "Cross-Repo Consistency",
      weight: WEIGHTS[3], value: d4,
      score: Math.round(d4 * WEIGHTS[3] * 1000),
      grade: gradeFromValue(d4), trend: "flat",
      detail: d4LaggingRepos.length > 0
        ? `${d4LaggingRepos.join(", ")} below 60% attestation — neglected repos drag the consistency score`
        : repos.length > 0
          ? `All ${repos.length} repos above 60% attestation — governance applied uniformly across the org`
          : "No repositories found",
    },
    {
      key: "freshness", label: "Scan Freshness",
      weight: WEIGHTS[4], value: d5,
      score: Math.round(d5 * WEIGHTS[4] * 1000),
      grade: gradeFromValue(d5), trend: d5 > 0.7 ? "up" : "down",
      detail: "Proportion of repositories scanned within the last 24 hours",
    },
  ];

  return { total, dimensions };
}

export function scoreColor(s: number): { text: string; bg: string; ring: string; label: string } {
  if (s >= 850) return { text:"#15803d", bg:"#f0fdf4", ring:"#86efac", label:"Excellent" };
  if (s >= 700) return { text:"#16a34a", bg:"#f0fdf4", ring:"#4ade80", label:"Good" };
  if (s >= 550) return { text:"#d97706", bg:"#fffbeb", ring:"#fcd34d", label:"Fair" };
  if (s >= 400) return { text:"#ea580c", bg:"#fff7ed", ring:"#fdba74", label:"Poor" };
  return           { text:"#dc2626", bg:"#fff1f2", ring:"#fca5a5", label:"Critical" };
}
