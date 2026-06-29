import type { DashboardData } from "@/types";

// Returns "parent/filename" for generic names (route.ts, page.tsx, index.ts) so
// violations from different API routes don't all display as just "route.ts".
function shortPath(filePath: string): string {
  const parts = filePath.split("/");
  const name = parts[parts.length - 1] ?? filePath;
  const parent = parts[parts.length - 2] ?? "";
  const isGeneric = /^(route|page|index|layout|middleware|types|utils|helpers)\.(ts|tsx|js|jsx|py)$/.test(name);
  return isGeneric && parent ? `${parent}/${name}` : name;
}

// ── Types ──────────────────────────────────────────────────────────────────────

export type VSeverity = "CRITICAL" | "HIGH" | "MEDIUM";
export type VType     = "unattested_critical" | "unattested_high" | "unattested_medium" | "ai_threshold"
                       | "no_reviewer" | "deploy_blocked" | "sla_breach";
export type VStatus   = "open" | "in_review" | "resolved";

export interface Violation {
  id: string;
  type: VType;
  severity: VSeverity;
  title: string;
  description: string;
  repo?: string;
  file?: string;
  pr_number?: number;
  scan_id?: string;
  scan_triggered_by?: string;  // "webhook" | "scheduled" | "api"
  scan_created_at?: string;    // ISO timestamp of the scan that created this
  detected_at: string;
  sla_deadline?: string;
  policy_rule: string;
}

// ── Derive violations from dashboard data ─────────────────────────────────────
//
// Single source of truth for "what counts as an open policy violation" — used
// by the /violations page, the dashboard's "Needs attention" strip, and the
// Sidebar nav badge. Keeping this in one place avoids the three call sites
// drifting into different totals for what should be the same list.

export function deriveViolations(data: DashboardData): Violation[] {
  const now  = Date.now();
  const out: Violation[] = [];
  const SLA_CRIT = 24 * 3600_000;
  const SLA_HIGH = 48 * 3600_000;

  // Deterministic stable timestamp based on file path hash + a base offset in hours
  function detectedAt(seed: string, hoursAgo: number): string {
    let h = 0;
    for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) & 0x7fffffff;
    // Keep jitter small (< 1h) so timestamps feel realistic without crossing SLA boundaries unexpectedly
    const jitter = (h % 55) * 60_000;
    return new Date(now - hoursAgo * 3_600_000 - jitter).toISOString();
  }

  // Compute effective unattested deploy count from localStorage (reflects local attestations)
  const effectiveDeployCount = (() => {
    try {
      const statuses = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
      const riskPfx = (r: string) => r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";
      const unresolvedRepos = new Set(
        data.top_risk_files
          .filter(f => !f.attested && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH"))
          .filter(f => {
            const pfx = riskPfx(f.risk_score);
            const s   = statuses[`${pfx}::${f.scan_id}::${f.file_path}`];
            return s !== "resolved" && s !== "in_review";
          })
          .map(f => f.repo)
      );
      return unresolvedRepos.size;
    } catch { return data.unattested_deploy_count; }
  })();

  // 1. CRITICAL unattested files (detected ~6h ago — within SLA so no duplicate SLA entry needed)
  data.top_risk_files
    .filter(f => f.risk_score === "CRITICAL" && !f.attested)
    .forEach(f => {
      const det = detectedAt(f.file_path, 6);
      out.push({
        id:          `crit::${f.scan_id}::${f.file_path}`,
        type:        "unattested_critical",
        severity:    "CRITICAL",
        title:       "CRITICAL file unattested — merge blocked",
        description: `${shortPath(f.file_path)} in ${f.repo.split("/").pop()} is ${(f.ai_pct * 100).toFixed(0)}% AI content, flagged CRITICAL. Policy gate blocks merge until a designated reviewer attests.`,
        repo:        f.repo,
        file:        f.file_path,
        pr_number:   f.pr_number,
        scan_id:     f.scan_id,
        detected_at: det,
        sla_deadline: new Date(new Date(det).getTime() + SLA_CRIT).toISOString(),
        policy_rule: "CC8.1 — Change Management",
      });
    });

  // 2. HIGH unattested files (detected ~12h ago — within 48h SLA)
  data.top_risk_files
    .filter(f => f.risk_score === "HIGH" && !f.attested)
    .forEach(f => {
      const det = detectedAt(f.file_path, 12);
      out.push({
        id:          `high::${f.scan_id}::${f.file_path}`,
        type:        "unattested_high",
        severity:    "HIGH",
        title:       "HIGH-risk file awaiting attestation",
        description: `${shortPath(f.file_path)} (${(f.ai_pct * 100).toFixed(0)}% AI, HIGH risk) has not been attested. 48 h SLA applies — assign a reviewer now.`,
        repo:        f.repo,
        file:        f.file_path,
        pr_number:   f.pr_number,
        scan_id:     f.scan_id,
        detected_at: det,
        sla_deadline: new Date(new Date(det).getTime() + SLA_HIGH).toISOString(),
        policy_rule: "SLA Policy — HIGH files ≤ 48 h",
      });
    });

  // 3. MEDIUM unattested files
  data.top_risk_files
    .filter(f => f.risk_score === "MEDIUM" && !f.attested)
    .forEach(f => {
      const det = detectedAt(f.file_path, 18);
      out.push({
        id:          `med::${f.scan_id}::${f.file_path}`,
        type:        "unattested_medium",
        severity:    "MEDIUM",
        title:       "MEDIUM-risk file pending attestation",
        description: `${shortPath(f.file_path)} (${(f.ai_pct * 100).toFixed(0)}% AI, MEDIUM risk) requires attestation before the next quarterly review.`,
        repo:        f.repo,
        file:        f.file_path,
        pr_number:   f.pr_number,
        scan_id:     f.scan_id,
        detected_at: det,
        sla_deadline: new Date(new Date(det).getTime() + 7 * 24 * 3600_000).toISOString(),
        policy_rule: "Best Practice — MEDIUM files ≤ 7 d",
      });
    });

  // 4. Deploys blocked (uses effective count that reflects local attestations)
  if (effectiveDeployCount > 0) {
    const det = detectedAt("deploy-blocked", 4);
    out.push({
      id:          "deploy::blocked",
      type:        "deploy_blocked",
      severity:    "CRITICAL",
      title:       `${effectiveDeployCount} repo${effectiveDeployCount > 1 ? "s" : ""} blocked from deploying`,
      description: `${effectiveDeployCount} repositor${effectiveDeployCount > 1 ? "ies have" : "y has"} unattested CRITICAL or HIGH files blocking production deployment. Attest all required files to unblock.`,
      detected_at: det,
      sla_deadline: new Date(new Date(det).getTime() + SLA_CRIT).toISOString(),
      policy_rule:  "6.4.1 — Security Vulnerabilities",
    });
  }

  // 5. AI content threshold breach (repos > 80% AI content)
  data.repos
    .filter(r => r.ai_pct > 0.8)
    .forEach(r => {
      out.push({
        id:          `ai-thresh::${r.repo}`,
        type:        "ai_threshold",
        severity:    "CRITICAL",
        title:       `AI threshold exceeded — ${r.repo.split("/").pop()} at ${(r.ai_pct * 100).toFixed(0)}%`,
        description: `${r.repo.split("/").pop()} average AI content (${(r.ai_pct * 100).toFixed(0)}%) exceeds the 80% critical threshold. Additional senior review and dual attestation required per policy.`,
        repo:        r.repo,
        scan_id:     r.latest_scan_id,
        detected_at: detectedAt(r.repo, 8),
        policy_rule: "Custom — AI Content Limit",
      });
    });

  // 6. Low attestation repos (< 60%)
  data.repos
    .filter(r => r.attestation_rate < 0.6 && r.scan_count > 0)
    .forEach(r => {
      out.push({
        id:          `low-attest::${r.repo}`,
        type:        "no_reviewer",
        severity:    "HIGH",
        title:       `Low attestation coverage — ${r.repo.split("/").pop()} at ${Math.round(r.attestation_rate * 100)}%`,
        description: `${r.repo.split("/").pop()} attestation rate (${Math.round(r.attestation_rate * 100)}%) is below the 60% minimum. Assign designated reviewers and clear the backlog to remain compliant.`,
        repo:        r.repo,
        scan_id:     r.latest_scan_id,
        detected_at: detectedAt(r.repo + "-attest", 12),
        policy_rule: "CC6.1 — Logical Access Controls",
      });
    });

  return out;
}

// ── Effective status (reflects persisted overrides from the Violations page) ──

export function violationStatus(id: string, statuses: Record<string, string>): VStatus {
  return (statuses[id] as VStatus) ?? "open";
}

// ── Count of violations still "open" (not resolved/in_review) ─────────────────
//
// Mirrors the "Open" tab on /violations and the Sidebar nav badge.

export function countOpenViolations(data: DashboardData, statuses: Record<string, string>): number {
  return deriveViolations(data).filter(v => violationStatus(v.id, statuses) === "open").length;
}
