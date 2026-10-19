/**
 * Loads an organisation's Trust Score inputs (governanceScore.ts) and saves daily snapshots.
 * Shared by /api/trust-score and the daily pipeline-health cron. Server-only (service-role client).
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { computeGovernanceScore, type GovernanceScore, type ScoreInput } from "./governanceScore";
import { loadShadowAi } from "./shadowAiStore";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

/** How far back the score looks. Older open findings still count once they reappear in a newer scan. */
export const SCORE_WINDOW_DAYS = 90;
const MAX_SCANS = 2000;
const IN_CHUNK = 200;

async function inChunks<T>(ids: string[], fetch: (chunk: string[]) => PromiseLike<{ data: T[] | null }>): Promise<T[]> {
  const out: T[] = [];
  for (let i = 0; i < ids.length; i += IN_CHUNK) out.push(...((await fetch(ids.slice(i, i + IN_CHUNK))).data ?? []));
  return out;
}

export async function loadScoreInput(db: Db, orgId: string, now = new Date()): Promise<ScoreInput> {
  const since = new Date(now.getTime() - SCORE_WINDOW_DAYS * 86400_000).toISOString();
  const [{ data: repoRows }, { data: scanRows }] = await Promise.all([
    db.from("repositories").select("repo_full_name").eq("org_id", orgId).eq("is_active", true) as unknown as Promise<{ data: Array<{ repo_full_name: string }> | null }>,
    db.from("scans").select("id, repo_full_name, pr_number, created_at").eq("org_id", orgId).gte("created_at", since)
      .order("created_at", { ascending: false }).limit(MAX_SCANS) as unknown as Promise<{ data: Array<{ id: string; repo_full_name: string; pr_number: number | null; created_at: string }> | null }>,
  ]);
  const scans = (scanRows ?? []).map(s => ({ id: s.id, repo: s.repo_full_name, pr_number: s.pr_number, created_at: s.created_at }));
  const ids = scans.map(s => s.id);

  const [riskyFiles, attested, violations, secrets, shadow] = await Promise.all([
    inChunks(ids, c => db.from("scan_files").select("scan_id, file_path, risk_score, ai_percentage").eq("org_id", orgId).in("scan_id", c).in("risk_score", ["CRITICAL", "HIGH"]) as unknown as PromiseLike<{ data: ScoreInput["riskyFiles"][number][] | null }>),
    inChunks(ids, c => db.from("attestations").select("scan_id, file_path").eq("org_id", orgId).in("scan_id", c) as unknown as PromiseLike<{ data: ScoreInput["attested"][number][] | null }>),
    inChunks(ids, c => db.from("violations").select("scan_id, file_path, risk_score, status, sla_deadline").eq("org_id", orgId).in("scan_id", c) as unknown as PromiseLike<{ data: ScoreInput["violations"][number][] | null }>),
    inChunks(ids, c => db.from("secret_findings").select("scan_id, severity").eq("org_id", orgId).eq("status", "open").in("scan_id", c) as unknown as PromiseLike<{ data: ScoreInput["secrets"][number][] | null }>),
    loadShadowAi(db, orgId, SCORE_WINDOW_DAYS).then(r => r.summary, () => null),
  ]);

  return {
    now: now.toISOString(),
    repos: (repoRows ?? []).map(r => r.repo_full_name),
    scans, riskyFiles, attested, violations, secrets,
    shadow: shadow ? { policy_configured: shadow.policy_configured, compliance: shadow.compliance, open_violations: shadow.open_violations } : null,
  };
}

export async function computeOrgScore(db: Db, orgId: string, now = new Date()): Promise<GovernanceScore> {
  return computeGovernanceScore(await loadScoreInput(db, orgId, now));
}

/** Upsert today's snapshot (UTC day). Best-effort: false when the history table isn't there yet. */
export async function saveSnapshot(db: Db, orgId: string, score: GovernanceScore): Promise<boolean> {
  const { error } = await db.from("trust_score_history").upsert({
    org_id: orgId,
    day: score.computed_at.slice(0, 10),
    total: score.total,
    dimensions: Object.fromEntries(score.dimensions.map(d => [d.key, Math.round(d.value * 1000) / 1000])),
    repo_scores: score.repos.map(r => ({ repo: r.repo, score: r.score })),
    computed_at: score.computed_at,
  }, { onConflict: "org_id,day" });
  return !error;
}

export interface HistoryPoint { day: string; total: number; dimensions: Record<string, number> }

export async function loadHistory(db: Db, orgId: string, days: number): Promise<HistoryPoint[]> {
  const since = new Date(Date.now() - days * 86400_000).toISOString().slice(0, 10);
  const { data, error } = await db.from("trust_score_history").select("day, total, dimensions").eq("org_id", orgId).gte("day", since).order("day", { ascending: true }) as
    { data: HistoryPoint[] | null; error: unknown };
  return error ? [] : data ?? [];
}
