/**
 * The merge gate: which unattested files block a PR from merging. The org chooses in Settings
 * (organizations.block_on_critical / block_on_high); every place that decides "blocked" -- the GitHub
 * check, its re-sync after a sign-off, the PR's policy alert, the Trust Record's merge_gate -- asks here,
 * so they can't disagree. Files the gate doesn't block still need review: their violations stay open
 * and listed, they just don't hold the merge.
 *
 * Fails closed: a setting that is missing (an org row from before the columns, a read error) blocks.
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = any;

export type BlockingRisk = "CRITICAL" | "HIGH";

export interface GateSettings { block_on_critical: boolean; block_on_high: boolean }

export const DEFAULT_GATE: GateSettings = { block_on_critical: true, block_on_high: true };

/** The risk levels whose unattested files block the merge. */
export function blockingRisks(s: GateSettings): BlockingRisk[] {
  return [...(s.block_on_critical ? ["CRITICAL" as const] : []), ...(s.block_on_high ? ["HIGH" as const] : [])];
}

/** Whether a file of this risk blocks the merge while unattested. */
export function blocksMerge(risk: string | null | undefined, s: GateSettings): boolean {
  return (blockingRisks(s) as string[]).includes(String(risk ?? "").toUpperCase());
}

/** The org's gate settings; anything unreadable counts as "blocks". */
export async function loadGate(db: Db, orgId: string | null | undefined): Promise<GateSettings> {
  if (!orgId) return { ...DEFAULT_GATE };
  try {
    const { data } = await db.from("organizations").select("block_on_critical, block_on_high").eq("id", orgId).maybeSingle();
    return {
      block_on_critical: data?.block_on_critical !== false,
      block_on_high: data?.block_on_high !== false,
    };
  } catch {
    return { ...DEFAULT_GATE };
  }
}

/** Open (unresolved) violations of `scanId` that block its merge. */
export async function countOpenBlocking(db: Db, scanId: string, gate: GateSettings, orgId: string): Promise<number> {
  const risks = blockingRisks(gate);
  if (risks.length === 0) return 0;
  const { count } = await db.from("violations").select("id", { count: "exact", head: true })
    .eq("org_id", orgId).eq("scan_id", scanId).neq("status", "resolved").in("risk_score", risks);
  return count ?? 0;
}
