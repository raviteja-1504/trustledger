/**
 * Server-side reads of finding triage decisions (see findingLifecycle.ts and the finding_triage migration).
 * Best-effort by design: any error -- including the table not existing before the migration is applied --
 * reads as "no decisions", so scanning and gating behave exactly as they did before triage existed.
 */
import type { createServiceClient } from "./supabase";
import type { TriageDecision, TriageStatus } from "./findingLifecycle";

type Db = ReturnType<typeof createServiceClient>;

export async function loadTriage(db: Db, orgId: string, repoFullName: string): Promise<Map<string, TriageDecision>> {
  const out = new Map<string, TriageDecision>();
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data, error } = await (db.from("finding_triage" as any) as any)
      .select("fingerprint, status, reason, expires_at, set_by_email, set_at")
      .eq("org_id", orgId)
      .eq("repo_full_name", repoFullName);
    if (error || !Array.isArray(data)) return out;
    for (const r of data as Array<{ fingerprint: string; status: TriageStatus; reason: string | null; expires_at: string | null; set_by_email: string | null; set_at: string }>) {
      out.set(r.fingerprint, { status: r.status, reason: r.reason, expires_at: r.expires_at, set_by_email: r.set_by_email, set_at: r.set_at });
    }
  } catch { /* best-effort */ }
  return out;
}
