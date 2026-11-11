/**
 * Plan limits, enforced on the server (the numbers live in lib/limits.ts, shared with what the UI shows).
 *
 * What is gated: a NEW scan (webhook, before any work is queued), connecting a repository, inviting a member. What is never
 * gated: reading scans and attesting files. Every check fails OPEN on a database error: a hiccup must not stop a paying
 * customer's scans, and the worst case is one scan over the limit.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { planLimits, type PlanLimits } from "./limits";
import { UPGRADE_LINE } from "./planGate-text";

type Db = SupabaseClient;

export { UPGRADE_LINE };

/** First instant of the current calendar month, UTC. */
export function monthStartIso(now = new Date()): string {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString();
}

export async function loadPlan(db: Db, orgId: string): Promise<{ plan: string; limits: PlanLimits }> {
  const { data } = await db.from("organizations").select("plan").eq("id", orgId).maybeSingle() as { data: { plan?: string } | null };
  const plan = data?.plan ?? "trial";
  return { plan, limits: planLimits(plan) };
}

const count = async (q: PromiseLike<{ count: number | null; error?: unknown }>) => { const r = await q; return r.error ? null : (r.count ?? 0); };

export interface ScanVerdict { allowed: boolean; reason?: "scans" | "repos"; title?: string; summary?: string }

/** May this organisation start another scan, for this repository? */
export async function checkScanAllowed(db: Db, orgId: string, repoFullName: string): Promise<ScanVerdict> {
  try {
    const { limits } = await loadPlan(db, orgId);

    if (limits.scans >= 0) {
      const used = await count(db.from("scans").select("id", { count: "exact", head: true }).eq("org_id", orgId).gte("created_at", monthStartIso()));
      if (used !== null && used >= limits.scans) {
        return {
          allowed: false, reason: "scans",
          title: `Plan limit reached: ${used} of ${limits.scans} scans used this month`,
          summary: `TrustLedger did not scan this pull request: your plan includes ${limits.scans} scans a month and they are all used. Existing scans can still be viewed and attested. The count resets on the 1st. ${UPGRADE_LINE}`,
        };
      }
    }

    if (limits.repos >= 0) {
      const { data: known } = await db.from("repositories").select("id").eq("org_id", orgId).eq("repo_full_name", repoFullName).maybeSingle() as { data: unknown };
      if (!known) {
        const used = await count(db.from("repositories").select("id", { count: "exact", head: true }).eq("org_id", orgId).eq("is_active", true));
        if (used !== null && used >= limits.repos) {
          return {
            allowed: false, reason: "repos",
            title: `Plan limit reached: ${used} of ${limits.repos} repositor${limits.repos === 1 ? "y" : "ies"} in use`,
            summary: `TrustLedger did not scan this pull request: your plan covers ${limits.repos} repositor${limits.repos === 1 ? "y" : "ies"} and this is not one of them. ${UPGRADE_LINE}`,
          };
        }
      }
    }
    return { allowed: true };
  } catch {
    return { allowed: true };
  }
}

/** How many more repositories this organisation may connect: null = unlimited; undefined-safe on errors (unlimited). */
export async function repoSlotsLeft(db: Db, orgId: string): Promise<{ left: number | null; limit: number }> {
  try {
    const { limits } = await loadPlan(db, orgId);
    if (limits.repos < 0) return { left: null, limit: -1 };
    const used = await count(db.from("repositories").select("id", { count: "exact", head: true }).eq("org_id", orgId).eq("is_active", true));
    return { left: used === null ? null : Math.max(0, limits.repos - used), limit: limits.repos };
  } catch { return { left: null, limit: -1 }; }
}

/** May another member be added? */
export async function checkMemberSlot(db: Db, orgId: string): Promise<{ allowed: boolean; message?: string }> {
  try {
    const { limits } = await loadPlan(db, orgId);
    if (limits.members < 0) return { allowed: true };
    const used = await count(db.from("org_members").select("id", { count: "exact", head: true }).eq("org_id", orgId));
    if (used !== null && used >= limits.members) {
      return { allowed: false, message: `Your plan includes ${limits.members} team members and they are all in use. ${UPGRADE_LINE}` };
    }
    return { allowed: true };
  } catch { return { allowed: true }; }
}

/** The "x of y scans used" figures for the dashboard banner; null when the plan has no scan limit. */
export async function scanUsage(db: Db, orgId: string): Promise<{ plan: string; used: number; limit: number } | null> {
  try {
    const { plan, limits } = await loadPlan(db, orgId);
    if (limits.scans < 0) return null;
    const used = await count(db.from("scans").select("id", { count: "exact", head: true }).eq("org_id", orgId).gte("created_at", monthStartIso()));
    return used === null ? null : { plan, used, limit: limits.scans };
  } catch { return null; }
}
