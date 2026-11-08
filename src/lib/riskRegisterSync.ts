/**
 * Risk Register: record derived risks in the `risk_register` table (used by POST /api/risk-register/sync and by
 * GET /api/risk-register, which syncs as it reads).
 *
 * Writes only computed metadata, keyed by external_id, and never a workflow column (treatment, owner_email,
 * due_date, mitigation, notes, residual_*): those are set by people and must survive re-derivation untouched.
 *
 * Existing rows are looked up and updated, new ones inserted (an ON CONFLICT upsert cannot use the table's partial
 * unique index). Status follows the data both ways: an auto-derived risk that stops being derived (the files were
 * attested or fixed) is closed, and one derived again after a sync closed it is reopened. A risk a PERSON closed
 * stays closed (a sync close records no updated_by; a person's change records theirs).
 */
import type { createServiceClient } from "@/lib/supabase";
import { writeAuditLog } from "@/lib/audit";
import { CAPS } from "@/lib/limits";

type Db = ReturnType<typeof createServiceClient>;

export interface DerivedRiskInput {
  id:            string;   // becomes external_id
  title:         string;
  description?:  string;
  category:      string;
  likelihood:    number;
  impact:        number;
  repo?:         string;
  related_cve?:  string;
  related_cwe?:  string;
  related_link?: string;
}

const CATEGORIES = new Set(["ai-code", "supply-chain", "secrets", "compliance", "access", "infrastructure"]);
export const MAX_RISKS = CAPS.riskRegisterSync.value;
const CHUNK = 200;
const META = ["title", "description", "category", "likelihood", "impact", "repo", "related_cve", "related_cwe", "related_link"] as const;

type Meta = Record<(typeof META)[number], string | number | null>;
interface ExistingRow extends Meta { external_id: string; auto_derived: boolean; status: string; updated_by: string | null }

const str = (v: unknown, max: number) => (typeof v === "string" && v.trim() ? v.slice(0, max) : null);
const score = (v: unknown) => (Number.isInteger(v) && (v as number) >= 1 && (v as number) <= 5 ? (v as number) : null);

/** A valid risk's stored metadata, or null when it can't be stored (the table would reject it). */
function toMeta(r: DerivedRiskInput): Meta | null {
  const title = str(r?.title, 500), likelihood = score(r?.likelihood), impact = score(r?.impact);
  if (!title || likelihood == null || impact == null || !CATEGORIES.has(r?.category)) return null;
  return {
    title, description: str(r.description, 4000), category: r.category, likelihood, impact,
    repo: str(r.repo, 300), related_cve: str(r.related_cve, 200), related_cwe: str(r.related_cwe, 300), related_link: str(r.related_link, 500),
  };
}

export interface SyncResult { synced: number; inserted: number; updated: number; reopened: number; closed: number; skipped: number }

/** Throws on a database error before anything is half-written by the insert; callers turn that into a user message. */
export async function syncDerivedRisks(db: Db, org_id: string, risks: readonly DerivedRiskInput[]): Promise<SyncResult> {
  // One entry per id (the last one wins) -- a repeated id used to make the whole write fail.
  const batch = new Map<string, Meta>();
  let skipped = 0;
  for (const r of risks) {
    const id = str(r?.id, 200);
    const meta = id ? toMeta(r) : null;
    if (!id || !meta) { skipped++; continue; }
    batch.set(id, meta);
  }
  const ids = [...batch.keys()];
  const now = new Date().toISOString();

  const existing = new Map<string, ExistingRow>();
  for (let i = 0; i < ids.length; i += CHUNK) {
    const { data, error } = await db.from("risk_register")
      .select(`external_id, auto_derived, status, updated_by, ${META.join(", ")}`)
      .eq("org_id", org_id)
      .in("external_id", ids.slice(i, i + CHUNK)) as { data: ExistingRow[] | null; error: unknown };
    if (error) throw error;
    for (const row of data ?? []) existing.set(row.external_id, row);
  }

  // New risks: one insert. Changed metadata: one update per changed row. A risk this sync closed earlier: reopen.
  const newIds = ids.filter(id => !existing.has(id));
  if (newIds.length > 0) {
    const { error } = await db.from("risk_register").insert(newIds.map(id => ({ ...batch.get(id)!, external_id: id, auto_derived: true, org_id })));
    if (error) throw error;
  }
  const reopened: string[] = [];
  let updated = 0;
  for (const id of ids) {
    const row = existing.get(id);
    if (!row || !row.auto_derived) continue;     // a manual risk that happens to share the id is never touched
    const meta = batch.get(id)!;
    const patch: Record<string, unknown> = {};
    for (const k of META) if ((row[k] ?? null) !== meta[k]) patch[k] = meta[k];
    if (row.status === "closed" && row.updated_by == null) { patch.status = "open"; reopened.push(id); }
    if (Object.keys(patch).length === 0) continue;
    const { error } = await db.from("risk_register").update({ ...patch, updated_at: now }).eq("org_id", org_id).eq("external_id", id);
    if (!error) updated++;
  }

  // Close previously-derived risks missing from this batch. updated_by is cleared so a later sync knows the system
  // (not a person) closed it and may reopen it.
  const currentIdSet = new Set(ids);
  const { data: openDerived } = await db
    .from("risk_register")
    .select("external_id")
    .eq("org_id", org_id)
    .eq("auto_derived", true)
    .neq("status", "closed")
    .not("external_id", "is", null) as { data: { external_id: string }[] | null };
  const staleIds = (openDerived ?? []).map(r => r.external_id).filter(id => !currentIdSet.has(id));

  let closed = 0;
  for (let i = 0; i < staleIds.length; i += CHUNK) {
    const { data: closedRows, error: closeErr } = await db
      .from("risk_register")
      .update({ status: "closed", updated_at: now, updated_by: null })
      .eq("org_id", org_id)
      .in("external_id", staleIds.slice(i, i + CHUNK))
      .select("id");
    if (!closeErr) closed += closedRows?.length ?? 0;
  }

  if (closed > 0 || reopened.length > 0) {
    await writeAuditLog(db, {
      org_id, event_type: "risk_updated", actor_id: null, actor_email: "system", resource_type: "risk_register",
      payload: {
        action: "auto_synced", reason: "follows live scan data",
        closed, closed_ids: staleIds.slice(0, 20), reopened: reopened.length, reopened_ids: reopened.slice(0, 20),
      },
    });
  }

  return { synced: ids.length, inserted: newIds.length, updated, reopened: reopened.length, closed, skipped };
}
