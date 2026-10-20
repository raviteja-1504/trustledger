/**
 * Risk Register — sync derived risks into the database.
 *
 * The Risk Register page re-derives its "auto" risks from live scan data
 * on every load (unattested CRITICAL/HIGH files, risky repos, etc. — see
 * lib/riskRegister.ts deriveRisks()). This endpoint records that computed
 * metadata in the real `risk_register` table, keyed by external_id, WITHOUT
 * touching workflow columns (treatment, owner_email, due_date, mitigation,
 * notes, residual_*) — those are only ever human-set, via
 * PATCH /api/risk-register/state, and must survive re-derivation untouched.
 *
 * It used to upsert ON CONFLICT (org_id, external_id), but the only unique
 * index on those columns is partial (WHERE external_id IS NOT NULL), which
 * Postgres can't use for that conflict target -- so every sync failed, no
 * derived risk ever got a row, and changing a derived risk's status or owner
 * failed too (PATCH found no row). Existing rows are now looked up and
 * updated, new ones inserted.
 *
 * Status follows the data both ways: an auto-derived risk that stops being
 * derived (e.g. a secret was removed, so DR-SECRETS-{repo} no longer
 * appears) is closed, and one that is derived again after this sync closed
 * it is reopened. A risk a PERSON closed stays closed (a sync close records
 * no updated_by; a person's change records theirs).
 *
 * Read-ish in effect (mirrors computed facts, doesn't change anyone's
 * workflow decisions), so it shares the triage permission tier.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";

interface DerivedRiskInput {
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
const MAX_RISKS = 500;
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

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_resolve_violations");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const body = await req.json().catch(() => null) as { risks?: DerivedRiskInput[] } | null;
  if (!body || !Array.isArray(body.risks)) return NextResponse.json({ error: "missing_risks" }, { status: 400 });
  if (body.risks.length > MAX_RISKS) return NextResponse.json({ error: "too_many_risks" }, { status: 400 });

  // One entry per id (the last one wins) -- a repeated id used to make the whole write fail.
  const batch = new Map<string, Meta>();
  let skipped = 0;
  for (const r of body.risks) {
    const id = str(r?.id, 200);
    const meta = id ? toMeta(r) : null;
    if (!id || !meta) { skipped++; continue; }
    batch.set(id, meta);
  }
  const ids = [...batch.keys()];
  const org_id = auth.org_id!;
  const db = createServiceClient();
  const now = new Date().toISOString();

  // Existing rows for these ids.
  const existing = new Map<string, ExistingRow>();
  for (let i = 0; i < ids.length; i += CHUNK) {
    const { data, error } = await db.from("risk_register")
      .select(`external_id, auto_derived, status, updated_by, ${META.join(", ")}`)
      .eq("org_id", org_id)
      .in("external_id", ids.slice(i, i + CHUNK)) as { data: ExistingRow[] | null; error: unknown };
    if (error) return safeError(error, { code: "risk_sync_failed", message: "We couldn't sync the risk register right now. Please try again." });
    for (const row of data ?? []) existing.set(row.external_id, row);
  }

  // New risks: one insert. Changed metadata: one update per changed row. A risk this sync closed earlier: reopen.
  const newIds = ids.filter(id => !existing.has(id));
  if (newIds.length > 0) {
    const { error } = await db.from("risk_register").insert(newIds.map(id => ({ ...batch.get(id)!, external_id: id, auto_derived: true, org_id })));
    if (error) return safeError(error, { code: "risk_sync_failed", message: "We couldn't sync the risk register right now. Please try again." });
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

  return NextResponse.json({ ok: true, synced: ids.length, inserted: newIds.length, updated, reopened: reopened.length, closed, skipped });
}
