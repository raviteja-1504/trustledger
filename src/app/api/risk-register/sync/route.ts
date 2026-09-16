/**
 * Risk Register — sync derived risks into the database.
 *
 * The Risk Register page re-derives its "auto" risks from live scan data
 * on every load (unattested CRITICAL/HIGH files, risky repos, etc. — see
 * deriveRisks() in the page). This endpoint upserts that computed metadata
 * into the real `risk_register` table, keyed by external_id, WITHOUT
 * touching workflow columns (status, treatment, owner_email, due_date,
 * mitigation, notes, residual_*) — those are only ever human-set, via
 * PATCH /api/risk-register/state, and must survive re-derivation untouched.
 *
 * It also auto-closes the other side of that: an auto-derived risk that
 * stops being derived (e.g. a hardcoded secret got rotated, so
 * DR-SECRETS-{repo} no longer appears) previously stayed "open" in the
 * database forever — the live UI correctly hid it (deriveRisks() just
 * doesn't produce it anymore), but the persisted record disagreed with
 * reality, which is exactly what an auditor querying the data directly
 * would notice. Any auto_derived row not present in this sync's batch
 * gets marked closed.
 *
 * Read-ish in effect (mirrors computed facts, doesn't change anyone's
 * workflow decisions), so any authenticated org member can trigger it --
 * unlike actual workflow writes, which require security_reviewer+.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
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

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const body = await req.json() as { risks: DerivedRiskInput[] };
  if (!Array.isArray(body.risks)) return NextResponse.json({ error: "missing_risks" }, { status: 400 });

  const db = createServiceClient();
  const currentIds = body.risks.map(r => r.id);

  if (currentIds.length > 0) {
    const { error } = await db.from("risk_register").upsert(
      body.risks.map(r => ({
        org_id:       auth.org_id,
        external_id:  r.id,
        auto_derived: true,
        title:        r.title,
        description:  r.description ?? null,
        category:     r.category,
        likelihood:   r.likelihood,
        impact:       r.impact,
        repo:         r.repo ?? null,
        related_cve:  r.related_cve ?? null,
        related_cwe:  r.related_cwe ?? null,
        related_link: r.related_link ?? null,
      })),
      { onConflict: "org_id,external_id" },
    );
    if (error) return safeError(error, { code: "risk_sync_failed", message: "We couldn't sync the risk register right now. Please try again." });
  }

  // Auto-close any previously-derived risk not in this batch. Fetch every
  // currently-open auto-derived external_id for the org (a small set --
  // bounded by how many distinct risk patterns exist per repo) and diff
  // against the current batch in JS, rather than building a NOT IN(...)
  // filter string from external_ids.
  const currentIdSet = new Set(currentIds);
  const { data: openDerived } = await db
    .from("risk_register")
    .select("external_id")
    .eq("org_id", auth.org_id)
    .eq("auto_derived", true)
    .neq("status", "closed")
    .not("external_id", "is", null) as { data: { external_id: string }[] | null };
  const staleIds = (openDerived ?? [])
    .map(r => r.external_id)
    .filter(id => !currentIdSet.has(id));

  let closed = 0;
  if (staleIds.length > 0) {
    const { data: closedRows, error: closeErr } = await db
      .from("risk_register")
      .update({ status: "closed", updated_at: new Date().toISOString() })
      .eq("org_id", auth.org_id)
      .in("external_id", staleIds)
      .select("id");
    if (!closeErr) {
      closed = closedRows?.length ?? 0;
      if (closed > 0) {
        await writeAuditLog(db, {
          org_id: auth.org_id!, event_type: "risk_updated",
          actor_id: null, actor_email: "system",
          resource_type: "risk_register",
          payload: { action: "auto_closed", reason: "no longer derived from live scan data", count: closed, external_ids: staleIds.slice(0, 20) },
        });
      }
    }
  }

  return NextResponse.json({ ok: true, synced: currentIds.length, closed });
}
