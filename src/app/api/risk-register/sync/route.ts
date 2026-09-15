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
 * Read-ish in effect (mirrors computed facts, doesn't change anyone's
 * workflow decisions), so any authenticated org member can trigger it --
 * unlike actual workflow writes, which require security_reviewer+.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
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
  related_link?: string;
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const body = await req.json() as { risks: DerivedRiskInput[] };
  if (!Array.isArray(body.risks)) return NextResponse.json({ error: "missing_risks" }, { status: 400 });
  if (body.risks.length === 0) return NextResponse.json({ ok: true, synced: 0 });

  const db = createServiceClient();
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
      related_link: r.related_link ?? null,
    })),
    { onConflict: "org_id,external_id" },
  );

  if (error) return safeError(error, { code: "risk_sync_failed", message: "We couldn't sync the risk register right now. Please try again." });

  return NextResponse.json({ ok: true, synced: body.risks.length });
}
