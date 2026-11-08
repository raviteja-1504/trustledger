/**
 * Risk Register — sync derived risks into the database.
 *
 * POST { risks } records the given derived risks in `risk_register` without touching any human-set workflow
 * column, closes derived risks that are no longer derived and reopens ones that came back (lib/riskRegisterSync.ts).
 * GET /api/risk-register derives the risks on the server and runs the same sync, so the page no longer needs this
 * endpoint; it stays for API clients and the offline path.
 *
 * Read-ish in effect (mirrors computed facts, doesn't change anyone's workflow decisions), so it shares the triage
 * permission tier.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { safeError } from "@/lib/errors";
import { MAX_RISKS, syncDerivedRisks, type DerivedRiskInput } from "@/lib/riskRegisterSync";

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_resolve_violations");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const body = await req.json().catch(() => null) as { risks?: DerivedRiskInput[] } | null;
  if (!body || !Array.isArray(body.risks)) return NextResponse.json({ error: "missing_risks" }, { status: 400 });
  if (body.risks.length > MAX_RISKS) return NextResponse.json({ error: "too_many_risks" }, { status: 400 });

  try {
    const result = await syncDerivedRisks(createServiceClient(), auth.org_id!, body.risks);
    return NextResponse.json({ ok: true, ...result });
  } catch (error) {
    return safeError(error, { code: "risk_sync_failed", message: "We couldn't sync the risk register right now. Please try again." });
  }
}
