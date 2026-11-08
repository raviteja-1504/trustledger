/**
 * Risk Register: the whole register in one request.
 *
 * GET /api/risk-register → { risks, basis, sync, capped, canEdit, generatedAt }
 *
 * Derives the risks on the server from the database (the latest scan of each active repository, the real
 * attestations on it, the violations closed without one: lib/riskRegisterLive.ts), records them in `risk_register`
 * (lib/riskRegisterSync.ts: new ones inserted, ones whose files were attested or fixed closed, ones that came back
 * reopened), then returns them merged with what people recorded (owner, due date, status, notes). Replaces the page's
 * old chain of requests (dashboard, one scan per repository, statuses, sync, state), which was slow and read a cached
 * payload, so the register could disagree with the attestation data.
 *
 * The sync is a write, so it runs only for a role that may resolve violations; anyone else gets the same register
 * from what was last synced plus the live derivation. Never cached (per-org, changes with every attestation).
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../_middleware";
import { safeError } from "@/lib/errors";
import { closedHistory, deriveRisksFrom, mergeRisks, rowsToStore, type RiskRow } from "@/lib/riskRegister";
import { loadLiveRiskState } from "@/lib/riskRegisterLive";
import { MAX_RISKS, syncDerivedRisks, type SyncResult } from "@/lib/riskRegisterSync";

const SELECT_COLS = "external_id, auto_derived, title, description, category, likelihood, impact, residual_likelihood, residual_impact, status, treatment, owner_email, due_date, mitigation, related_cve, related_cwe, related_link, repo, notes, created_at";
const PAGE = 1000;

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const canEdit = (await requirePermission(auth, "can_resolve_violations")) == null;
  const orgId = auth.org_id!;
  const db = createServiceClient();

  try {
    const live = await loadLiveRiskState(db, orgId);
    const all = deriveRisksFrom(live.input);
    // Highest-scoring first, so past the cap what is dropped is the least important.
    const derived = [...all].sort((a, b) => b.likelihood * b.impact - a.likelihood * a.impact).slice(0, MAX_RISKS);

    let sync: SyncResult | null = null;
    let syncError: string | null = null;
    if (canEdit) {
      try { sync = await syncDerivedRisks(db, orgId, derived); }
      catch { syncError = "The register couldn't be recorded just now; what you see is live, and workflow changes may not save until it is."; }
    }

    const rows: RiskRow[] = [];
    for (let from = 0; from < 10 * PAGE; from += PAGE) {
      const { data, error } = await db.from("risk_register").select(SELECT_COLS).eq("org_id", orgId)
        .order("created_at", { ascending: false }).range(from, from + PAGE - 1) as { data: RiskRow[] | null; error: unknown };
      if (error) throw error;
      rows.push(...(data ?? []));
      if (!data || data.length < PAGE) break;
    }
    const store = rowsToStore(rows);
    const risks = mergeRisks([...derived, ...closedHistory(rows, new Set(derived.map(r => r.id)))], store);

    return NextResponse.json({
      risks,
      basis: live.basis,
      sync,
      syncError,
      capped: all.length > derived.length ? { shown: derived.length, total: all.length } : null,
      canEdit,
      generatedAt: new Date().toISOString(),
    }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    return safeError(err, { code: "risk_register_failed", message: "We couldn't load the risk register right now. Please try again." });
  }
}
