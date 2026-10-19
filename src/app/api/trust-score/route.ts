/**
 * Trust Score (lib/governanceScore.ts)
 *
 * GET /api/trust-score?history=90 → { score, history }
 * GET /api/trust-score?report=1    → a signed score report (download), verifiable with the published public key
 *
 * Computed live from the org's real data, then saved as today's snapshot so the trend is real history. Readable
 * by every member: it is the org's own governance posture, and every dimension says what to fix.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { safeError } from "@/lib/errors";
import { writeAuditLog } from "@/lib/audit";
import { computeOrgScore, saveSnapshot, loadHistory } from "@/lib/governanceScoreLoader";
import { signEd25519 } from "@/lib/exportSigning";
import { canonicalJson } from "@/lib/trustRecord";

const SCORE_REPORT_SCHEMA = "trustledger.trust-score-report/v1";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const params = req.nextUrl.searchParams;
  const days = Math.min(Math.max(parseInt(params.get("history") ?? "90") || 90, 7), 365);
  const db = createServiceClient();
  try {
    const score = await computeOrgScore(db, auth.org_id);
    const saved = await saveSnapshot(db, auth.org_id, score);
    const history = await loadHistory(db, auth.org_id, days);

    if (params.get("report") === "1") {
      const { data: org } = await db.from("organizations").select("name").eq("id", auth.org_id).maybeSingle() as { data: { name?: string } | null };
      const record = { schema: SCORE_REPORT_SCHEMA, organization: org?.name ?? null, score, history };
      const signature = signEd25519(canonicalJson(record), "canonical JSON of `record`: object keys sorted, no whitespace");
      await writeAuditLog(db, {
        org_id: auth.org_id, event_type: "report_generated", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
        resource_type: "trust_score", resource_id: score.computed_at.slice(0, 10),
        payload: { kind: "trust_score_report", total: score.total, signed: !!signature },
      });
      return new NextResponse(JSON.stringify({ record, signature }, null, 2), {
        headers: { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="trust-score-${score.computed_at.slice(0, 10)}.json"` },
      });
    }
    return NextResponse.json({ score, history, history_available: saved });
  } catch (err) {
    return safeError(err, { code: "trust_score_failed", message: "We couldn't compute the Trust Score right now. Please try again." });
  }
}
