/**
 * Report generation history — GET /api/report/history?limit=10
 *
 * Real traceability for "was this the report an auditor was actually
 * handed, and when" -- lists past report_generations rows (who
 * generated what, for which framework/period, with which signature).
 * See migration 20260918_report_generations.sql.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { safeError } from "@/lib/errors";

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const limit = Math.min(50, Math.max(1, parseInt(new URL(req.url).searchParams.get("limit") ?? "10", 10) || 10));

  const db = createServiceClient();
  const { data, error: qErr } = await db
    .from("report_generations")
    .select("id, framework, period_start, period_end, generated_by_email, signature, created_at")
    .eq("org_id", org_id)
    .order("created_at", { ascending: false })
    .limit(limit);

  if (qErr) return safeError(qErr, { code: "report_history_fetch_failed", message: "We couldn't load report history right now. Please try again." });

  return NextResponse.json({ reports: data ?? [] });
}
