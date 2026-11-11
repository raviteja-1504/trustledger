/**
 * GET /api/plan-usage → { plan, used, limit } : the scans this organisation has used this month against its plan, for the
 * dashboard's "2 of 3 scans used" line. One small count, not the whole usage report. null when the plan has no scan limit.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { scanUsage } from "@/lib/planGate";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  return NextResponse.json({ usage: await scanUsage(createServiceClient(), auth.org_id) });
}
