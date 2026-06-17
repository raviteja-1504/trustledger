/**
 * POST /api/orgs/reset
 * Wipes all operational data for the organisation and resets onboarding.
 * Keeps: org record, org_members (all team members stay).
 * Deletes: scans, scan_files, violations, attestations, secret_findings,
 *          repositories, webhook_deliveries, api_keys, audit_log.
 * Admin only.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../../_middleware";
import { cacheDel, cacheKeys } from "@/lib/cache";

const DASHBOARD_CACHE_DAYS = [7, 30, 90];

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const { org_id } = auth;
  const db = createServiceClient();

  // Get all scan IDs for this org (needed for cascading deletes)
  const { data: scans } = await db
    .from("scans")
    .select("id")
    .eq("org_id", org_id);

  const scanIds = (scans ?? []).map(s => s.id);

  // Delete in FK-safe order
  if (scanIds.length > 0) {
    await db.from("violations")      .delete().in("scan_id", scanIds);
    await db.from("attestations")    .delete().in("scan_id", scanIds);
    await db.from("secret_findings") .delete().in("scan_id", scanIds);
    await db.from("scan_files")      .delete().in("scan_id", scanIds);
  }

  await db.from("scans")             .delete().eq("org_id", org_id);
  await db.from("repositories")      .delete().eq("org_id", org_id);
  await db.from("webhook_deliveries").delete().eq("org_id", org_id);
  await db.from("api_keys")          .delete().eq("org_id", org_id);
  await db.from("audit_log")         .delete().eq("org_id", org_id);

  // Reset onboarding so the wizard runs again
  await db
    .from("organizations")
    .update({ onboarding_complete: false })
    .eq("id", org_id);

  // Bust dashboard cache
  await Promise.all(DASHBOARD_CACHE_DAYS.map(d => cacheDel(cacheKeys.dashboard(org_id, d))));

  return NextResponse.json({ ok: true, message: "Organisation data reset. Redirecting to onboarding." });
}
