/**
 * POST /api/orgs/reset
 * Wipes mutable operational data for the organisation and resets onboarding.
 * Keeps (by design — immutable):
 *   - attestations  — permanent sign-off records (Postgres RULE blocks DELETE)
 *   - audit_log     — tamper-evident chain (Postgres RULE blocks DELETE)
 * Keeps (membership):
 *   - org record, org_members (all team members stay)
 * Deletes:
 *   - scans, scan_files, violations, secret_findings, repositories,
 *     webhook_deliveries, api_keys
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

  // Delete in FK-safe order.
  // Note: attestations and audit_log are intentionally NOT cleared here — both
  // tables have Postgres RULE-based immutability (create rule ... do instead nothing)
  // that makes DELETE a silent no-op even for the service role.  They are permanent
  // records by design (compliance / tamper-evident audit chain).
  if (scanIds.length > 0) {
    await db.from("violations")      .delete().in("scan_id", scanIds);
    await db.from("secret_findings") .delete().in("scan_id", scanIds);
    await db.from("scan_files")      .delete().in("scan_id", scanIds);
  }

  await db.from("scans")             .delete().eq("org_id", org_id);
  await db.from("repositories")      .delete().eq("org_id", org_id);
  await db.from("webhook_deliveries").delete().eq("org_id", org_id);
  await db.from("api_keys")          .delete().eq("org_id", org_id);

  // Reset onboarding so the wizard runs again
  await db
    .from("organizations")
    .update({ onboarding_complete: false })
    .eq("id", org_id);

  // Bust dashboard cache
  await Promise.all(DASHBOARD_CACHE_DAYS.map(d => cacheDel(cacheKeys.dashboard(org_id, d))));
  await cacheDel(cacheKeys.dependencies(org_id));

  return NextResponse.json({
    ok: true,
    message: "Organisation data reset. Redirecting to onboarding.",
    retained: ["attestations", "audit_log"],
  });
}
