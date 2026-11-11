/**
 * POST /api/claim-admin
 * Recovery path for an organisation that has NO admin (its admin was removed or deleted): promotes its owner.
 *
 * Allowed when ALL of these hold:
 *  - the caller is a signed-in person (not an API key);
 *  - the organisation has 0 admins;
 *  - the caller is the organisation's OLDEST member, the one who created it. Before, ANY member of such an organisation
 *    (a viewer, a developer) could make themselves admin; now everyone else is refused and told who to ask.
 *
 * Every claim is written to the audit log, and attempts are rate-limited.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { checkRateLimit } from "@/lib/rateLimit";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  if (!auth.user_id) return NextResponse.json({ error: "user_required" }, { status: 400 });   // not for API keys

  const rl = await checkRateLimit(auth.user_id, { limit: 5, windowMs: 60 * 60_000, prefix: "claim-admin" });
  if (!rl.success) return NextResponse.json({ error: "too_many_attempts" }, { status: 429, headers: rl.headers });

  const db = createServiceClient();

  // Count current admins in this org
  const { count: adminCount } = await db
    .from("org_members")
    .select("id", { count: "exact", head: true })
    .eq("org_id", auth.org_id)
    .eq("role", "admin");

  if ((adminCount ?? 0) > 0) {
    return NextResponse.json({
      error: "org_has_admin",
      message: "This organisation already has an admin. Ask them to change your role.",
    }, { status: 403 });
  }

  // The organisation's de-facto owner is its oldest member who has actually joined (an invitation nobody has accepted
  // has no user yet). Only they may claim.
  const { data: owner } = await db
    .from("org_members")
    .select("user_id")
    .eq("org_id", auth.org_id)
    .not("user_id", "is", null)
    .order("created_at", { ascending: true })
    .order("id", { ascending: true })
    .limit(1)
    .maybeSingle() as { data: { user_id: string } | null };

  if (!owner || owner.user_id !== auth.user_id) {
    return NextResponse.json({
      error: "not_the_owner",
      message: "Only the organisation's first member can claim admin rights while it has no admin. Ask them, or contact support.",
    }, { status: 403 });
  }

  // No admins and the caller is the owner: promote them
  const { error: updateErr } = await db
    .from("org_members")
    .update({ role: "admin" })
    .eq("org_id", auth.org_id)
    .eq("user_id", auth.user_id);
  if (updateErr) {
    return safeError(updateErr, { code: "claim_admin_failed", message: "We couldn't make you an admin right now. Please try again." });
  }

  await writeAuditLog(db, {
    org_id:        auth.org_id,
    event_type:    "member_role_changed",
    actor_id:      auth.user_id,
    actor_email:   auth.actor_email ?? null,
    resource_type: "org_member",
    resource_id:   auth.user_id,
    payload:       { via: "claim_admin", to: "admin" },
  });

  return NextResponse.json({ ok: true });
}
