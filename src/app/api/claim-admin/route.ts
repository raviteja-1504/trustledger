/**
 * POST /api/claim-admin
 * Promotes the caller to admin when the org has no admins (e.g. the user
 * ended up as developer/reviewer through an invite chain but is the
 * de-facto org owner).
 * Allowed when: caller belongs to the org AND there are 0 existing admins.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

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

  // No admins — promote caller
  await db
    .from("org_members")
    .update({ role: "admin" })
    .eq("org_id", auth.org_id)
    .eq("user_id", auth.user_id!);

  return NextResponse.json({ ok: true });
}
