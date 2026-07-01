import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";

/**
 * GET /api/me
 *
 * Returns the org profile for the authenticated user. The middleware's
 * verifyApiKey already handles linking invited members (user_id = null
 * in org_members) to their auth account on first call — it uses the
 * service role client which bypasses RLS, so the UPDATE succeeds even
 * for brand-new signups where the browser anon client would be denied.
 *
 * Called by loadProfile() in auth.tsx as a fallback when the direct
 * Supabase client UPDATE fails (RLS prevents a new user from updating
 * a row they don't yet own).
 */
export async function GET(req: NextRequest) {
  const { org_id, user_id, actor_email, role, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();
  const { data } = await db
    .from("org_members")
    .select("org_id, role, email, name, github_login, avatar_url, organizations(slug, name)")
    .eq("user_id", user_id!)
    .single();

  if (!data) return NextResponse.json({ error: "no_org_membership" }, { status: 404 });

  const org = (Array.isArray(data.organizations) ? data.organizations[0] : data.organizations) as { slug: string; name: string } | null;

  return NextResponse.json({
    org_id:       data.org_id,
    org_slug:     org?.slug ?? "",
    org_name:     org?.name ?? "",
    role:         data.role,
    email:        data.email,
    name:         data.name,
    github_login: data.github_login,
    avatar_url:   data.avatar_url,
  });
}
