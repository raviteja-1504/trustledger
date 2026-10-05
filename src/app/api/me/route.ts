import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, permissionsFor } from "../_middleware";

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
/** Name of the member's custom role, if one is assigned (null on a database without custom roles). */
async function customRoleName(db: ReturnType<typeof createServiceClient>, orgId: string, userId: string): Promise<string | null> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: m } = await (db.from("org_members") as any).select("custom_role_id").eq("org_id", orgId).eq("user_id", userId).maybeSingle() as { data: { custom_role_id?: string | null } | null };
  if (!m?.custom_role_id) return null;
  const { data: r } = await db.from("custom_roles").select("name").eq("id", m.custom_role_id).eq("org_id", orgId).maybeSingle() as { data: { name: string } | null };
  return r?.name ?? null;
}

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { user_id, error } = auth;
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
    // What the UI may offer -- the same set every API route enforces.
    permissions:  await permissionsFor(auth),
    custom_role_name: await customRoleName(db, data.org_id, user_id!),
  });
}
