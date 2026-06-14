import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { getJwtSessionId } from "@/lib/jwt";

// Called once by the client right after exchangeCodeForSession() succeeds.
// Ensures org membership exists, and records this session as the user's sole
// active session — any previously issued token is rejected by verifyApiKey().
export async function POST(req: NextRequest) {
  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return NextResponse.json({ error: "missing_token" }, { status: 401 });
  }

  const token = authHeader.slice(7);
  const db = createServiceClient();
  const { data: { user }, error } = await db.auth.getUser(token);
  if (error || !user) {
    return NextResponse.json({ error: "invalid_token" }, { status: 401 });
  }

  const sessionId = getJwtSessionId(token);

  const { data: existing } = await db
    .from("org_members")
    .select("id")
    .eq("user_id", user.id)
    .single();

  if (existing) {
    if (sessionId) {
      await db
        .from("org_members")
        .update({ active_session_id: sessionId, active_session_at: new Date().toISOString() })
        .eq("user_id", user.id);
    }
    return NextResponse.json({ is_new_user: false });
  }

  // Look up org by GitHub user/org association
  const githubLogin  = user.user_metadata?.user_name as string | undefined;
  const githubOrgStr = user.user_metadata?.preferred_username as string | undefined;
  const orgSlug      = process.env.NEXT_PUBLIC_ORG ?? githubOrgStr ?? githubLogin ?? "default";

  let { data: org } = await db
    .from("organizations")
    .select("id")
    .eq("slug", orgSlug)
    .single();

  if (!org) {
    // Create the org on first sign-in
    const { data: newOrg } = await db
      .from("organizations")
      .insert({ slug: orgSlug, name: orgSlug, github_org: githubLogin ?? null })
      .select("id")
      .single() as { data: { id: string } | null };
    org = newOrg;
  }

  if (org) {
    // Count existing members to assign role
    const { count } = await db
      .from("org_members")
      .select("*", { count: "exact", head: true })
      .eq("org_id", org.id);

    await db.from("org_members").insert({
      org_id:       org.id,
      user_id:      user.id,
      email:        user.email ?? "",
      name:         (user.user_metadata?.full_name as string) ?? null,
      role:         count === 0 ? "admin" : "developer",
      github_login: githubLogin ?? null,
      avatar_url:   (user.user_metadata?.avatar_url as string) ?? null,
      active_session_id: sessionId,
      active_session_at: new Date().toISOString(),
    });
  }

  return NextResponse.json({ is_new_user: true });
}
