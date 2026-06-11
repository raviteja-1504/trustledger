import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";

export async function GET(req: NextRequest) {
  const { searchParams, origin } = new URL(req.url);
  const code  = searchParams.get("code");
  const next  = searchParams.get("next") ?? "/dashboard";
  const error = searchParams.get("error");

  if (error) {
    return NextResponse.redirect(`${origin}/login?error=${encodeURIComponent(error)}`);
  }

  if (!code) {
    return NextResponse.redirect(`${origin}/login?error=missing_code`);
  }

  const supabase = createServiceClient();
  const { data, error: exchErr } = await supabase.auth.exchangeCodeForSession(code);

  if (exchErr || !data.user) {
    return NextResponse.redirect(`${origin}/login?error=auth_failed`);
  }

  // Auto-create org membership if this is a new GitHub OAuth user
  const { data: existing } = await supabase
    .from("org_members")
    .select("id")
    .eq("user_id", data.user.id)
    .single();

  if (!existing) {
    // Look up org by GitHub user/org association
    const githubLogin  = data.user.user_metadata?.user_name as string | undefined;
    const githubOrgStr = data.user.user_metadata?.preferred_username as string | undefined;
    const orgSlug      = process.env.NEXT_PUBLIC_ORG ?? githubOrgStr ?? githubLogin ?? "default";

    let { data: org } = await supabase
      .from("organizations")
      .select("id")
      .eq("slug", orgSlug)
      .single();

    if (!org) {
      // Create the org on first sign-in
      const { data: newOrg } = await supabase
        .from("organizations")
        .insert({ slug: orgSlug, name: orgSlug, github_org: githubLogin ?? null })
        .select("id")
        .single() as { data: { id: string } | null };
      org = newOrg;
    }

    if (org) {
      // Count existing members to assign role
      const { count } = await supabase
        .from("org_members")
        .select("*", { count: "exact", head: true })
        .eq("org_id", org.id);

      await supabase.from("org_members").insert({
        org_id:       org.id,
        user_id:      data.user.id,
        email:        data.user.email ?? "",
        name:         (data.user.user_metadata?.full_name as string) ?? null,
        role:         count === 0 ? "admin" : "developer",
        github_login: githubLogin ?? null,
        avatar_url:   (data.user.user_metadata?.avatar_url as string) ?? null,
      });
    }
  }

  // New users (just created membership) → redirect to onboarding wizard
  // Returning users or explicit `next` param → use normal flow
  const isNewUser = !existing;
  const destination = isNewUser && next === "/dashboard" ? "/onboarding" : next;

  return NextResponse.redirect(`${origin}${destination}`);
}
