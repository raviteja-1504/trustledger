/**
 * GitHub App post-install callback.
 *
 * GitHub redirects here (browser GET, carrying the user's session cookies)
 * after someone installs/updates the App — see the manifest's callback_url
 * in /api/github-app/manifest. Links the installation_id to the signed-in
 * user's org so scans/checks can look it up later.
 *
 * Query params: code (unused — the app authenticates via its own JWT +
 * installation tokens, not user OAuth tokens), installation_id, setup_action.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { getInstallationAccount } from "@/lib/github";

function authCookieName(): string {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
  const ref = url ? new URL(url).hostname.split(".")[0] : "";
  return `sb-${ref}-auth-token`;
}

export async function GET(req: NextRequest) {
  const installationId = req.nextUrl.searchParams.get("installation_id");
  if (!installationId) {
    return NextResponse.redirect(new URL("/settings?error=missing_installation_id", req.url));
  }

  const raw = req.cookies.get(authCookieName())?.value;
  if (!raw) {
    return NextResponse.redirect(new URL("/login?error=not_signed_in", req.url));
  }

  let accessToken: string | undefined;
  try {
    accessToken = (JSON.parse(decodeURIComponent(raw)) as { access_token?: string }).access_token;
  } catch {
    accessToken = undefined;
  }
  if (!accessToken) {
    return NextResponse.redirect(new URL("/login?error=invalid_session", req.url));
  }

  const db = createServiceClient();
  const { data: { user }, error: userErr } = await db.auth.getUser(accessToken);
  if (userErr || !user) {
    return NextResponse.redirect(new URL("/login?error=invalid_session", req.url));
  }

  const { data: member } = await db
    .from("org_members")
    .select("org_id")
    .eq("user_id", user.id)
    .single() as { data: { org_id: string } | null };

  if (!member) {
    return NextResponse.redirect(new URL("/onboarding?error=no_org", req.url));
  }

  let githubOrg = "unknown";
  try {
    githubOrg = await getInstallationAccount(Number(installationId));
  } catch (err) {
    console.error("[auth/callback] failed to fetch installation account:", err);
  }

  const { error: upsertErr } = await db
    .from("github_installations")
    .upsert(
      { org_id: member.org_id, installation_id: Number(installationId), github_org: githubOrg },
      { onConflict: "installation_id" },
    );

  if (upsertErr) {
    console.error("[auth/callback] failed to save installation:", upsertErr);
    return NextResponse.redirect(new URL("/settings?error=installation_save_failed", req.url));
  }

  return NextResponse.redirect(new URL("/settings?github_app=connected", req.url));
}
