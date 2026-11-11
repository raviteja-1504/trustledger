/**
 * GitHub App post-install callback.
 *
 * GitHub redirects here (browser GET, carrying the user's session cookies)
 * after someone installs/updates the App — see the manifest's callback_url
 * in /api/github-app/manifest. Links the installation_id to the signed-in
 * user's org so scans/checks can look it up later.
 *
 * Query params: code (one-time, from "Request user authorization during installation"), installation_id, setup_action.
 * The installation_id in the URL can be edited by anyone, so it is linked only after GitHub confirms, through that
 * code, that the person has access to it (lib/githubUserAuth.ts); an installation already linked to this same
 * organisation is just refreshed. Anything unverifiable is refused.
 *
 * Where the person lands afterwards: back in the setup wizard while setup is unfinished (it shows where the app was
 * installed and carries on), the dashboard once it is done. Settings has nothing about GitHub to show.
 * setup_action=request (an organisation owner must approve the install; no installation_id) also goes to the wizard.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { getInstallationAccount } from "@/lib/github";
import { verifyInstallationAccess } from "@/lib/githubUserAuth";
import { logger } from "@/lib/logger";

function authCookieName(): string {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
  const ref = url ? new URL(url).hostname.split(".")[0] : "";
  return `sb-${ref}-auth-token`;
}

export async function GET(req: NextRequest) {
  const installationId = req.nextUrl.searchParams.get("installation_id");
  const setupAction = req.nextUrl.searchParams.get("setup_action") ?? "install";
  if (!installationId) {
    return NextResponse.redirect(new URL(setupAction === "request" ? "/onboarding?setup_action=request" : "/onboarding?error=missing_installation_id", req.url));
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

  // Is this really the person's installation? (Not needed to refresh one this organisation already has.)
  const { data: existing } = await db.from("github_installations").select("org_id").eq("installation_id", Number(installationId)).maybeSingle() as { data: { org_id: string } | null };
  if (existing?.org_id !== member.org_id) {
    const proof = await verifyInstallationAccess(req.nextUrl.searchParams.get("code"), Number(installationId));
    if (!proof.ok) {
      logger.warn("GitHub App installation not linked: could not verify access", { installation_id: installationId, reason: proof.reason, org_id: member.org_id });
      return NextResponse.redirect(new URL(`/onboarding?error=installation_not_verified&why=${proof.reason}`, req.url));
    }
  }

  let githubOrg = "unknown";
  try {
    githubOrg = await getInstallationAccount(Number(installationId));
  } catch (err) {
    logger.error("GitHub App installation account lookup failed", { installation_id: installationId, detail: err instanceof Error ? err.message : String(err) });
  }

  const { error: upsertErr } = await db
    .from("github_installations")
    .upsert(
      { org_id: member.org_id, installation_id: Number(installationId), github_org: githubOrg },
      { onConflict: "installation_id" },
    );

  if (upsertErr) {
    logger.error("Saving the GitHub App installation failed", { installation_id: installationId, detail: upsertErr.message });
    return NextResponse.redirect(new URL("/onboarding?error=installation_save_failed", req.url));
  }

  const { data: org } = await db.from("organizations").select("onboarding_complete").eq("id", member.org_id).maybeSingle() as { data: { onboarding_complete?: boolean } | null };
  if (org?.onboarding_complete) return NextResponse.redirect(new URL("/dashboard?github_app=connected", req.url));
  return NextResponse.redirect(new URL(`/onboarding?github_app=connected&installation_id=${encodeURIComponent(installationId)}&setup_action=${encodeURIComponent(setupAction)}`, req.url));
}
