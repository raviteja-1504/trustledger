/**
 * GitHub App manifest endpoint — enables one-click GitHub App creation.
 * POST /api/github-app/manifest → returns manifest JSON
 *
 * Usage: POST to https://github.com/settings/apps/new?state=<state>
 * with manifest in request body (GitHub creates the app automatically).
 *
 * Docs: https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest
 */

import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";
  const origin = new URL(req.url).origin;

  const manifest = {
    name:        "TrustLedger",
    url:         appUrl,
    description: "AI code provenance, attestation, and compliance for every pull request",
    public:      false,

    // Callback after OAuth flow
    callback_url:          `${origin}/api/auth/callback`,
    setup_url:             `${origin}/onboarding`,
    redirect_url:          `${origin}/api/auth/callback`,
    setup_on_update:       true,
    request_oauth_on_install: true,

    // Webhook
    hook_attributes: {
      url:    `${origin}/api/webhook/github`,
      active: true,
    },

    // Default permissions
    default_permissions: {
      pull_requests: "read",
      contents:      "read",
      checks:        "write",
      metadata:      "read",
      statuses:      "write",
    },

    // Subscribe to these events
    default_events: [
      "pull_request",
      "push",
      "check_run",
      "check_suite",
    ],
  };

  return NextResponse.json(manifest);
}

/**
 * Handles the redirect back from GitHub after app creation.
 * GitHub sends ?code= which we exchange for credentials.
 */
export async function POST(req: NextRequest) {
  const url    = new URL(req.url);
  const code   = url.searchParams.get("code");
  const origin = url.origin;

  if (!code) {
    return NextResponse.redirect(`${origin}/settings?error=github_app_setup_failed`);
  }

  try {
    // Exchange code for GitHub App credentials
    const res = await fetch(
      `https://api.github.com/app-manifests/${code}/conversions`,
      {
        method:  "POST",
        headers: { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" },
      },
    );

    if (!res.ok) throw new Error(`GitHub returned ${res.status}`);

    const data = await res.json() as {
      id:          number;
      pem:         string;
      client_id:   string;
      webhook_secret: string;
    };

    // In production: save these to your .env / secrets manager
    // For now, redirect to settings with the values so the admin can copy them
    const params = new URLSearchParams({
      github_app_id:        String(data.id),
      github_webhook_secret: data.webhook_secret,
      // NOTE: private key is shown once — must be copied immediately
      setup_complete: "1",
    });

    return NextResponse.redirect(`${origin}/settings?${params.toString()}#github-app-credentials`);
  } catch (e) {
    console.error("GitHub App manifest exchange failed:", e);
    return NextResponse.redirect(`${origin}/settings?error=github_app_exchange_failed`);
  }
}
