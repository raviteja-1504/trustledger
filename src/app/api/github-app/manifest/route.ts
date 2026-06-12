/**
 * GitHub App manifest endpoint — enables one-click GitHub App creation.
 *
 * Flow:
 *   1. GET  /api/github-app/manifest                 → returns manifest JSON
 *      (used by /setup/github-app to POST to https://github.com/settings/apps/new)
 *   2. GitHub creates the app, then redirects the browser (GET) back to
 *      `redirect_url` (= this endpoint) with ?code=<temporary_code>
 *   3. GET  /api/github-app/manifest?code=...        → exchanges the code for
 *      app credentials (id, pem, webhook_secret, slug) and renders them once
 *      so they can be copied into Vercel env vars (GITHUB_APP_ID,
 *      GITHUB_APP_PRIVATE_KEY, GITHUB_WEBHOOK_SECRET).
 *
 * Docs: https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest
 */

import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const url    = new URL(req.url);
  const code   = url.searchParams.get("code");
  const origin = url.origin;

  if (code) return handleConversion(code, origin);

  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

  const manifest = {
    name:        "TrustLedger",
    url:         appUrl,
    description: "AI code provenance, attestation, and compliance for every pull request",
    public:      false,

    // Callback after OAuth flow
    callback_url:          `${origin}/api/auth/callback`,
    setup_url:             `${origin}/onboarding`,
    // GitHub redirects here (GET, with ?code=) right after app creation
    redirect_url:          `${origin}/api/github-app/manifest`,
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

/** Exchanges the manifest creation `code` for app credentials and renders them. */
async function handleConversion(code: string, origin: string): Promise<NextResponse> {
  try {
    const res = await fetch(
      `https://api.github.com/app-manifests/${code}/conversions`,
      {
        method:  "POST",
        headers: { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" },
      },
    );

    if (!res.ok) throw new Error(`GitHub returned ${res.status}`);

    const data = await res.json() as {
      id:             number;
      slug:           string;
      pem:            string;
      webhook_secret: string;
      html_url:       string;
    };

    const installUrl = `https://github.com/apps/${data.slug}/installations/new`;

    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>GitHub App created — TrustLedger</title>
<style>
  body{font-family:-apple-system,Segoe UI,sans-serif;max-width:720px;margin:40px auto;padding:0 20px;color:#1f2937}
  h1{font-size:20px}
  .step{background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin:16px 0}
  label{display:block;font-weight:600;font-size:12px;color:#6b7280;margin-bottom:4px}
  textarea,input{width:100%;font-family:monospace;font-size:12px;padding:8px;border:1px solid #d1d5db;border-radius:6px;box-sizing:border-box}
  textarea{height:140px}
  a.btn{display:inline-block;background:#4f46e5;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;margin-top:12px}
  .warn{color:#b45309;font-size:13px}
</style></head>
<body>
  <h1>✅ GitHub App "${data.slug}" created</h1>
  <p class="warn">The private key below is shown <b>once</b> — copy these 3 values into Vercel env vars now
  (<code>GITHUB_APP_ID</code>, <code>GITHUB_APP_PRIVATE_KEY</code>, <code>GITHUB_WEBHOOK_SECRET</code>), then redeploy.</p>

  <div class="step">
    <label>GITHUB_APP_ID</label>
    <input readonly value="${data.id}" onclick="this.select()">
  </div>
  <div class="step">
    <label>GITHUB_WEBHOOK_SECRET</label>
    <input readonly value="${data.webhook_secret}" onclick="this.select()">
  </div>
  <div class="step">
    <label>GITHUB_APP_PRIVATE_KEY (PEM)</label>
    <textarea readonly onclick="this.select()">${data.pem}</textarea>
  </div>

  <div class="step">
    <p style="margin:0 0 8px">Next: install the app on your org/repos —</p>
    <a class="btn" href="${installUrl}" target="_blank" rel="noopener noreferrer">Install on GitHub →</a>
  </div>
</body></html>`;

    return new NextResponse(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  } catch (e) {
    console.error("GitHub App manifest exchange failed:", e);
    return NextResponse.redirect(`${origin}/settings?error=github_app_exchange_failed`);
  }
}
