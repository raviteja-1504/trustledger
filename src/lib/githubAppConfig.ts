/**
 * The GitHub App TrustLedger needs, in one place: the one-click manifest (api/github-app/manifest) and the setup
 * wizard's field-by-field instructions are both built from this, so what the wizard tells a person to fill in is
 * exactly what the product needs. Pure and client-safe.
 */

export const GITHUB_APP_NAME = "TrustLedger";
export const GITHUB_APP_DESCRIPTION = "AI code provenance, attestation, and compliance for every pull request";

/**
 * Repository permissions, as the manifest names them (GitHub's keys; the value is the access level). Exactly what the
 * code calls and no more: check runs (lib/github.ts), reading changed files and PR details, and creating / updating the
 * summary comment on the pull request (issue-comments API, which needs Pull requests: write). Commit statuses are not
 * used for GitHub (the merge gate is a check run), so they are not requested.
 */
export const GITHUB_APP_PERMISSIONS = {
  checks:        "write",
  contents:      "read",
  metadata:      "read",
  pull_requests: "write",
} as const;

/** Webhook events, as the manifest names them: the two api/webhook/github acts on. */
export const GITHUB_APP_EVENTS = ["pull_request", "check_run"] as const;

/** How GitHub's "Register new GitHub App" form labels each permission and event, and why TrustLedger needs it. */
export const PERMISSION_FORM: Record<keyof typeof GITHUB_APP_PERMISSIONS, { label: string; why: string }> = {
  checks:        { label: "Checks",          why: "post the TrustLedger result on the pull request and block the merge until it is signed off" },
  contents:      { label: "Contents",        why: "read the changed files to scan them" },
  metadata:      { label: "Metadata",        why: "required by GitHub for every app (read-only)" },
  pull_requests: { label: "Pull requests",   why: "see which pull requests changed and who opened them, and post / update the TrustLedger summary comment" },
};
export const EVENT_FORM: Record<(typeof GITHUB_APP_EVENTS)[number], string> = {
  pull_request: "Pull request",
  check_run:    "Check run",
};
export const ACCESS_LABEL = { read: "Read-only", write: "Read and write" } as const;

export interface GithubAppSettings {
  name: string;
  description: string;
  homepageUrl: string;
  callbackUrl: string;
  setupUrl: string;
  webhookUrl: string;
}

/** The values for the form's text fields, for an app served at `origin`. */
export function githubAppSettings(origin: string, homepageUrl = origin): GithubAppSettings {
  return {
    name:        GITHUB_APP_NAME,
    description: GITHUB_APP_DESCRIPTION,
    homepageUrl,
    callbackUrl: `${origin}/api/auth/callback`,
    setupUrl:    `${origin}/onboarding`,
    webhookUrl:  `${origin}/api/webhook/github`,
  };
}

/** The manifest GitHub's one-click flow reads (https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest). */
export function githubAppManifest(origin: string, homepageUrl = origin) {
  const s = githubAppSettings(origin, homepageUrl);
  return {
    name:        s.name,
    url:         s.homepageUrl,
    description: s.description,
    public:      false,
    callback_url:             s.callbackUrl,
    setup_url:                s.setupUrl,
    // GitHub redirects here (GET, with ?code=) right after the app is created
    redirect_url:             `${origin}/api/github-app/manifest`,
    setup_on_update:          true,
    request_oauth_on_install: true,
    hook_attributes: { url: s.webhookUrl, active: true },
    default_permissions: { ...GITHUB_APP_PERMISSIONS },
    default_events:      [...GITHUB_APP_EVENTS],
  };
}
