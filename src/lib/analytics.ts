"use client";
/**
 * PostHog product analytics.
 * Tracks feature usage to guide product decisions — never sends PII or code content.
 * Initialised lazily; no-ops when NEXT_PUBLIC_POSTHOG_KEY is not set.
 */

let _posthog: { capture: (event: string, props?: Record<string, unknown>) => void; identify: (id: string, props?: Record<string, unknown>) => void } | null = null;

async function getPostHog() {
  if (_posthog) return _posthog;
  const key  = process.env.NEXT_PUBLIC_POSTHOG_KEY;
  const host = process.env.NEXT_PUBLIC_POSTHOG_HOST ?? "https://eu.posthog.com";
  if (!key || typeof window === "undefined") {
    _posthog = { capture: () => {}, identify: () => {} };
    return _posthog;
  }
  try {
    const posthog = await import("posthog-js").then(m => m.default);
    if (!posthog.__loaded) {
      posthog.init(key, { api_host: host, persistence: "localStorage", autocapture: false, capture_pageview: false });
    }
    _posthog = posthog;
    return posthog;
  } catch {
    _posthog = { capture: () => {}, identify: () => {} };
    return _posthog;
  }
}

// ── Track events ──────────────────────────────────────────────────────────────

export async function track(event: string, props?: Record<string, unknown>) {
  const ph = await getPostHog();
  ph.capture(event, props);
}

export async function identify(userId: string, props?: Record<string, unknown>) {
  const ph = await getPostHog();
  ph.identify(userId, props);
}

// ── Named events (keeps analytics calls consistent) ──────────────────────────

export const analytics = {
  // Onboarding
  onboardingStarted:    ()                                     => track("onboarding_started"),
  onboardingCompleted:  (steps: string[])                      => track("onboarding_completed", { steps }),
  githubConnected:      ()                                     => track("github_connected"),

  // Scanning
  scanSubmitted:        (repo: string, fileCount: number)      => track("scan_submitted",   { repo, file_count: fileCount }),
  scanCompleted:        (risk: string, aiPct: number)          => track("scan_completed",   { overall_risk: risk, ai_pct: aiPct }),
  scanViewedInPR:       (scanId: string, risk: string)         => track("scan_pr_viewed",   { scan_id: scanId, risk }),

  // Attestation
  fileAttested:         (risk: string)                         => track("file_attested",    { risk }),
  attestAllClicked:     (fileCount: number)                    => track("attest_all",       { file_count: fileCount }),

  // Reports
  reportDownloaded:     (framework: string)                    => track("report_downloaded",{ framework }),
  aibomDownloaded:      ()                                     => track("aibom_downloaded"),

  // Violations
  violationResolved:    (risk: string)                         => track("violation_resolved",{ risk }),
  ticketCreated:        (provider: string, risk: string)       => track("ticket_created",   { provider, risk }),

  // Settings
  slackConnected:       ()                                     => track("slack_connected"),
  jiraConnected:        ()                                     => track("jira_connected"),
  linearConnected:      ()                                     => track("linear_connected"),
  ssoConfigured:        (provider: string)                     => track("sso_configured",   { provider }),
  memberInvited:        ()                                     => track("member_invited"),

  // Billing
  upgradeStarted:       (plan: string, billing: string)        => track("upgrade_started",  { plan, billing }),
  portalOpened:         ()                                     => track("billing_portal_opened"),

  // Navigation
  pageViewed:           (page: string)                         => track("page_viewed",      { page }),
};
