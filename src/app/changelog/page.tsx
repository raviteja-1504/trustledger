/**
 * Public API Changelog — documents breaking changes, new features, deprecations.
 * Accessible at /changelog — no auth required.
 */

const CHANGELOG = [
  {
    version: "1.0.0",
    date:    "2026-06-01",
    type:    "release",
    changes: [
      { kind:"added",   text:"Initial stable release with full scan, attest, and report API surface" },
      { kind:"added",   text:"Supabase Realtime — live dashboard updates on scan completion and attestation" },
      { kind:"added",   text:"GitHub App webhook receiver with HMAC-SHA256 verification and Check Runs" },
      { kind:"added",   text:"GitLab MR scanning with commit status API" },
      { kind:"added",   text:"Bitbucket PR scanning with build status API" },
      { kind:"added",   text:"SOC 2, EU AI Act, PCI-DSS PDF compliance reports" },
      { kind:"added",   text:"OpenAPI 3.1 spec + Swagger UI at /docs" },
    ],
  },
  {
    version: "0.9.0",
    date:    "2026-05-20",
    type:    "beta",
    changes: [
      { kind:"added",   text:"Python SDK + Node.js/TypeScript SDK" },
      { kind:"added",   text:"VS Code extension with inline AI risk indicators and Problems panel integration" },
      { kind:"added",   text:"trustledger-cli with scan, attest, violations, report commands" },
      { kind:"added",   text:"Stripe billing integration (checkout, customer portal, subscription webhooks)" },
      { kind:"added",   text:"SCIM 2.0 user provisioning for Okta and Azure AD" },
      { kind:"added",   text:"Zapier/Make.com trigger and action endpoints" },
    ],
  },
  {
    version: "0.8.0",
    date:    "2026-05-10",
    type:    "beta",
    changes: [
      { kind:"added",   text:"Self-hosted scanner — analyse code locally, only metadata sent to API" },
      { kind:"added",   text:"AI model attribution — detect GitHub Copilot, ChatGPT, Gemini, Claude" },
      { kind:"added",   text:"Compliance calendar with SOC 2 / EU AI Act / PCI-DSS deadline tracking" },
      { kind:"added",   text:"ROI dashboard with breach risk reduction calculations" },
      { kind:"added",   text:"Rate limiting via Upstash Redis with in-memory fallback" },
      { kind:"added",   text:"Dark mode support via prefers-color-scheme + manual toggle" },
    ],
  },
  {
    version: "0.7.0",
    date:    "2026-04-28",
    type:    "beta",
    changes: [
      { kind:"added",   text:"Customer outbound webhooks with HMAC-SHA256 signatures" },
      { kind:"added",   text:"JIRA and Linear ticket creation from violations" },
      { kind:"added",   text:"Slack, email (SendGrid), PagerDuty, and Microsoft Teams alert delivery" },
      { kind:"added",   text:"Webhook delivery retry with exponential backoff" },
      { kind:"added",   text:"Scheduled repository scanning (hourly cron)" },
      { kind:"added",   text:"Full-text search across scans, violations, secrets, incidents, audit log" },
    ],
  },
  {
    version: "0.6.0",
    date:    "2026-04-15",
    type:    "beta",
    changes: [
      { kind:"added",   text:"Supabase Realtime replacing localStorage polling for live updates" },
      { kind:"added",   text:"SLA breach monitor cron — P1 alerts when attestation deadline exceeded" },
      { kind:"added",   text:"Multi-org MSP dashboard for managing multiple client organisations" },
      { kind:"added",   text:"Evidence vault with Supabase Storage file uploads" },
      { kind:"added",   text:"SSO/SAML settings UI (Okta, Azure AD, Google Workspace, OneLogin)" },
      { kind:"changed", text:"Auth migrated from Firebase to Supabase Auth with GitHub OAuth and magic links" },
    ],
  },
];

const KIND_STYLE: Record<string, { bg: string; text: string; label: string }> = {
  added:      { bg:"#f0fdf4", text:"#15803d", label:"Added"      },
  changed:    { bg:"#eff6ff", text:"#1d4ed8", label:"Changed"     },
  deprecated: { bg:"#fffbeb", text:"#b45309", label:"Deprecated"  },
  removed:    { bg:"#fff1f2", text:"#be123c", label:"Removed"     },
  fixed:      { bg:"#f0fdf4", text:"#15803d", label:"Fixed"       },
  security:   { bg:"#ede9fe", text:"#6d28d9", label:"Security"    },
};

const TYPE_STYLE: Record<string, { bg: string; text: string; border: string }> = {
  release: { bg:"linear-gradient(135deg,#6366f1,#7c3aed)", text:"#ffffff", border:"transparent" },
  beta:    { bg:"#eff6ff",                                   text:"#1d4ed8", border:"#bfdbfe"     },
  patch:   { bg:"#f8fafc",                                   text:"#475569", border:"#e2e8f0"     },
};

export default function ChangelogPage() {
  return (
    <div className="min-h-screen" style={{ background:"#f8fafc" }}>
      <div className="max-w-2xl mx-auto py-16 px-4">

        {/* Header */}
        <div className="mb-12">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center text-white"
              style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <polyline points="9 12 11 14 15 10"/>
              </svg>
            </div>
            <div>
              <h1 className="text-2xl font-black text-gray-900">TrustLedger Changelog</h1>
              <p className="text-sm text-gray-400">API and platform release notes</p>
            </div>
          </div>
          <p className="text-sm text-gray-500 leading-relaxed">
            All notable changes to the TrustLedger API and platform are documented here.
            The API follows <a href="https://semver.org" className="text-indigo-600 hover:underline" target="_blank" rel="noopener noreferrer">semantic versioning</a>.
          </p>
        </div>

        {/* Entries */}
        <div className="space-y-10">
          {CHANGELOG.map(entry => {
            const ts = TYPE_STYLE[entry.type] ?? TYPE_STYLE.patch;
            return (
              <div key={entry.version} id={`v${entry.version}`}>
                {/* Version header */}
                <div className="flex items-center gap-3 mb-4">
                  <span className="text-lg font-black text-gray-900 px-3 py-1 rounded-xl text-white text-sm"
                    style={{ background: ts.bg, color: ts.text, border: `1px solid ${ts.border}` }}>
                    v{entry.version}
                  </span>
                  <span className="text-sm text-gray-400">{new Date(entry.date).toLocaleDateString("en-GB", { day:"numeric", month:"long", year:"numeric" })}</span>
                  <div className="flex-1 h-px bg-gray-200" />
                </div>

                {/* Changes */}
                <div className="space-y-1.5">
                  {entry.changes.map((c, i) => {
                    const style = KIND_STYLE[c.kind] ?? KIND_STYLE.added;
                    return (
                      <div key={i} className="flex items-start gap-3 py-1">
                        <span className="text-[9px] font-black uppercase tracking-wider px-2 py-0.5 rounded shrink-0 mt-0.5"
                          style={{ background: style.bg, color: style.text }}>
                          {style.label}
                        </span>
                        <p className="text-sm text-gray-700 leading-relaxed">{c.text}</p>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-16 text-center">
          <p className="text-xs text-gray-400">
            Subscribe to updates:{" "}
            <a href="mailto:updates@trustledger.dev" className="text-indigo-600 hover:underline">updates@trustledger.dev</a>
          </p>
        </div>
      </div>
    </div>
  );
}
