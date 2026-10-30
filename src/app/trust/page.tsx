import type { Metadata } from "next";
import Link from "next/link";
import { SitePage, Section, Card, Pill, TableWrap, BORDER, CYAN, EMERALD, AMBER, ROSE, VIOLET, SKY } from "@/components/marketing/Site";
import { securityContact, SECURITY_ACK_BUSINESS_DAYS } from "@/lib/contacts";

export const metadata: Metadata = {
  title: "Trust Center — TrustLedger",
  description: "How TrustLedger handles your source code: architecture, repository permissions, what is stored and for how long, encryption, tenant isolation, attestation integrity, subprocessors and current compliance status.",
};

/** The GitHub App's permissions, exactly as requested by /api/github-app/manifest. */
const GITHUB_PERMISSIONS = [
  { scope: "Pull requests", access: "Read", why: "To learn which files a pull request changes and to read its metadata (title, branch, author, commit)." },
  { scope: "Contents", access: "Read", why: "To fetch the contents of the changed files so the scanner can analyse them. No write access to your code." },
  { scope: "Metadata", access: "Read", why: "Required by GitHub for every app: repository names and visibility." },
  { scope: "Checks", access: "Write", why: "To post the scan result as a check run on the pull request, which is what can hold a merge." },
  { scope: "Commit statuses", access: "Write", why: "Requested by the app manifest so a result can also be reported as a commit status. On GitHub, TrustLedger currently reports through check runs only." },
];
const GITHUB_EVENTS = ["pull_request", "push", "check_run", "check_suite"];

function Diagram() {
  const box = (x: number, y: number, w: number, h: number, title: string, sub: string, color: string) => (
    <g>
      <rect x={x} y={y} width={w} height={h} rx="12" fill="rgba(255,255,255,0.04)" stroke={color} strokeOpacity="0.7" />
      <text x={x + w / 2} y={y + 24} textAnchor="middle" fill="#fff" fontSize="14" fontWeight="700">{title}</text>
      {sub.split("|").map((s, i) => <text key={i} x={x + w / 2} y={y + 44 + i * 16} textAnchor="middle" fill="rgba(255,255,255,0.6)" fontSize="11.5">{s}</text>)}
    </g>
  );
  const arrow = (x1: number, y1: number, x2: number, y2: number, label: string, ly = -8) => (
    <g>
      <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="rgba(255,255,255,0.45)" strokeWidth="1.5" markerEnd="url(#arrow)" />
      <text x={(x1 + x2) / 2} y={(y1 + y2) / 2 + ly} textAnchor="middle" fill="rgba(255,255,255,0.55)" fontSize="11">{label}</text>
    </g>
  );
  return (
    <div className="overflow-x-auto rounded-2xl border" style={{ borderColor: BORDER, background: "rgba(255,255,255,0.02)" }}>
      <svg viewBox="0 0 980 470" className="min-w-[860px] w-full" role="img" aria-labelledby="arch-title arch-desc">
        <title id="arch-title">TrustLedger architecture and data flow</title>
        <desc id="arch-desc">A pull request on GitHub triggers a signed webhook to the TrustLedger application on Vercel, which queues a scan job. The scan worker fetches the changed files with a short-lived installation token, analyses them as text, stores results in an organisation-scoped Postgres database, and posts a check run back to GitHub. Users read results in the dashboard.</desc>
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="rgba(255,255,255,0.55)" /></marker>
        </defs>
        {/* trust boundaries */}
        <rect x="16" y="16" width="250" height="438" rx="16" fill="none" stroke={AMBER} strokeDasharray="6 6" strokeOpacity="0.6" />
        <text x="30" y="40" fill={AMBER} fontSize="11" fontWeight="700">YOUR GIT PROVIDER</text>
        <rect x="300" y="16" width="664" height="438" rx="16" fill="none" stroke={CYAN} strokeDasharray="6 6" strokeOpacity="0.6" />
        <text x="314" y="40" fill={CYAN} fontSize="11" fontWeight="700">TRUSTLEDGER (VERCEL · SUPABASE · UPSTASH)</text>

        {box(40, 70, 200, 76, "Pull request", "opened or updated|on GitHub / GitLab / Bitbucket", AMBER)}
        {box(40, 300, 200, 92, "Check run / status", "pass, or merge blocked|until a reviewer attests", AMBER)}
        {box(330, 70, 220, 76, "Webhook endpoint", "HMAC-SHA256 signature|verified before anything runs", CYAN)}
        {box(610, 70, 330, 76, "Job queue (QStash)", "the scan is queued, not run|inside the webhook request", VIOLET)}
        {box(610, 190, 330, 104, "Scan worker", "fetches changed files (GitHub: short-lived|installation token) · parses them as text,|never executes them · size and depth limits", ROSE)}
        {box(330, 330, 250, 100, "Postgres (Supabase)", "row-level security per organisation|findings, risk, file content for review|hash-chained audit log", EMERALD)}
        {box(640, 340, 300, 90, "Dashboard & API", "Supabase Auth · SSO · 2FA · SCIM|role checked on every write|Ed25519-signed exports", SKY)}

        {arrow(240, 108, 330, 108, "signed webhook")}
        {arrow(550, 108, 610, 108, "enqueue")}
        {arrow(775, 146, 775, 190, "deliver job", -2)}
        {arrow(610, 280, 240, 108, "fetch changed files (read-only)", -10)}
        {arrow(700, 294, 560, 330, "store results", 4)}
        {arrow(610, 250, 240, 330, "post check run / status", 18)}
        {arrow(580, 385, 640, 385, "org-scoped reads", -8)}
      </svg>
    </div>
  );
}

export default function TrustPage() {
  const contact = securityContact();
  return (
    <SitePage active="/trust" eyebrow="Trust Center" eyebrowColor={EMERALD} title="What happens to your code when you connect it"
      lede={<>A code-security product should be judged by its own security posture. This page describes what TrustLedger accesses, what it stores, how long it keeps it and how it is protected — and, just as plainly, what we have <em>not</em> done yet.</>}>
      <Section>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card accent={CYAN}><p className="font-bold text-white mb-1.5">What we access</p><p className="text-sm text-white/65">The metadata of pull requests in repositories you connect, and the contents of the files each pull request changes. Read-only: the app cannot push, merge or change settings.</p></Card>
          <Card accent={AMBER}><p className="font-bold text-white mb-1.5">What we store</p><p className="text-sm text-white/65">Scan results (findings, traces, risk scores, AI estimates), the content of scanned files — so reviewers can see the flagged lines — attestations and an audit log. Scoped to your organisation.</p></Card>
          <Card accent={EMERALD}><p className="font-bold text-white mb-1.5">What we never do</p><p className="text-sm text-white/65">Execute your code, use it to train AI models, share it with other customers, or ask for write access to your repositories&apos; contents.</p></Card>
        </div>
      </Section>

      <Section id="architecture" title="Architecture and data flow" tone="surface"
        intro="Dashed outlines are trust boundaries. Code crosses from your git provider into TrustLedger only when a pull request in a connected repository changes, and only the changed files.">
        <Diagram />
      </Section>

      <Section id="permissions" title="Repository permissions, and why each is needed"
        intro={<>These are the exact permissions the TrustLedger GitHub App requests. It subscribes to these events: {GITHUB_EVENTS.map(e => <code key={e} className="font-mono text-white/80 mr-1.5">{e}</code>)}. GitLab and Bitbucket connections need read access to merge/pull requests and repository content, and permission to post a commit/build status.</>}>
        <TableWrap>
          <table className="w-full text-[13px]">
            <thead><tr className="text-left text-white/45"><th className="px-4 py-2.5">Permission</th><th className="px-4 py-2.5">Access</th><th className="px-4 py-2.5">Why</th></tr></thead>
            <tbody>{GITHUB_PERMISSIONS.map(p => (
              <tr key={p.scope} className="border-t" style={{ borderColor: BORDER }}>
                <td className="px-4 py-2.5 font-semibold text-white">{p.scope}</td>
                <td className="px-4 py-2.5"><Pill color={p.access === "Read" ? EMERALD : AMBER}>{p.access}</Pill></td>
                <td className="px-4 py-2.5 text-white/65">{p.why}</td>
              </tr>
            ))}</tbody>
          </table>
        </TableWrap>
      </Section>

      <Section id="data" title="Source code, retention and deletion" tone="surface">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-sm text-white/70 leading-relaxed">
          <Card><p className="font-bold text-white mb-1.5">How code is processed</p><p>Changed files are fetched when a pull request is opened or updated and analysed by the scanner as text. It never runs, builds or installs your code, and it has hard limits on file size and parse depth so a hostile file cannot exhaust it. Processing happens in TrustLedger&apos;s hosted infrastructure; we do not currently offer an on-premises scanner.</p></Card>
          <Card><p className="font-bold text-white mb-1.5">What is retained</p><p>Scan results and the content of each scanned file are stored so reviewers can see the flagged lines when they attest. By default nothing is deleted automatically: an organisation chooses a retention window between 30 days and 7 years in Settings. Automatic enforcement never deletes attested scans (they are the audit evidence), open items, or the audit log.</p></Card>
          <Card><p className="font-bold text-white mb-1.5">Deletion</p><p>Administrators can delete historical, unattested scans older than seven days, export the organisation&apos;s data, or delete the organisation&apos;s account and data from Settings. Attestations are immutable by database rule. Some records may be kept where the law requires it.</p></Card>
          <Card><p className="font-bold text-white mb-1.5">AI and model training</p><p>Your source code is used only to provide the service to your organisation. It is not used to train our models or third-party models, and it is not sent to external AI services for analysis — the engines run inside TrustLedger.</p></Card>
        </div>
      </Section>

      <Section id="protection" title="How data is protected">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-sm text-white/70 leading-relaxed">
          <Card><p className="font-bold text-white mb-1.5">Encryption</p><p>HTTPS with HSTS everywhere. Data at rest is encrypted by the database provider. Two-factor secrets are additionally encrypted with AES-256-GCM, and backup codes are stored only as salted hashes.</p></Card>
          <Card><p className="font-bold text-white mb-1.5">Secrets and credentials</p><p>GitHub access uses short-lived app installation tokens requested when needed, not stored personal tokens. Incoming webhooks are rejected unless their HMAC-SHA256 signature verifies. Service credentials are held as environment secrets in the hosting provider, never in the repository.</p></Card>
          <Card><p className="font-bold text-white mb-1.5">Tenant isolation</p><p>Every organisation&apos;s rows are separated by Postgres row-level security. An automated test (built on <code className="font-mono">scripts/tenantScopeAudit.cjs</code>) fails when a server-side query on customer data is not limited to one organisation.</p></Card>
          <Card><p className="font-bold text-white mb-1.5">Access control</p><p>Role-based permissions checked on every API write; SAML single sign-on, two-factor authentication and SCIM deprovisioning; per-IP rate limits on every API route.</p></Card>
          <Card><p className="font-bold text-white mb-1.5">Audit log</p><p>Sign-ins, repository changes, exports, attestations and administrative actions are written to a hash-chained log: each entry commits to the one before it, so a removed or edited entry breaks verification.</p></Card>
          <Card><p className="font-bold text-white mb-1.5">Attestation integrity</p><p>An attestation records the reviewer, a timestamp and a payload hash, and is bound to the file&apos;s content hash: it carries over only to scans of byte-identical content. Trust Records and audit exports are signed with Ed25519; the public key is published at <a href="/.well-known/trustledger-export-signing-key" className="underline underline-offset-2 text-white/85">/.well-known/trustledger-export-signing-key</a> and <code className="font-mono">scripts/verify-trust-record.mjs</code> verifies a document offline.</p></Card>
        </div>
      </Section>

      <Section id="threat-model" title="Threat model (summary)" tone="surface"
        intro="The threats we design against first, and the control that addresses each. This is a summary, not an exhaustive model.">
        <TableWrap>
          <table className="w-full text-[13px]">
            <thead><tr className="text-left text-white/45"><th className="px-4 py-2.5">Threat</th><th className="px-4 py-2.5">Control</th></tr></thead>
            <tbody>{[
              ["One customer reads another customer's code or findings", "Row-level security on customer tables, and a test that fails when a server-side query on an organisation's data is not limited to one organisation."],
              ["A forged webhook triggers scans or writes results", "HMAC-SHA256 signature verification with the per-app webhook secret before any processing."],
              ["A malicious file attacks the scanner", "Code is parsed, never executed; file-size and nesting-depth limits; the analysis engines work only on the text they are given and make no network or filesystem calls."],
              ["A stolen session or API key is used", "2FA and SSO, API keys with expiry and revocation, per-IP rate limits, every sensitive action in the hash-chained audit log."],
              ["Someone rewrites the audit record of who approved what", "Immutable attestations, hash-chained audit log, Ed25519-signed exports verifiable offline."],
              ["An approval is reused for code that later changed", "Attestations are bound to the file's content hash; changed content needs a new attestation."],
            ].map(([t, c]) => (
              <tr key={t} className="border-t" style={{ borderColor: BORDER }}>
                <td className="px-4 py-2.5 text-white font-semibold align-top">{t}</td><td className="px-4 py-2.5 text-white/65">{c}</td>
              </tr>
            ))}</tbody>
          </table>
        </TableWrap>
      </Section>

      <Section id="subprocessors" title="Subprocessors">
        <TableWrap>
          <table className="w-full text-[13px]">
            <thead><tr className="text-left text-white/45"><th className="px-4 py-2.5">Provider</th><th className="px-4 py-2.5">Purpose</th><th className="px-4 py-2.5">Data</th></tr></thead>
            <tbody>{[
              ["Vercel", "Application hosting and serverless functions", "All application traffic, transiently"],
              ["Supabase", "Postgres database, authentication, file storage", "Account data, scan results, scanned file content, audit log"],
              ["Upstash", "Job queue (QStash) and Redis cache / rate limiting", "Scan job references, rate-limit counters"],
              ["GitHub, GitLab, Bitbucket", "Source hosting integrations", "Only repositories you connect"],
              ["Sentry", "Error monitoring", "Error reports and stack traces"],
              ["PostHog", "Product analytics, where enabled", "Usage events"],
              ["SendGrid", "Account and alert email", "Recipient address and message"],
              ["Payment processor", "Billing, paid plans only", "Billing contact and payment details"],
            ].map(([p, u, d]) => (
              <tr key={p} className="border-t" style={{ borderColor: BORDER }}>
                <td className="px-4 py-2.5 font-semibold text-white">{p}</td><td className="px-4 py-2.5 text-white/65">{u}</td><td className="px-4 py-2.5 text-white/55">{d}</td>
              </tr>
            ))}</tbody>
          </table>
        </TableWrap>
        <p className="text-[12px] text-white/45 mt-3">Integrations you configure yourself (Slack, Jira, PagerDuty, webhooks) receive the alerts you route to them.</p>
      </Section>

      <Section id="disclosure" title="Vulnerability disclosure and incident response" tone="surface">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-white/70 leading-relaxed">
          <Card accent={ROSE}><p className="font-bold text-white mb-1.5">Report a vulnerability</p><p>Email <a href={`mailto:${contact}`} className="underline underline-offset-2 text-white/85">{contact}</a>. We acknowledge within {SECURITY_ACK_BUSINESS_DAYS} business days and give an initial assessment within 10. Good-faith research within our guidelines is covered by safe harbour. Full policy: <Link href="/security" className="underline underline-offset-2 text-white/85">/security</Link> · machine-readable: <a href="/.well-known/security.txt" className="underline underline-offset-2 text-white/85">security.txt</a>.</p></Card>
          <Card accent={VIOLET}><p className="font-bold text-white mb-1.5">If something goes wrong</p><p>Incidents are triaged by severity with a written runbook. If we confirm an incident affecting a customer&apos;s data we notify that customer&apos;s administrators without undue delay and within 72 hours of confirming it, with what happened, what data was involved and what to do.</p></Card>
        </div>
      </Section>

      <Section id="compliance" title="Compliance status">
        <Card accent={AMBER}>
          <ul className="space-y-2 text-sm text-white/75">
            <li><strong className="text-white">SOC 2:</strong> not certified. TrustLedger helps <em>you</em> produce SOC 2 evidence for your own change-management controls; we have not completed a SOC 2 audit of our own.</li>
            <li><strong className="text-white">ISO 27001:</strong> not certified.</li>
            <li><strong className="text-white">Independent penetration test:</strong> not yet performed. We will publish a summary when one is.</li>
            <li><strong className="text-white">GDPR:</strong> data export and deletion are available to administrators; see the <Link href="/privacy" className="underline underline-offset-2">privacy policy</Link>.</li>
          </ul>
          <p className="text-[12px] text-white/45 mt-3">We will update this section when any of these change, and never list a certification we do not hold.</p>
        </Card>
      </Section>
    </SitePage>
  );
}
