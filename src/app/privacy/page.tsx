"use client";

/**
 * Public Privacy Policy — no auth required.
 * Accessible at /privacy.
 */

function ShieldIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-8">
      <h2 className="text-base font-black text-gray-900 mb-2.5">{title}</h2>
      <div className="text-sm text-gray-600 leading-relaxed space-y-2.5">{children}</div>
    </section>
  );
}

export default function PrivacyPolicyPage() {
  return (
    <div className="min-h-screen" style={{ background: "#f8fafc" }}>
      <div className="max-w-2xl mx-auto py-16 px-4">

        {/* Header */}
        <div className="mb-12">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center text-white"
              style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)" }}>
              <ShieldIcon />
            </div>
            <div>
              <h1 className="text-2xl font-black text-gray-900">Privacy Policy</h1>
              <p className="text-sm text-gray-400">Last updated September 13, 2026</p>
            </div>
          </div>
          <p className="text-sm text-gray-500 leading-relaxed">
            This Privacy Policy explains what information TrustLedger ("TrustLedger," "we," "us") collects
            when you use our AI code governance platform, how we use it, and the choices you have.
          </p>
        </div>

        <Section title="1. Information We Collect">
          <p><strong>Account information.</strong> When you create an account, we collect your name, work email address, and — if you sign in with GitHub — your GitHub username, profile URL, and avatar. If you sign up with email and password, your password is stored by our authentication provider (Supabase Auth) in hashed form; we never see or store it in plain text.</p>
          <p><strong>Repository and source code data.</strong> Once you install our GitHub, GitLab, or Bitbucket integration, we receive pull request metadata (repository name, branch, commit SHA, author, diff statistics) and the contents of files changed in each pull request, so our scanner can analyse them. Scan results — risk scores, detected AI-generated code, flagged secrets, and vulnerable dependencies — are stored so you can review, attest, and report on them later.</p>
          <p><strong>Usage and diagnostic data.</strong> We collect product usage analytics (pages visited, features used) and error/crash diagnostics to operate and improve the service.</p>
          <p><strong>Payment information.</strong> If you subscribe to a paid plan, billing is handled by our payment processor; we do not store your full card number on our own servers.</p>
        </Section>

        <Section title="2. How We Use Your Information">
          <p>We use the information above to: operate the scanning, gating, and reporting features of the platform; authenticate you and enforce access controls; send you service notifications and security alerts you've configured (Slack, email, PagerDuty); generate the compliance evidence and audit reports you request; monitor and improve platform reliability and performance; and communicate with you about your account or the service.</p>
        </Section>

        <Section title="3. How We Handle Your Source Code">
          <p>Source code you submit for scanning is treated as confidential. It is used solely to provide the service to your organisation — to run our detection engine, generate risk scores, and produce the reports and dashboards you see. We do not use your source code to train third-party AI models, and we do not share it with other customers.</p>
          <p>Access to stored code and scan data is scoped per organisation with database-level access controls, so one customer's data is never visible to another. You can configure data retention windows and request deletion of historical scan data at any time (see Section 6).</p>
        </Section>

        <Section title="4. Third-Party Service Providers">
          <p>We rely on the following categories of subprocessors to operate TrustLedger. Each is bound by its own data processing terms:</p>
          <ul className="list-disc pl-5 space-y-1">
            <li><strong>Infrastructure &amp; database</strong> — Supabase (Postgres database, authentication) and Vercel (application hosting)</li>
            <li><strong>Queueing &amp; caching</strong> — Upstash (Redis cache, QStash job queue)</li>
            <li><strong>Source hosting integrations</strong> — GitHub, GitLab, and Bitbucket (only for repositories you explicitly connect)</li>
            <li><strong>Error monitoring &amp; analytics</strong> — Sentry and PostHog</li>
            <li><strong>Email delivery</strong> — SendGrid, for account and alert emails</li>
            <li><strong>Payments</strong> — our payment processor, for billing (paid plans only)</li>
          </ul>
        </Section>

        <Section title="5. Data Retention">
          <p>We retain scan and violation data for as long as your account is active, subject to any retention window you configure in Settings. Attested scans are kept as an immutable audit record and are not deleted, since their purpose is to provide durable proof of review. You can request full deletion of your organisation's account and associated data by contacting us or using the account deletion option in Settings; some records may be retained where we have a legal obligation to do so.</p>
        </Section>

        <Section title="6. Data Security">
          <p>We use encryption in transit (HTTPS/TLS) and at rest, HMAC-signed webhook verification, role-based access control, and an immutable audit log for security-sensitive actions. No method of transmission or storage is 100% secure, and we cannot guarantee absolute security.</p>
        </Section>

        <Section title="7. Your Rights and Choices">
          <p>Depending on your location, you may have the right to access, correct, export, or delete your personal data, and to object to or restrict certain processing. To exercise these rights, contact us at the email address below. We will respond within the timeframe required by applicable law.</p>
        </Section>

        <Section title="8. Cookies">
          <p>We use a small number of essential cookies to keep you signed in (via Supabase Auth) and, where analytics are enabled, a cookie to distinguish unique visitors. We do not use third-party advertising cookies.</p>
        </Section>

        <Section title="9. Children's Privacy">
          <p>TrustLedger is intended for business use and is not directed at children. We do not knowingly collect personal information from anyone under 16.</p>
        </Section>

        <Section title="10. Changes to This Policy">
          <p>We may update this policy from time to time. Material changes will be notified via email or an in-product notice before they take effect.</p>
        </Section>

        <Section title="11. Contact Us">
          <p>Questions about this policy or your data can be sent to{" "}
            <a href="mailto:privacy@trustledger.dev" className="text-indigo-600 hover:underline">privacy@trustledger.dev</a>.
          </p>
        </Section>

      </div>
    </div>
  );
}
