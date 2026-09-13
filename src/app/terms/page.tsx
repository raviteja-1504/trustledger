"use client";

/**
 * Public Terms of Service — no auth required.
 * Accessible at /terms.
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

export default function TermsOfServicePage() {
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
              <h1 className="text-2xl font-black text-gray-900">Terms of Service</h1>
              <p className="text-sm text-gray-400">Last updated September 13, 2026</p>
            </div>
          </div>
          <p className="text-sm text-gray-500 leading-relaxed">
            These Terms of Service ("Terms") govern your access to and use of TrustLedger's AI code
            governance platform (the "Service"). By creating an account or using the Service, you agree
            to these Terms.
          </p>
        </div>

        <Section title="1. The Service">
          <p>TrustLedger scans pull requests for AI-generated code, hardcoded secrets, and vulnerable dependencies; applies policy gates you configure; records reviewer attestations; and generates supporting evidence for compliance frameworks such as SOC 2, PCI-DSS, and the EU AI Act.</p>
        </Section>

        <Section title="2. Accounts and Registration">
          <p>You must provide accurate registration information and are responsible for maintaining the confidentiality of your account credentials and for all activity under your account. Notify us promptly of any unauthorised use.</p>
        </Section>

        <Section title="3. Acceptable Use">
          <p>You agree not to: submit source code you do not have the right to share with us; attempt to bypass rate limits, policy gates, or access controls; reverse engineer or attempt to extract our detection models or source code; or use the Service to build a competing product. We may suspend accounts that violate this section.</p>
        </Section>

        <Section title="4. Your Content and Data Ownership">
          <p>You retain all ownership rights to the source code, repository data, and other content you submit ("Your Content"). You grant us a limited licence to process Your Content solely to provide and improve the Service to you. We do not claim ownership of Your Content and do not use it to train models for other customers.</p>
        </Section>

        <Section title="5. Subscriptions and Fees">
          <p>TrustLedger is currently offered on a beta basis. Pricing and paid plans, when introduced, will be described separately and will not apply retroactively without notice. We will give reasonable advance notice before introducing or changing fees for your account.</p>
        </Section>

        <Section title="6. Third-Party Integrations">
          <p>The Service integrates with third-party platforms (including GitHub, GitLab, Bitbucket, Slack, and Jira/Linear) that you choose to connect. Your use of those platforms is governed by their own terms, and we are not responsible for their availability or conduct.</p>
        </Section>

        <Section title="7. Disclaimers">
          <p>The Service is provided "as is" and "as available." TrustLedger helps identify risk signals in code and supports your compliance workflow, but it does not guarantee the detection of every AI-generated code pattern, security vulnerability, or dependency risk, and it does not constitute legal, security, or compliance advice or certification. You remain responsible for your own security, legal, and compliance obligations.</p>
        </Section>

        <Section title="8. Limitation of Liability">
          <p>To the maximum extent permitted by law, TrustLedger will not be liable for any indirect, incidental, special, or consequential damages, or for any loss of data, revenue, or profits, arising from your use of the Service. Our total liability for any claim relating to the Service is limited to the amount you paid us in the 12 months preceding the claim.</p>
        </Section>

        <Section title="9. Termination">
          <p>You may stop using the Service and delete your account at any time. We may suspend or terminate accounts that violate these Terms or pose a security risk to the Service or other customers. Upon termination, we will handle your data as described in our Privacy Policy.</p>
        </Section>

        <Section title="10. Changes to These Terms">
          <p>We may update these Terms from time to time. Material changes will be notified via email or an in-product notice before they take effect. Continued use of the Service after changes take effect constitutes acceptance of the updated Terms.</p>
        </Section>

        <Section title="11. Contact Us">
          <p>Questions about these Terms can be sent to{" "}
            <a href="mailto:hello@trustledger.dev" className="text-indigo-600 hover:underline">hello@trustledger.dev</a>.
          </p>
        </Section>

      </div>
    </div>
  );
}
