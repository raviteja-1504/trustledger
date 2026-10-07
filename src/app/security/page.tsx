"use client";

/**
 * Public security page — no auth required. Accessible at /security; /.well-known/security.txt points here as
 * its Policy. The contact comes from lib/securityContact.ts (NEXT_PUBLIC_SECURITY_CONTACT).
 */

import { BrandMark } from "@/components/BrandLogo";
import { securityContact, SECURITY_ACK_BUSINESS_DAYS } from "@/lib/securityContact";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-8">
      <h2 className="text-base font-black text-gray-900 mb-2.5">{title}</h2>
      <div className="text-sm text-gray-600 leading-relaxed space-y-2.5">{children}</div>
    </section>
  );
}

export default function SecurityPage() {
  const contact = securityContact();
  const mail = <a href={`mailto:${contact}`} className="text-indigo-600 hover:underline font-semibold">{contact}</a>;
  return (
    <div className="min-h-screen" style={{ background: "#f8fafc" }}>
      <div className="max-w-2xl mx-auto py-16 px-4">

        <div className="mb-12">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: "#050810" }}>
              <BrandMark size={30} />
            </div>
            <div>
              <h1 className="text-2xl font-black text-gray-900">Security</h1>
              <p className="text-sm text-gray-400">Vulnerability disclosure and incident response</p>
            </div>
          </div>
          <p className="text-sm text-gray-500 leading-relaxed">
            Customers trust TrustLedger with their private source code. If you believe you have found a security
            vulnerability in TrustLedger, or you are a customer who suspects a security incident affecting your
            account, please tell us.
          </p>
        </div>

        <Section title="Reporting a vulnerability">
          <p>Email {mail}. Please include:</p>
          <ul className="list-disc pl-5 space-y-1">
            <li>what you found and where (URL, API endpoint, or component);</li>
            <li>steps to reproduce, and a proof of concept if you have one;</li>
            <li>the impact you believe it has;</li>
            <li>how we can reach you for follow-up questions.</li>
          </ul>
          <p>Please do not report security issues through public GitHub issues, social media, or support chat.</p>
        </Section>

        <Section title="What to expect from us">
          <ul className="list-disc pl-5 space-y-1">
            <li>An acknowledgement within <strong>{SECURITY_ACK_BUSINESS_DAYS} business days</strong>.</li>
            <li>An initial assessment and severity rating within 10 business days.</li>
            <li>Updates as we work on a fix, and a note when it is deployed.</li>
            <li>Credit in our release notes if you would like it, once the issue is fixed.</li>
          </ul>
          <p>We do not currently run a paid bug bounty programme.</p>
        </Section>

        <Section title="Safe harbour">
          <p>
            We will not pursue legal action against, or ask law enforcement to investigate, anyone who researches
            and reports a vulnerability in good faith and within these guidelines:
          </p>
          <ul className="list-disc pl-5 space-y-1">
            <li>only test against accounts and organisations you own or have permission to test;</li>
            <li>access no more data than needed to demonstrate the issue, and never another customer&apos;s source code or findings — stop and report as soon as you can see data that isn&apos;t yours;</li>
            <li>do not degrade the service for others (no denial-of-service or high-volume automated testing);</li>
            <li>give us a reasonable time to fix the issue — normally up to 90 days — before disclosing it publicly.</li>
          </ul>
        </Section>

        <Section title="Scope">
          <p><strong>In scope:</strong> this web application and its API, the TrustLedger GitHub App, and the scanning pipeline.</p>
          <p><strong>Out of scope:</strong> social engineering or phishing of our staff or customers; physical attacks; denial-of-service;
            vulnerabilities in third-party services we use (report those to the vendor); and reports that only point out a missing
            best practice without a demonstrated security impact.</p>
        </Section>

        <Section title="Security incidents and customer notification">
          <p>
            If we confirm a security incident that affects a customer&apos;s data, we notify that customer&apos;s account
            administrators by email without undue delay — and within 72 hours of confirming it — with what happened,
            what data was involved, what we have done, and what they should do. We follow up as our investigation
            progresses.
          </p>
          <p>Customers who suspect an incident affecting their TrustLedger account should report it to {mail}.</p>
        </Section>

        <Section title="How we protect your data">
          <ul className="list-disc pl-5 space-y-1">
            <li><strong>Encryption:</strong> HTTPS everywhere (HSTS); data at rest is encrypted by our database provider; two-factor secrets are additionally encrypted (AES-256-GCM) and backup codes are stored only as salted hashes.</li>
            <li><strong>Tenant isolation:</strong> every organisation&apos;s data is separated by database row-level security, and an automated check fails our build if a server query is not limited to one organisation.</li>
            <li><strong>Access control:</strong> role-based permissions checked on every API write, SAML single sign-on, two-factor authentication, and SCIM deprovisioning.</li>
            <li><strong>Audit log:</strong> sign-ins, repository changes, data exports, attestations and administrative actions are recorded in a tamper-evident, hash-chained log.</li>
            <li><strong>Scanning:</strong> your code is analysed as text — it is never executed — and the scanner has hard limits so a malicious file cannot crash or stall it.</li>
          </ul>
        </Section>

        <p className="text-xs text-gray-400">
          Machine-readable contact details: <a href="/.well-known/security.txt" className="hover:underline">/.well-known/security.txt</a>
        </p>

      </div>
    </div>
  );
}
