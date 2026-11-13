import type { Metadata } from "next";
import Link from "next/link";
import { SitePage, Section, Card, CYAN, EMERALD, AMBER, ROSE, VIOLET } from "@/components/marketing/Site";
import { contactEmail } from "@/lib/contacts";

export const metadata: Metadata = {
  title: "Contact and feedback — TrustLedger",
  description: "Book a demo, ask about pricing, report a false positive or a missed vulnerability, request a feature or tell us something is not working.",
};

/** A mailto link with the subject and a short template filled in, so the message arrives with what is needed to act on it. */
const mail = (subject: string, body: string) => `mailto:${contactEmail("sales")}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

const ACTIONS: Array<{ color: string; title: string; text: string; cta: string; href: string }> = [
  {
    color: CYAN, title: "Book a demo or ask about pricing",
    text: "A walk-through on your own code, or questions about plans, limits and what comes after the free trial.",
    cta: "Request a demo",
    href: mail("TrustLedger demo / pricing", "Hi,\n\nI'd like a demo / to ask about pricing.\n\nTeam size:\nLanguages and frameworks:\nSource host (GitHub, GitLab, Bitbucket):\nWhat we want to achieve:\n"),
  },
  {
    color: AMBER, title: "Report a false positive",
    text: "A finding that is not a real vulnerability. Every one we get makes the engines more precise.",
    cta: "Report a false positive",
    href: mail("False positive", "Hi,\n\nThis finding is not a real vulnerability.\n\nFinding (rule name and CWE):\nFile and line:\nLanguage / framework:\nWhy it is safe (a validation, a framework protection, test code...):\n\n(Please do not paste secrets or proprietary code you cannot share. The finding's source-to-sink trace from the pull request page is enough.)\n"),
  },
  {
    color: ROSE, title: "Report a missed vulnerability",
    text: "A real vulnerability TrustLedger did not report. Tell us the language and how the value reaches the dangerous call.",
    cta: "Report a miss",
    href: mail("Missed vulnerability", "Hi,\n\nTrustLedger did not report this vulnerability.\n\nType (SQL injection, XSS, SSRF...):\nLanguage / framework:\nWhere the input comes from and where it ends up (a few lines are enough):\n"),
  },
  {
    color: VIOLET, title: "Request a feature",
    text: "A language, framework, integration or report you need. Tell us the problem you are trying to solve.",
    cta: "Request a feature",
    href: mail("Feature request", "Hi,\n\nI'd like TrustLedger to...\n\nThe problem it would solve for us:\n"),
  },
  {
    color: EMERALD, title: "Something is not working",
    text: "A pull request that was not scanned, a check that did not appear, or a page that fails. The details below let us find it quickly.",
    cta: "Report a problem",
    href: mail("Problem report", "Hi,\n\nSomething is not working.\n\nWhat I expected:\nWhat happened:\nPull request link:\nGitHub delivery ID (GitHub App > Advanced > Recent Deliveries), if you have it:\nThe TrustLedger account (email) I was signed in with:\n"),
  },
];

export default function ContactPage() {
  const email = contactEmail("sales");
  return (
    <SitePage active="/contact" eyebrow="Contact and feedback" eyebrowColor={CYAN} title="Talk to the team behind TrustLedger"
      lede={<>Demos, pricing, false positives, missed vulnerabilities, feature requests and problems all come to one inbox: <a className="underline underline-offset-2 text-white/85" href={`mailto:${email}`}>{email}</a>. Pick the closest option below and the email opens with the details we need.</>}>
      <Section>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {ACTIONS.map(a => (
            <Card key={a.title}>
              <p className="font-bold text-white">{a.title}</p>
              <p className="text-[13px] text-white/60 mt-1.5 leading-relaxed">{a.text}</p>
              <a href={a.href} className="inline-block mt-3 text-sm font-semibold rounded-lg px-3.5 py-2 border" style={{ color: a.color, borderColor: `${a.color}55`, background: `${a.color}12` }}>
                {a.cta} →
              </a>
            </Card>
          ))}
        </div>
        <p className="text-[13px] text-white/50 mt-6 leading-relaxed">
          Reporting a security vulnerability in TrustLedger itself? Use the <Link href="/security" className="underline underline-offset-2 text-white/70">security page</Link> instead.
          Looking for an answer first? Try <Link href="/docs/troubleshooting" className="underline underline-offset-2 text-white/70">troubleshooting</Link> and the{" "}
          <Link href="/docs/getting-started" className="underline underline-offset-2 text-white/70">getting started guide</Link>.
          If the buttons do not open your email program, write to <span className="font-mono text-white/70">{email}</span> directly.
        </p>
      </Section>
    </SitePage>
  );
}
