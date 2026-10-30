import type { Metadata } from "next";
import { SitePage, Section, Card, CYAN, EMERALD, AMBER } from "@/components/marketing/Site";
import DemoClient from "./DemoClient";
import { DemoVideos } from "@/components/marketing/DemoVideos";

export const metadata: Metadata = {
  title: "Live demo — TrustLedger",
  description: "Run the real TrustLedger engine on deliberately vulnerable sample code: see the source-to-sink trace, the merge-gate decision, the fix and the rescan.",
};

export default function DemoPage() {
  return (
    <SitePage active="/demo" eyebrow="Live · real engine · sandboxed" title="See a vulnerability traced, gated and fixed"
      lede={<>Every result on this page comes from the actual TrustLedger scanner running on sample applications — the same engine that checks pull requests. Pick a sample, scan it, follow the data flow from the untrusted input to the dangerous call, then apply the fix and rescan.</>}>
      <Section>
        <DemoClient />
      </Section>
      <Section title="What is real here, and what is simulated" tone="surface">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card accent={EMERALD}>
            <p className="font-bold text-white mb-1.5">Real</p>
            <p className="text-sm text-white/65">The scan: findings, traces, CWE mapping, risk level, AI-generated estimate and content hash come from running the production scanner on the sample&apos;s files, in the request you make.</p>
          </Card>
          <Card accent={CYAN}>
            <p className="font-bold text-white mb-1.5">Real, with the default policy</p>
            <p className="text-sm text-white/65">The merge decision uses the product&apos;s merge-gate rule with its default settings — CRITICAL and HIGH files block until attested. Organisations can change these settings.</p>
          </Card>
          <Card accent={AMBER}>
            <p className="font-bold text-white mb-1.5">Simulated</p>
            <p className="text-sm text-white/65">The reviewer sign-off: it is kept in your browser to show how an attestation is tied to a file&apos;s exact content. Nothing about your visit or your edits is stored.</p>
          </Card>
        </div>
      </Section>
      <Section id="videos" title="Walkthrough videos" intro="Short recordings of this demo running against the real engine. Captions are included.">
        <DemoVideos />
      </Section>
    </SitePage>
  );
}
