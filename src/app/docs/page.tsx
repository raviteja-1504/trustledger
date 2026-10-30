import type { Metadata } from "next";
import Link from "next/link";
import { DocsLayout } from "./DocsLayout";
import { DOCS_PAGES } from "./docsNav";
import { BORDER, CYAN } from "@/components/marketing/Site";

export const metadata: Metadata = {
  title: "Documentation — TrustLedger",
  description: "How TrustLedger works: setup, engine architecture, language and vulnerability coverage, taint analysis, AI attribution, pull-request integration, attestation and the API.",
};

export default function DocsHome() {
  return (
    <DocsLayout title="Documentation" summary="How TrustLedger analyses pull requests, what it covers, where its limits are, and how to integrate it.">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 not-prose">
        {DOCS_PAGES.map(p => (
          <Link key={p.slug} href={`/docs/${p.slug}`} className="rounded-xl border p-4 transition-colors hover:bg-white/5" style={{ borderColor: BORDER, textDecoration: "none" }}>
            <span className="block font-bold" style={{ color: CYAN }}>{p.title}</span>
            <span className="block text-sm text-white/60 mt-1">{p.summary}</span>
          </Link>
        ))}
      </div>
    </DocsLayout>
  );
}
