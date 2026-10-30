import type { Metadata } from "next";
import Link from "next/link";
import { SitePage, Section, Card, CYAN } from "@/components/marketing/Site";
import { POSTS } from "./posts";

export const metadata: Metadata = {
  title: "Blog — TrustLedger",
  description: "Engineering notes on how the TrustLedger engines detect vulnerabilities, what we measure, and what we got wrong.",
};

export default function BlogIndex() {
  return (
    <SitePage active="/blog" eyebrow="Engineering notes" title="How the engines work, and what we learn building them"
      lede="Technical write-ups of real engine changes, with the numbers behind them — including the mistakes.">
      <Section>
        <div className="grid grid-cols-1 gap-4 max-w-3xl">
          {POSTS.map(p => (
            <Link key={p.slug} href={`/blog/${p.slug}`} className="block">
              <Card>
                <p className="text-[11px] font-mono text-white/45">{p.date}</p>
                <p className="text-lg font-bold mt-1" style={{ color: CYAN }}>{p.title}</p>
                <p className="text-sm text-white/65 mt-1.5">{p.summary}</p>
              </Card>
            </Link>
          ))}
        </div>
      </Section>
    </SitePage>
  );
}
