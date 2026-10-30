import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { DocsLayout } from "../DocsLayout";
import { DOCS_PAGES } from "../docsNav";
import { DOCS_CONTENT } from "../content";

type Params = { slug: string };

export function generateStaticParams(): Params[] {
  return DOCS_PAGES.filter(p => p.slug !== "api").map(p => ({ slug: p.slug }));
}

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const { slug } = await params;
  const page = DOCS_PAGES.find(p => p.slug === slug);
  return page ? { title: `${page.title} — TrustLedger docs`, description: page.summary } : {};
}

export default async function DocsArticle({ params }: { params: Promise<Params> }) {
  const { slug } = await params;
  const page = DOCS_PAGES.find(p => p.slug === slug);
  const Content = (DOCS_CONTENT as Record<string, (() => React.ReactNode) | undefined>)[slug];
  if (!page || !Content) notFound();
  const i = DOCS_PAGES.findIndex(p => p.slug === slug);
  const next = DOCS_PAGES[i + 1];
  return (
    <DocsLayout slug={slug} title={page.title} summary={page.summary}>
      <Content />
      {next && <p className="pt-8 border-t" style={{ borderColor: "rgba(255,255,255,0.09)" }}>Next: <Link href={`/docs/${next.slug}`}>{next.title} →</Link></p>}
    </DocsLayout>
  );
}
