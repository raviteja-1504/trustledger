import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { SiteNav, SiteFooter, INK, BORDER } from "@/components/marketing/Site";
import { POSTS } from "../posts";

type Params = { slug: string };

export function generateStaticParams(): Params[] {
  return POSTS.map(p => ({ slug: p.slug }));
}

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const { slug } = await params;
  const post = POSTS.find(p => p.slug === slug);
  return post ? { title: `${post.title} — TrustLedger`, description: post.summary } : {};
}

export default async function BlogPost({ params }: { params: Promise<Params> }) {
  const { slug } = await params;
  const post = POSTS.find(p => p.slug === slug);
  if (!post) notFound();
  const Body = post.body;
  return (
    <div className="min-h-screen text-white" style={{ background: INK }}>
      <SiteNav active="/blog" />
      <article className="max-w-3xl mx-auto px-5 pt-32 pb-16 post-prose">
        <p className="text-[12px] font-mono text-white/45"><Link href="/blog">Blog</Link> · {post.date}</p>
        <h1 className="text-3xl sm:text-4xl font-black tracking-tight mt-2" style={{ textWrap: "balance" }}>{post.title}</h1>
        <p className="text-lg text-white/60 mt-3">{post.summary}</p>
        <div className="mt-8 space-y-5 text-[15.5px] leading-relaxed text-white/75"><Body /></div>
      </article>
      <style>{`
        .post-prose h2 { color: #fff; font-weight: 800; font-size: 1.35rem; margin-top: 2.2rem; }
        .post-prose a { color: #a5f3fc; text-decoration: underline; text-underline-offset: 3px; }
        .post-prose code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.86em; color: #e2e8f0; background: rgba(255,255,255,0.07); padding: 0.1em 0.35em; border-radius: 4px; }
        .post-prose pre { background: rgba(255,255,255,0.04); border: 1px solid ${BORDER}; border-radius: 12px; padding: 1rem; overflow-x: auto; font-size: 13px; }
        .post-prose pre code { background: none; padding: 0; }
      `}</style>
      <SiteFooter />
    </div>
  );
}
