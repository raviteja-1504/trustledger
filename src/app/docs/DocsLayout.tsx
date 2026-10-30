import Link from "next/link";
import { SiteNav, SiteFooter, INK, BORDER, CYAN } from "@/components/marketing/Site";
import { DOCS_PAGES } from "./docsNav";

/** Docs chrome: the site nav, a page list on the left, the article on the right. */
export function DocsLayout({ slug, title, summary, children }: { slug?: string; title: string; summary?: string; children: React.ReactNode }) {
  return (
    <div className="min-h-screen text-white" style={{ background: INK }}>
      <SiteNav active="/docs" />
      <div className="max-w-6xl mx-auto px-5 pt-28 pb-16 grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-10">
        <nav aria-label="Documentation" className="lg:sticky lg:top-24 self-start">
          <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-white/45 font-mono mb-3"><Link href="/docs">Documentation</Link></p>
          <ul className="space-y-1">
            {DOCS_PAGES.map(p => (
              <li key={p.slug}>
                <Link href={`/docs/${p.slug}`} aria-current={p.slug === slug ? "page" : undefined}
                  className="block text-sm px-2.5 py-1.5 rounded-md transition-colors"
                  style={p.slug === slug ? { color: "#fff", background: `${CYAN}1a`, boxShadow: `inset 2px 0 0 ${CYAN}` } : { color: "rgba(255,255,255,0.6)" }}>{p.title}</Link>
              </li>
            ))}
          </ul>
        </nav>
        <article className="min-w-0 max-w-3xl docs-prose">
          <h1 className="text-3xl sm:text-4xl font-black tracking-tight" style={{ textWrap: "balance" }}>{title}</h1>
          {summary && <p className="text-white/60 mt-2 text-lg">{summary}</p>}
          <div className="mt-8 space-y-5 text-[15px] leading-relaxed text-white/75">{children}</div>
        </article>
      </div>
      <style>{`
        .docs-prose h2 { color: #fff; font-weight: 800; font-size: 1.35rem; margin-top: 2.2rem; letter-spacing: -0.01em; }
        .docs-prose h3 { color: #fff; font-weight: 700; font-size: 1.05rem; margin-top: 1.4rem; }
        .docs-prose ul { list-style: disc; padding-left: 1.25rem; }
        .docs-prose ol { list-style: decimal; padding-left: 1.25rem; }
        .docs-prose li { margin: 0.3rem 0; }
        .docs-prose a { color: #a5f3fc; text-decoration: underline; text-underline-offset: 3px; }
        .docs-prose code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.86em; color: #e2e8f0; background: rgba(255,255,255,0.07); padding: 0.1em 0.35em; border-radius: 4px; }
        .docs-prose pre { background: rgba(255,255,255,0.04); border: 1px solid ${BORDER}; border-radius: 12px; padding: 1rem; overflow-x: auto; }
        .docs-prose pre code { background: none; padding: 0; }
        .docs-prose table { width: 100%; font-size: 13px; }
        .docs-prose th { text-align: left; color: rgba(255,255,255,0.5); font-weight: 600; padding: 0.5rem 0.75rem; }
        .docs-prose td { padding: 0.45rem 0.75rem; border-top: 1px solid ${BORDER}; vertical-align: top; }
      `}</style>
      <SiteFooter />
    </div>
  );
}
