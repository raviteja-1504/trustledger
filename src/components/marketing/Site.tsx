/**
 * Shared chrome for the public site (landing page, demo, benchmarks, docs, trust center, blog, roadmap): the same
 * near-black, cyan-accented palette the landing page introduced, as server-renderable components (no hooks), so a
 * page can stay a server component and still share the nav and footer.
 */
import Link from "next/link";
import { BrandLogo, BrandWordmark } from "@/components/BrandLogo";
import { contactEmail } from "@/lib/contacts";

export const INK = "#050810";
export const SURFACE = "#0a0f1c";
export const CYAN = "#22d3ee";
export const ROSE = "#fb7185";
export const AMBER = "#fbbf24";
export const ORANGE = "#fb923c";
export const VIOLET = "#a78bfa";
export const EMERALD = "#34d399";
export const SKY = "#38bdf8";
export const BORDER = "rgba(255,255,255,0.09)";

export const SITE_LINKS = [
  { label: "Product", href: "/" },
  { label: "Live demo", href: "/demo" },
  { label: "Benchmarks", href: "/benchmarks" },
  { label: "Docs", href: "/docs" },
  { label: "Trust Center", href: "/trust" },
  { label: "Blog", href: "/blog" },
];

export function SiteNav({ active }: { active?: string }) {
  return (
    <header className="fixed top-0 inset-x-0 z-50 border-b" style={{ borderColor: BORDER, background: "rgba(5,8,16,0.86)", backdropFilter: "blur(16px) saturate(160%)" }}>
      <div className="max-w-6xl mx-auto px-5 h-14 flex items-center justify-between gap-4">
        <Link href="/" aria-label="TrustLedger home" className="flex items-center shrink-0">
          <BrandWordmark height={32} />
        </Link>
        <nav aria-label="Main" className="hidden lg:flex items-center gap-6">
          {SITE_LINKS.slice(1).map(l => (
            <Link key={l.href} href={l.href} aria-current={active === l.href ? "page" : undefined}
              className="text-sm font-medium transition-colors"
              style={{ color: active === l.href ? "#fff" : "rgba(255,255,255,0.65)" }}>{l.label}</Link>
          ))}
        </nav>
        <div className="flex items-center gap-1 sm:gap-2 shrink-0">
          <Link href="/login" className="whitespace-nowrap text-sm font-semibold text-white/70 hover:text-white transition-colors px-2 sm:px-3 py-1.5">Sign in</Link>
          <Link href="/demo" className="whitespace-nowrap text-sm font-bold px-3 sm:px-3.5 py-1.5 rounded-lg text-[#050810]" style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 2px 18px ${CYAN}66` }}>
            Try the demo
          </Link>
        </div>
      </div>
      {/* small screens: the same links, scrollable */}
      <nav aria-label="Main (mobile)" className="lg:hidden flex gap-5 overflow-x-auto px-5 pb-2 -mt-1 text-[13px]">
        {SITE_LINKS.slice(1).map(l => (
          <Link key={l.href} href={l.href} className="whitespace-nowrap font-medium" style={{ color: active === l.href ? "#fff" : "rgba(255,255,255,0.6)" }}>{l.label}</Link>
        ))}
      </nav>
    </header>
  );
}

const FOOTER_COLUMNS: { title: string; links: { label: string; href: string }[] }[] = [
  { title: "Product", links: [{ label: "Overview", href: "/" }, { label: "Live demo", href: "/demo" }, { label: "Dashboard", href: "/dashboard" }, { label: "Pricing & sign up", href: "/login?mode=signup" }] },
  { title: "Evidence", links: [{ label: "Benchmark report", href: "/benchmarks" }, { label: "Coverage matrix", href: "/docs/coverage" }, { label: "Changelog", href: "/changelog" }, { label: "Roadmap", href: "/roadmap" }] },
  { title: "Resources", links: [{ label: "Documentation", href: "/docs" }, { label: "API reference", href: "/docs/api" }, { label: "Blog", href: "/blog" }, { label: "System status", href: "/status" }] },
  { title: "Trust", links: [{ label: "Trust Center", href: "/trust" }, { label: "Security & disclosure", href: "/security" }, { label: "Privacy", href: "/privacy" }, { label: "Terms", href: "/terms" }] },
];

export function SiteFooter() {
  return (
    <footer className="py-12 px-5 border-t" style={{ borderColor: BORDER, background: INK }}>
      <div className="max-w-6xl mx-auto flex flex-col lg:flex-row items-start justify-between gap-10">
        <div className="max-w-xs">
          <BrandLogo height={52} className="mb-3" />
          <p className="text-xs text-white/45 leading-relaxed">Data-flow security engines, AI provenance and auditable merge decisions for every pull request.</p>
          <p className="text-xs text-white/45 mt-3">Contact: <a href={`mailto:${contactEmail("hello")}`} className="text-white/70 hover:text-white underline underline-offset-2">{contactEmail("hello")}</a></p>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-8 text-sm">
          {FOOTER_COLUMNS.map(c => (
            <div key={c.title}>
              <p className="font-bold text-white/60 text-xs uppercase tracking-wider mb-3">{c.title}</p>
              <ul className="space-y-2">
                {c.links.map(l => <li key={l.href}><Link href={l.href} className="text-white/45 hover:text-white/80 transition-colors">{l.label}</Link></li>)}
              </ul>
            </div>
          ))}
        </div>
      </div>
      <div className="max-w-6xl mx-auto mt-10 pt-6 border-t flex flex-col sm:flex-row items-center justify-between gap-3" style={{ borderColor: "rgba(255,255,255,0.14)" }}>
        <p className="text-xs text-white/40">© 2026 TrustLedger. All rights reserved.</p>
        <Link href="/status" className="flex items-center gap-1.5 text-xs text-white/40 hover:text-white/70 transition-colors"><span className="w-1.5 h-1.5 rounded-full" style={{ background: EMERALD }} />System status</Link>
      </div>
    </footer>
  );
}

export function Eyebrow({ children, color = CYAN }: { children: React.ReactNode; color?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-[0.14em] px-3 py-1.5 rounded-full border font-mono" style={{ color, background: `${color}1c`, borderColor: `${color}4d` }}>
      {children}
    </span>
  );
}

/** Page wrapper: nav, a header block, the page's sections, footer. */
export function SitePage({ active, eyebrow, title, lede, children, eyebrowColor }: {
  active?: string; eyebrow?: string; title: React.ReactNode; lede?: React.ReactNode; children: React.ReactNode; eyebrowColor?: string;
}) {
  return (
    <div className="min-h-screen text-white" style={{ background: INK }}>
      <SiteNav active={active} />
      <header className="relative px-5 pt-32 pb-12 overflow-hidden" style={{ background: `radial-gradient(ellipse 80% 60% at 50% 0%, ${eyebrowColor ?? CYAN}14, transparent 62%), ${INK}` }}>
        <div className="max-w-6xl mx-auto space-y-4">
          {eyebrow && <Eyebrow color={eyebrowColor}>{eyebrow}</Eyebrow>}
          <h1 className="text-4xl sm:text-5xl font-black tracking-tight leading-[1.08] max-w-4xl" style={{ textWrap: "balance" }}>{title}</h1>
          {lede && <div className="text-base sm:text-lg text-white/65 max-w-3xl leading-relaxed">{lede}</div>}
        </div>
      </header>
      <main>{children}</main>
      <SiteFooter />
    </div>
  );
}

export function Section({ id, title, intro, children, tone = "ink" }: { id?: string; title?: React.ReactNode; intro?: React.ReactNode; children: React.ReactNode; tone?: "ink" | "surface" }) {
  return (
    <section id={id} className="px-5 py-14 border-t scroll-mt-20" style={{ borderColor: BORDER, background: tone === "surface" ? SURFACE : INK }}>
      <div className="max-w-6xl mx-auto">
        {title && <h2 className="text-2xl sm:text-3xl font-black tracking-tight mb-3" style={{ textWrap: "balance" }}>{title}</h2>}
        {intro && <div className="text-white/60 max-w-3xl leading-relaxed mb-8">{intro}</div>}
        {children}
      </div>
    </section>
  );
}

export function Card({ children, className = "", accent }: { children: React.ReactNode; className?: string; accent?: string }) {
  return (
    <div className={`rounded-2xl border p-5 ${className}`} style={{ borderColor: accent ? `${accent}40` : BORDER, background: "rgba(255,255,255,0.03)" }}>
      {children}
    </div>
  );
}

export function Pill({ children, color = CYAN }: { children: React.ReactNode; color?: string }) {
  return <span className="inline-flex items-center text-[10.5px] font-bold uppercase tracking-wide px-2 py-0.5 rounded font-mono whitespace-nowrap" style={{ color, background: `${color}1a`, border: `1px solid ${color}38` }}>{children}</span>;
}

/** A horizontally scrollable table wrapper -- wide tables scroll inside, the page body never does. */
export function TableWrap({ children }: { children: React.ReactNode }) {
  return <div className="overflow-x-auto rounded-xl border" style={{ borderColor: BORDER }}>{children}</div>;
}
