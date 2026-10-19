"use client";

/**
 * The first thing on the dashboard: what needs someone's action now, worst first -- files past their fix deadline,
 * critical secrets, CRITICAL/HIGH files awaiting attestation, repos awaiting sign-off, unapproved AI tools -- each
 * naming the actual files and repos, linking straight to where they're fixed. Built only from loaded data; a source
 * that hasn't loaded contributes nothing (never a guessed item).
 */
import Link from "next/link";

export type AttentionSeverity = "critical" | "high" | "medium";

export interface AttentionLink { label: string; href: string; note?: string }

export interface AttentionItem {
  key: string;
  severity: AttentionSeverity;
  title: string;
  detail: string;
  href: string;
  cta: string;
  /** The specific files / repos behind the count (first few). */
  links?: AttentionLink[];
  more?: number;
}

interface FileRef { file: string; scanId: string; repo: string; overdueHours?: number | null }

export interface AttentionInput {
  slaOverdue: number;
  /** Overdue files, oldest first. */
  overdueFiles: FileRef[];
  unreviewedCritical: FileRef[];
  unreviewedHigh: FileRef[];
  awaitingRepos: Array<{ repoName: string; scanId: string }>;
  openCriticalSecrets: number | null;
  openOtherSecrets: number | null;
  unapprovedAiTools: number | null;
  /** Evidence checks (lib/controlEvidence.ts) whose status is "fail" -- counted once, not per framework. */
  failingControls: number | null;
}

const SHOW = 3;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const attestHref = (f: FileRef) => `/pr/${f.scanId}?attest=${encodeURIComponent(f.file)}`;
const base = (p: string) => p.split("/").pop() ?? p;
const overdue = (h: number) => h >= 48 ? `${Math.floor(h / 24)}d overdue` : `${h}h overdue`;

function fileLinks(files: FileRef[], withOverdue = false): Pick<AttentionItem, "links" | "more"> {
  return {
    links: files.slice(0, SHOW).map(f => ({
      label: base(f.file), href: attestHref(f),
      note: withOverdue && f.overdueHours != null ? overdue(f.overdueHours) : base(f.repo),
    })),
    more: Math.max(0, files.length - SHOW),
  };
}

/** Items in priority order: they are added worst first. */
export function buildAttention(a: AttentionInput): AttentionItem[] {
  const items: AttentionItem[] = [];
  if (a.slaOverdue > 0) items.push({
    key: "sla", severity: "critical", title: `${plural(a.slaOverdue, "file")} past the fix deadline`,
    detail: "HIGH/CRITICAL findings beyond their SLA", href: "/sla", cta: "SLA",
    ...fileLinks(a.overdueFiles, true),
  });
  if (a.openCriticalSecrets) items.push({
    key: "secrets-critical", severity: "critical", title: `${plural(a.openCriticalSecrets, "critical secret")} exposed in code`,
    detail: "Rotate the credential, then resolve the finding", href: "/secrets", cta: "Secrets",
  });
  if (a.unreviewedCritical.length > 0) items.push({
    key: "critical", severity: "critical", title: `${plural(a.unreviewedCritical.length, "CRITICAL file")} awaiting attestation`,
    detail: "Merges are held until a reviewer signs off", href: "/violations", cta: "All",
    ...fileLinks(a.unreviewedCritical),
  });
  if (a.awaitingRepos.length > 0) items.push({
    key: "repos", severity: "high", title: `${plural(a.awaitingRepos.length, "repo")} pending sign-off`,
    detail: "Latest scan has HIGH/CRITICAL files nobody has signed off", href: "/violations", cta: "All",
    links: a.awaitingRepos.slice(0, SHOW).map(r => ({ label: r.repoName, href: `/pr/${r.scanId}` })),
    more: Math.max(0, a.awaitingRepos.length - SHOW),
  });
  if (a.unreviewedHigh.length > 0) items.push({
    key: "high", severity: "high", title: `${plural(a.unreviewedHigh.length, "HIGH-risk file")} awaiting attestation`,
    detail: "Waiting in the review queue", href: "/violations", cta: "All",
    ...fileLinks(a.unreviewedHigh),
  });
  if (a.unapprovedAiTools) items.push({
    key: "ai", severity: "high", title: `${plural(a.unapprovedAiTools, "unapproved AI tool detection")} open`,
    detail: "AI tools outside your approved list", href: "/shadow-ai", cta: "Triage",
  });
  if (a.openOtherSecrets) items.push({
    key: "secrets", severity: "medium", title: `${plural(a.openOtherSecrets, "secret")} open`,
    detail: "HIGH/MEDIUM credentials found in code", href: "/secrets", cta: "Secrets",
  });
  if (a.failingControls) items.push({
    key: "controls", severity: "medium", title: `${plural(a.failingControls, "audit evidence check")} failing`,
    detail: "A gap your auditor will see in the evidence", href: "/compliance", cta: "Gaps",
  });
  return items;
}

const STYLE: Record<AttentionSeverity, { dot: string; bg: string; ring: string; title: string; chip: string }> = {
  critical: { dot: "bg-rose-500",  bg: "bg-rose-50/70",  ring: "ring-rose-100",  title: "text-rose-900",  chip: "bg-white ring-rose-200 text-rose-800 hover:bg-rose-50" },
  high:     { dot: "bg-amber-500", bg: "bg-amber-50/70", ring: "ring-amber-100", title: "text-amber-900", chip: "bg-white ring-amber-200 text-amber-800 hover:bg-amber-50" },
  medium:   { dot: "bg-slate-400", bg: "bg-slate-50",    ring: "ring-slate-100", title: "text-slate-800", chip: "bg-white ring-slate-200 text-slate-700 hover:bg-slate-50" },
};

export default function NeedsAttention({ items, ready }: { items: readonly AttentionItem[]; ready: boolean }) {
  if (!ready) return <div className="h-20 rounded-2xl bg-white border border-gray-100 animate-pulse" aria-label="Loading what needs attention" />;
  if (items.length === 0) {
    return (
      <section aria-label="Needs attention" className="flex items-center gap-3 rounded-2xl bg-emerald-50/70 ring-1 ring-emerald-100 px-5 py-3.5">
        <span className="w-8 h-8 rounded-xl bg-emerald-100 text-emerald-600 flex items-center justify-center shrink-0">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
        </span>
        <div>
          <p className="text-sm font-bold text-emerald-900">All clear</p>
          <p className="text-xs text-emerald-700">Nothing is overdue, awaiting attestation or exposed right now.</p>
        </div>
      </section>
    );
  }
  const critical = items.filter(i => i.severity === "critical").length;
  return (
    <section aria-label="Needs attention" className="rounded-2xl bg-white border border-gray-100 shadow-sm p-4 sm:p-5">
      <div className="flex items-center gap-2 mb-3">
        <span className="relative flex w-2.5 h-2.5">
          {critical > 0 && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-60" />}
          <span className={`relative inline-flex rounded-full w-2.5 h-2.5 ${critical ? "bg-rose-500" : "bg-amber-500"}`} />
        </span>
        <h2 className="text-sm font-bold text-gray-900">Needs attention</h2>
        <span className="text-xs text-gray-400">{items.length} item{items.length === 1 ? "" : "s"}{critical ? ` · ${critical} critical` : ""}</span>
      </div>
      <ul className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2.5">
        {items.map(i => {
          const s = STYLE[i.severity];
          return (
            <li key={i.key} className={`flex flex-col gap-2 rounded-xl ${s.bg} ring-1 ${s.ring} px-3.5 py-3`}>
              <div className="flex items-start gap-3">
                <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${s.dot}`} />
                <div className="min-w-0 flex-1">
                  <Link href={i.href} className={`block text-sm font-bold leading-snug hover:underline ${s.title}`}>{i.title}</Link>
                  <p className="text-xs text-gray-500 mt-0.5">{i.detail}</p>
                </div>
                <Link href={i.href} className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 whitespace-nowrap" aria-label={`${i.cta}: ${i.title}`}>{i.cta} →</Link>
              </div>
              {i.links && i.links.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pl-5">
                  {i.links.map(l => (
                    <Link key={l.href + l.label} href={l.href}
                      className={`inline-flex items-center gap-1.5 max-w-full rounded-lg ring-1 px-2 py-1 text-[11px] font-semibold transition-colors ${s.chip}`}>
                      <span className="font-mono truncate max-w-[150px]">{l.label}</span>
                      {l.note && <span className="font-normal opacity-70 whitespace-nowrap">{l.note}</span>}
                    </Link>
                  ))}
                  {i.more ? <Link href={i.href} className="text-[11px] font-semibold text-gray-500 hover:text-gray-700 self-center">+{i.more} more</Link> : null}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
