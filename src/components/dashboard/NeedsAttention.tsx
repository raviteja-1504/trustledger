"use client";

/**
 * The first thing on the dashboard: what needs someone's action now, worst first -- files past their fix deadline,
 * critical secrets, CRITICAL/HIGH files awaiting attestation, repos pending sign-off, unapproved AI tools -- each
 * naming the actual files and repos and linking to the page where that thing is fixed:
 *   files    → the file's sign-off on its pull request (/pr/{scan}?attest=...)
 *   repos    → the repository's page (/repo/{owner}/{repo})
 *   secrets  → /secrets, AI tools → /shadow-ai, audit gaps → /compliance, deadlines → /sla
 * Built only from loaded data; a source that hasn't loaded contributes nothing (never a guessed item).
 */
import Link from "next/link";

export type AttentionSeverity = "critical" | "high" | "medium";
export type AttentionKind = "sla" | "secret" | "file" | "repo" | "ai" | "evidence";

export interface AttentionLink { label: string; href: string; note?: string }

export interface AttentionItem {
  key: string;
  kind: AttentionKind;
  severity: AttentionSeverity;
  count: number;
  title: string;
  detail: string;
  /** Where the heading goes: the single most useful page for this item. */
  href: string;
  /** Secondary link to the full list. */
  all?: { label: string; href: string };
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
  awaitingRepos: Array<{ repo: string; repoName: string; scanId: string }>;
  openCriticalSecrets: number | null;
  openOtherSecrets: number | null;
  unapprovedAiTools: number | null;
  /** Evidence checks (lib/controlEvidence.ts) whose status is "fail" -- counted once, not per framework. */
  failingControls: number | null;
}

const SHOW = 3;
const plural = (n: number, one: string, many = `${one}s`) => `${n === 1 ? one : many}`;
export const attestHref = (f: { scanId: string; file: string }) => `/pr/${f.scanId}?attest=${encodeURIComponent(f.file)}`;
export const repoHref = (repo: string) => `/repo/${repo.split("/").map(encodeURIComponent).join("/")}`;
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
    key: "sla", kind: "sla", severity: "critical", count: a.slaOverdue,
    title: `${plural(a.slaOverdue, "file")} past the fix deadline`, detail: "HIGH/CRITICAL findings beyond their SLA",
    href: a.overdueFiles[0] ? attestHref(a.overdueFiles[0]) : "/sla", all: { label: "SLA tracker", href: "/sla" },
    ...fileLinks(a.overdueFiles, true),
  });
  if (a.openCriticalSecrets) items.push({
    key: "secrets-critical", kind: "secret", severity: "critical", count: a.openCriticalSecrets,
    title: `critical ${plural(a.openCriticalSecrets, "secret")} exposed`, detail: "Rotate the credential, then resolve the finding",
    href: "/secrets",
  });
  if (a.unreviewedCritical.length > 0) items.push({
    key: "critical", kind: "file", severity: "critical", count: a.unreviewedCritical.length,
    title: `CRITICAL ${plural(a.unreviewedCritical.length, "file")} awaiting attestation`, detail: "Merges are held until a reviewer signs off",
    href: attestHref(a.unreviewedCritical[0]), all: { label: "Review queue", href: "#review-queue" },
    ...fileLinks(a.unreviewedCritical),
  });
  if (a.awaitingRepos.length > 0) items.push({
    key: "repos", kind: "repo", severity: "high", count: a.awaitingRepos.length,
    title: `${plural(a.awaitingRepos.length, "repo")} pending sign-off`, detail: "Latest scan has HIGH/CRITICAL files nobody has signed off",
    href: a.awaitingRepos.length === 1 ? repoHref(a.awaitingRepos[0].repo) : "#repositories",
    all: { label: "Repositories", href: "#repositories" },
    links: a.awaitingRepos.slice(0, SHOW).map(r => ({ label: r.repoName, href: repoHref(r.repo) })),
    more: Math.max(0, a.awaitingRepos.length - SHOW),
  });
  if (a.unreviewedHigh.length > 0) items.push({
    key: "high", kind: "file", severity: "high", count: a.unreviewedHigh.length,
    title: `HIGH-risk ${plural(a.unreviewedHigh.length, "file")} awaiting attestation`, detail: "Waiting for a reviewer",
    href: attestHref(a.unreviewedHigh[0]), all: { label: "Review queue", href: "#review-queue" },
    ...fileLinks(a.unreviewedHigh),
  });
  if (a.unapprovedAiTools) items.push({
    key: "ai", kind: "ai", severity: "high", count: a.unapprovedAiTools,
    title: `unapproved AI tool ${plural(a.unapprovedAiTools, "detection")}`, detail: "AI tools outside your approved list",
    href: "/shadow-ai",
  });
  if (a.openOtherSecrets) items.push({
    key: "secrets", kind: "secret", severity: "medium", count: a.openOtherSecrets,
    title: `open ${plural(a.openOtherSecrets, "secret")}`, detail: "HIGH/MEDIUM credentials found in code",
    href: "/secrets",
  });
  if (a.failingControls) items.push({
    key: "controls", kind: "evidence", severity: "medium", count: a.failingControls,
    title: `failing audit evidence ${plural(a.failingControls, "check")}`, detail: "A gap your auditor will see",
    href: "/compliance",
  });
  return items;
}

const SEV: Record<AttentionSeverity, { label: string; accent: string; iconBg: string; icon: string; count: string; chip: string; pill: string }> = {
  critical: { label: "Critical", accent: "from-rose-500 to-rose-400", iconBg: "bg-rose-50 ring-rose-100", icon: "text-rose-600", count: "text-rose-600",
    chip: "bg-rose-50/60 ring-rose-100 text-rose-900 hover:bg-rose-50 hover:ring-rose-200", pill: "bg-rose-50 text-rose-700 ring-rose-200" },
  high:     { label: "High", accent: "from-amber-500 to-amber-300", iconBg: "bg-amber-50 ring-amber-100", icon: "text-amber-600", count: "text-amber-600",
    chip: "bg-amber-50/60 ring-amber-100 text-amber-900 hover:bg-amber-50 hover:ring-amber-200", pill: "bg-amber-50 text-amber-700 ring-amber-200" },
  medium:   { label: "Medium", accent: "from-slate-400 to-slate-300", iconBg: "bg-slate-50 ring-slate-100", icon: "text-slate-500", count: "text-slate-700",
    chip: "bg-slate-50 ring-slate-100 text-slate-800 hover:bg-slate-100 hover:ring-slate-200", pill: "bg-slate-50 text-slate-600 ring-slate-200" },
};

function KindIcon({ kind }: { kind: AttentionKind }) {
  const p = { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true };
  switch (kind) {
    case "sla": return <svg {...p}><circle cx="12" cy="12" r="9" /><polyline points="12 7 12 12 15 14" /></svg>;
    case "secret": return <svg {...p}><circle cx="8" cy="15" r="4" /><path d="M10.85 12.15 19 4" /><path d="m18 5 2 2" /><path d="m15 8 2 2" /></svg>;
    case "file": return <svg {...p}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><path d="m9 15 2 2 4-4" /></svg>;
    case "repo": return <svg {...p}><path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1 0-5H20" /></svg>;
    case "ai": return <svg {...p}><rect x="5" y="5" width="14" height="14" rx="2" /><path d="M9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4" /></svg>;
    case "evidence": return <svg {...p}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>;
  }
}

export default function NeedsAttention({ items, ready }: { items: readonly AttentionItem[]; ready: boolean }) {
  if (!ready) return <div className="h-28 rounded-3xl bg-white border border-gray-100 animate-pulse" aria-label="Loading what needs attention" />;
  if (items.length === 0) {
    return (
      <section aria-label="Needs attention" className="flex items-center gap-4 rounded-3xl bg-gradient-to-r from-emerald-50 to-teal-50 ring-1 ring-emerald-100 px-6 py-4">
        <span className="w-10 h-10 rounded-2xl bg-white ring-1 ring-emerald-100 text-emerald-600 flex items-center justify-center shrink-0 shadow-sm">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
        </span>
        <div>
          <p className="text-sm font-black text-emerald-900">All clear</p>
          <p className="text-xs text-emerald-700">Nothing is overdue, awaiting attestation or exposed right now.</p>
        </div>
      </section>
    );
  }
  const counts = { critical: 0, high: 0, medium: 0 } as Record<AttentionSeverity, number>;
  for (const i of items) counts[i.severity]++;
  return (
    <section aria-label="Needs attention" className="relative overflow-hidden rounded-3xl bg-white border border-gray-100 shadow-sm">
      <div className={`h-1 bg-gradient-to-r ${counts.critical ? "from-rose-500 via-orange-400 to-amber-300" : "from-amber-400 to-amber-200"}`} aria-hidden="true" />
      <div className="p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2.5">
            <span className="relative flex w-2.5 h-2.5">
              {counts.critical > 0 && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-60" />}
              <span className={`relative inline-flex rounded-full w-2.5 h-2.5 ${counts.critical ? "bg-rose-500" : "bg-amber-500"}`} />
            </span>
            <h2 className="text-base font-black text-gray-900 tracking-tight">Needs attention</h2>
          </div>
          <div className="flex items-center gap-1.5" aria-label="By severity">
            {(["critical", "high", "medium"] as const).filter(s => counts[s] > 0).map(s => (
              <span key={s} className={`text-[11px] font-bold px-2.5 py-1 rounded-full ring-1 ${SEV[s].pill}`}>{counts[s]} {SEV[s].label.toLowerCase()}</span>
            ))}
          </div>
        </div>
        <ul className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {items.map(i => {
            const s = SEV[i.severity];
            return (
              <li key={i.key} className="group relative flex flex-col rounded-2xl bg-white ring-1 ring-gray-100 shadow-[0_1px_2px_rgba(15,23,42,0.04)] hover:shadow-md hover:ring-gray-200 transition-all overflow-hidden">
                <span className={`absolute inset-y-0 left-0 w-1 bg-gradient-to-b ${s.accent}`} aria-hidden="true" />
                <div className="flex items-start gap-3 pl-5 pr-4 pt-3.5 pb-3">
                  <span className={`w-9 h-9 rounded-xl ring-1 flex items-center justify-center shrink-0 ${s.iconBg} ${s.icon}`}><KindIcon kind={i.kind} /></span>
                  <div className="min-w-0 flex-1">
                    <Link href={i.href} className="block leading-tight hover:underline decoration-gray-300 underline-offset-2">
                      <span className={`text-xl font-black tabular-nums mr-1.5 ${s.count}`}>{i.count}</span>
                      <span className="text-sm font-bold text-gray-900">{i.title}</span>
                    </Link>
                    <p className="text-xs text-gray-500 mt-1">{i.detail}</p>
                  </div>
                </div>
                {i.links && i.links.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pl-5 pr-4 pb-3">
                    {i.links.map(l => (
                      <Link key={l.href + l.label} href={l.href}
                        className={`inline-flex items-center gap-1.5 max-w-full rounded-lg ring-1 px-2 py-1 text-[11px] font-semibold transition-colors ${s.chip}`}>
                        <span className="font-mono truncate max-w-[150px]">{l.label}</span>
                        {l.note && <span className="font-medium opacity-60 whitespace-nowrap">{l.note}</span>}
                      </Link>
                    ))}
                    {i.more ? <Link href={i.all?.href ?? i.href} className="text-[11px] font-semibold text-gray-500 hover:text-gray-800 self-center px-1">+{i.more} more</Link> : null}
                  </div>
                )}
                {i.all && (
                  <Link href={i.all.href} className="mt-auto flex items-center justify-between pl-5 pr-4 py-2 border-t border-gray-50 text-[11px] font-semibold text-indigo-600 hover:bg-indigo-50/40">
                    {i.all.label}<span aria-hidden="true">→</span>
                  </Link>
                )}
              </li>
            );
          })}
        </ul>
      </div>
    </section>
  );
}
