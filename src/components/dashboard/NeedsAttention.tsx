"use client";

/**
 * The first thing on the dashboard: what needs someone's action now, worst first -- files past their fix deadline,
 * critical secrets, CRITICAL/HIGH files awaiting attestation, repos pending sign-off, unapproved AI tools -- each
 * naming the actual files and repos and linking to the page where that thing is fixed:
 *   files    → the file's sign-off on its pull request (/pr/{scan}?attest=...); for a viewer who can't sign it
 *              off (a developer), the file itself (?file=...)
 *   repos    → the pull request waiting for sign-off, with all its files (/pr/{scan})
 *   secrets  → /secrets, AI tools → /shadow-ai, audit gaps → /compliance, deadlines → /sla
 * Built only from loaded data; a source that hasn't loaded contributes nothing (never a guessed item).
 */
import Link from "next/link";
import { LoadingBlock } from "@/components/Loading";
import { fileReviewHref } from "@/lib/reviewLinks";

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

interface FileRef { file: string; scanId: string; repo: string; risk?: string; overdueHours?: number | null }

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
  /** Whether the viewer's role may sign off a file of this risk: if not, file links open the file, not its
   *  sign-off. Omitted: every file links to its sign-off. */
  canAttestRisk?: (risk: string | undefined) => boolean;
}

const SHOW = 3;
const plural = (n: number, one: string, many = `${one}s`) => `${n === 1 ? one : many}`;
export const repoHref = (repo: string) => `/repo/${repo.split("/").map(encodeURIComponent).join("/")}`;
/** A repo pending sign-off → the pull request (its latest scan) waiting for it; the repo page only without a scan. */
export const prHref = (r: { repo: string; scanId: string }) => r.scanId ? `/pr/${encodeURIComponent(r.scanId)}` : repoHref(r.repo);
const base = (p: string) => p.split("/").pop() ?? p;
const overdue = (h: number) => h >= 48 ? `${Math.floor(h / 24)}d overdue` : `${h}h overdue`;

function fileLinks(files: FileRef[], href: (f: FileRef) => string, withOverdue = false): Pick<AttentionItem, "links" | "more"> {
  return {
    links: files.slice(0, SHOW).map(f => ({
      label: base(f.file), href: href(f),
      note: withOverdue && f.overdueHours != null ? overdue(f.overdueHours) : base(f.repo),
    })),
    more: Math.max(0, files.length - SHOW),
  };
}

/** Items in priority order: they are added worst first. */
export function buildAttention(a: AttentionInput): AttentionItem[] {
  const items: AttentionItem[] = [];
  // A file's link: its sign-off for someone who may attest it, otherwise the file itself.
  const fileHref = (f: FileRef) => fileReviewHref(f.scanId, f.file, a.canAttestRisk ? a.canAttestRisk(f.risk) : true);
  if (a.slaOverdue > 0) items.push({
    key: "sla", kind: "sla", severity: "critical", count: a.slaOverdue,
    title: `${plural(a.slaOverdue, "file")} past the fix deadline`, detail: "HIGH/CRITICAL findings beyond their SLA",
    href: a.overdueFiles[0] ? fileHref(a.overdueFiles[0]) : "/sla", all: { label: "SLA tracker", href: "/sla" },
    ...fileLinks(a.overdueFiles, fileHref, true),
  });
  if (a.openCriticalSecrets) items.push({
    key: "secrets-critical", kind: "secret", severity: "critical", count: a.openCriticalSecrets,
    title: `critical ${plural(a.openCriticalSecrets, "secret")} exposed`, detail: "Rotate the credential, then resolve the finding",
    href: "/secrets",
  });
  if (a.unreviewedCritical.length > 0) items.push({
    key: "critical", kind: "file", severity: "critical", count: a.unreviewedCritical.length,
    title: `CRITICAL ${plural(a.unreviewedCritical.length, "file")} awaiting attestation`, detail: "Merges are held until a reviewer signs off",
    href: fileHref(a.unreviewedCritical[0]), all: { label: "Review queue", href: "#review-queue" },
    ...fileLinks(a.unreviewedCritical, fileHref),
  });
  if (a.awaitingRepos.length > 0) items.push({
    key: "repos", kind: "repo", severity: "high", count: a.awaitingRepos.length,
    title: `${plural(a.awaitingRepos.length, "repo")} pending sign-off`, detail: "Latest scan has HIGH/CRITICAL files nobody has signed off",
    // Straight to the pull request waiting for sign-off: its page lists every file with its attestation.
    href: a.awaitingRepos.length === 1 ? prHref(a.awaitingRepos[0]) : "#repositories",
    all: { label: "Repositories", href: "#repositories" },
    links: a.awaitingRepos.slice(0, SHOW).map(r => ({ label: r.repoName, href: prHref(r) })),
    more: Math.max(0, a.awaitingRepos.length - SHOW),
  });
  if (a.unreviewedHigh.length > 0) items.push({
    key: "high", kind: "file", severity: "high", count: a.unreviewedHigh.length,
    title: `HIGH-risk ${plural(a.unreviewedHigh.length, "file")} awaiting attestation`, detail: "Waiting for a reviewer",
    href: fileHref(a.unreviewedHigh[0]), all: { label: "Review queue", href: "#review-queue" },
    ...fileLinks(a.unreviewedHigh, fileHref),
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

/** The three groups the bar shows, in order. Item severity decides the group. */
export const GROUPS: ReadonlyArray<{ severity: AttentionSeverity; label: string; hint: string }> = [
  { severity: "critical", label: "Act now", hint: "Live risk: overdue, exposed or blocking merges" },
  { severity: "high",     label: "Next up", hint: "Waiting on a reviewer or a decision" },
  { severity: "medium",   label: "Plan for", hint: "Not blocking, but your auditor will see it" },
];

/** The button on each row says what you'll do there. */
const ACTION: Record<AttentionKind, string> = {
  sla: "Fix now", secret: "Rotate", file: "Review", repo: "Open", ai: "Triage", evidence: "See gaps",
};

const SEV: Record<AttentionSeverity, { tile: string; tileText: string; dot: string; tag: string; chip: string; button: string }> = {
  critical: {
    tile: "bg-rose-50 ring-rose-100", tileText: "text-rose-600", dot: "bg-rose-500", tag: "text-rose-700",
    chip: "bg-white ring-rose-200 text-rose-900 hover:bg-rose-50",
    button: "bg-rose-600 text-white hover:bg-rose-700 shadow-sm shadow-rose-200",
  },
  high: {
    tile: "bg-amber-50 ring-amber-100", tileText: "text-amber-600", dot: "bg-amber-500", tag: "text-amber-700",
    chip: "bg-white ring-amber-200 text-amber-900 hover:bg-amber-50",
    button: "bg-gray-900 text-white hover:bg-gray-800 shadow-sm",
  },
  medium: {
    tile: "bg-slate-50 ring-slate-200", tileText: "text-slate-600", dot: "bg-slate-400", tag: "text-slate-600",
    chip: "bg-white ring-slate-200 text-slate-800 hover:bg-slate-50",
    button: "bg-white text-gray-800 ring-1 ring-gray-200 hover:bg-gray-50",
  },
};

function KindIcon({ kind }: { kind: AttentionKind }) {
  const p = { width: 14, height: 14, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2.2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true };
  switch (kind) {
    case "sla": return <svg {...p}><circle cx="12" cy="12" r="9" /><polyline points="12 7 12 12 15 14" /></svg>;
    case "secret": return <svg {...p}><circle cx="8" cy="15" r="4" /><path d="M10.85 12.15 19 4" /><path d="m18 5 2 2" /><path d="m15 8 2 2" /></svg>;
    case "file": return <svg {...p}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><path d="m9 15 2 2 4-4" /></svg>;
    case "repo": return <svg {...p}><path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1 0-5H20" /></svg>;
    case "ai": return <svg {...p}><rect x="5" y="5" width="14" height="14" rx="2" /><path d="M9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4" /></svg>;
    case "evidence": return <svg {...p}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>;
  }
}

function Row({ i, group }: { i: AttentionItem; group: string }) {
  const s = SEV[i.severity];
  return (
    <li className="flex flex-col sm:flex-row sm:items-center gap-4 px-6 py-5">
      {/* Count tile */}
      <div className={`flex sm:flex-col items-center sm:justify-center gap-3 sm:gap-0.5 sm:w-20 sm:h-20 rounded-2xl ring-1 px-4 py-2 sm:p-0 shrink-0 ${s.tile}`}>
        <span className={`text-2xl sm:text-3xl font-black tabular-nums leading-none ${s.tileText}`}>{i.count}</span>
        <span className={`flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider ${s.tag}`}>
          <KindIcon kind={i.kind} />{group}
        </span>
      </div>

      {/* What and which */}
      <div className="min-w-0 flex-1">
        <Link href={i.href} className="text-[15px] font-bold text-gray-900 leading-snug hover:underline decoration-gray-300 underline-offset-2">
          <span className="sr-only">{i.count} </span>{i.title}
        </Link>
        <p className="text-sm text-gray-500 mt-0.5">{i.detail}</p>
        {i.links && i.links.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 mt-3">
            {i.links.map(l => (
              <Link key={l.href + l.label} href={l.href} title={l.note ? `${l.label} · ${l.note}` : l.label}
                className={`inline-flex flex-wrap items-baseline gap-x-1.5 max-w-full rounded-lg ring-1 px-2.5 py-1 text-xs font-semibold transition-colors ${s.chip}`}>
                <span className="font-mono break-all">{l.label}</span>
                {l.note && <span className="font-medium opacity-60">{l.note}</span>}
              </Link>
            ))}
            {i.more ? <Link href={i.all?.href ?? i.href} className="text-xs font-semibold text-gray-500 hover:text-gray-800 px-1">+{i.more} more</Link> : null}
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex sm:flex-col items-center sm:items-end gap-3 sm:gap-1.5 shrink-0">
        <Link href={i.href} className={`inline-flex items-center gap-1.5 rounded-xl px-4 py-2 text-sm font-bold transition-colors ${s.button}`}>
          {ACTION[i.kind]}<span aria-hidden="true">→</span>
        </Link>
        {i.all && <Link href={i.all.href} className="text-xs font-semibold text-gray-500 hover:text-indigo-600">{i.all.label}</Link>}
      </div>
    </li>
  );
}

export default function NeedsAttention({ items, ready }: { items: readonly AttentionItem[]; ready: boolean }) {
  if (!ready) return <LoadingBlock label="what needs attention" rows={3} />;
  if (items.length === 0) {
    return (
      <section aria-label="Needs attention" className="flex items-center gap-4 rounded-3xl bg-white border border-gray-100 shadow-sm px-6 py-5">
        <span className="w-11 h-11 rounded-2xl bg-emerald-50 ring-1 ring-emerald-100 text-emerald-600 flex items-center justify-center shrink-0">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
        </span>
        <div>
          <p className="text-base font-black text-gray-900">All clear</p>
          <p className="text-sm text-gray-500">Nothing is overdue, awaiting attestation or exposed right now.</p>
        </div>
      </section>
    );
  }
  const groups = GROUPS.map(g => ({ ...g, items: items.filter(i => i.severity === g.severity) })).filter(g => g.items.length > 0);
  const worst = groups[0].severity;
  const urgent = groups.find(g => g.severity === "critical")?.items.length ?? 0;
  const summary = urgent
    ? `${urgent} ${urgent === 1 ? "needs" : "need"} action now`
    : worst === "high" ? "Nothing urgent, but reviewers are needed" : "Nothing urgent or blocking";

  return (
    <section aria-label="Needs attention" className="rounded-3xl bg-white border border-gray-100 shadow-[0_8px_30px_rgba(15,23,42,0.05)] overflow-hidden">
      <header className="flex flex-wrap items-center justify-between gap-4 px-6 py-5 border-b border-gray-100">
        <div className="flex items-center gap-3">
          <span className={`relative w-10 h-10 rounded-2xl flex items-center justify-center ${urgent ? "bg-rose-50 text-rose-600" : "bg-amber-50 text-amber-600"}`}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" /><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
            </svg>
            {urgent > 0 && <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-rose-500 ring-2 ring-white animate-pulse" aria-hidden="true" />}
          </span>
          <div>
            <h2 className="text-lg font-black text-gray-900 tracking-tight leading-tight">Needs attention</h2>
            <p className="text-sm text-gray-500">{summary}</p>
          </div>
        </div>
        <ul className="flex flex-wrap items-center gap-2" aria-label="By urgency">
          {groups.map(g => (
            <li key={g.severity} role="group" aria-label={`${g.label}: ${g.items.length}`} title={g.hint}
              className="flex items-center gap-2 rounded-full bg-gray-50 ring-1 ring-gray-100 pl-2.5 pr-3 py-1.5 text-xs">
              <span className={`w-2 h-2 rounded-full ${SEV[g.severity].dot}`} />
              <span className="font-semibold text-gray-600">{g.label}</span>
              <span className="font-black text-gray-900 tabular-nums">{g.items.length}</span>
            </li>
          ))}
        </ul>
      </header>
      <ul className="divide-y divide-gray-100">
        {groups.flatMap(g => g.items.map(i => <Row key={i.key} i={i} group={g.label} />))}
      </ul>
    </section>
  );
}

