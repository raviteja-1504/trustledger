"use client";

/**
 * The governance row: Shadow AI, leaked secrets and audit evidence, each a summary of its page with a link to it.
 * Each panel takes already-loaded data (null while loading, "unavailable" if it couldn't load) and only shows
 * what that data says.
 */
import Link from "next/link";
import type { ShadowSummary } from "@/lib/shadowAi";
import type { EvidenceOverview } from "@/lib/evidenceEngine";
import type { EvidenceStatus } from "@/lib/controlEvidence";

export type Loadable<T> = T | null | "unavailable";

function Panel({ title, href, cta, children, label }: { title: string; href: string; cta: string; children: React.ReactNode; label: string }) {
  return (
    <section aria-label={label} className="section-card p-6 flex flex-col gap-5 min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-bold text-gray-900">{title}</h2>
        <Link href={href} className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 whitespace-nowrap">{cta} →</Link>
      </div>
      {children}
    </section>
  );
}

function Pending({ state }: { state: null | "unavailable" }) {
  return state === null
    ? <div className="h-24 rounded-xl bg-gray-50 animate-pulse" aria-label="Loading" />
    : <p className="text-xs text-gray-400">Couldn&apos;t load this right now.</p>;
}

// ── Shadow AI ─────────────────────────────────────────────────────────────────

export function ShadowAiPanel({ summary }: { summary: Loadable<ShadowSummary> }) {
  return (
    <Panel title="AI tool usage" href="/shadow-ai" cta="Shadow AI" label="AI tool usage">
      {summary === null || summary === "unavailable" ? <Pending state={summary} /> : (() => {
        const tools = [...summary.by_tool].sort((a, b) => b.detections - a.detections).slice(0, 4);
        const maxDet = Math.max(1, ...tools.map(t => t.detections));
        return (
          <>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className={`text-3xl font-black tabular-nums leading-none ${summary.open_violations ? "text-rose-600" : "text-gray-900"}`}>{summary.open_violations}</p>
                <p className="text-[11px] text-gray-500 mt-1">unapproved-tool detections open</p>
              </div>
              <div>
                <p className="text-3xl font-black tabular-nums leading-none text-gray-900">
                  {summary.compliance == null ? "—" : `${Math.round(summary.compliance * 100)}%`}
                </p>
                <p className="text-[11px] text-gray-500 mt-1">of AI tool evidence is approved</p>
              </div>
            </div>
            {!summary.policy_configured && (
              <p className="text-[11px] font-semibold text-amber-800 bg-amber-50 border border-amber-100 rounded-lg px-3 py-2">
                No approved-tools policy yet, so nothing is flagged. Set one in Shadow AI.
              </p>
            )}
            {tools.length ? (
              <ul className="space-y-2">
                {tools.map(t => (
                  <li key={t.tool}>
                    <div className="flex items-start justify-between gap-2 text-xs">
                      <span className="min-w-0 font-semibold text-gray-700 break-words leading-snug">{t.label}</span>
                      <span className="flex items-center gap-2 shrink-0">
                        <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded whitespace-nowrap ${
                          t.approval === "approved" ? "bg-emerald-50 text-emerald-700" : t.approval === "unapproved" ? "bg-rose-50 text-rose-700" : "bg-gray-100 text-gray-500"}`}>
                          {t.approval}
                        </span>
                        <span className="tabular-nums text-gray-500 min-w-[1.5rem] text-right">{t.detections}</span>
                      </span>
                    </div>
                    <div className="mt-1 h-1 rounded-full bg-gray-100 overflow-hidden">
                      <div className={`h-full rounded-full ${t.violations ? "bg-rose-400" : "bg-indigo-400"}`} style={{ width: `${(t.detections / maxDet) * 100}%` }} />
                    </div>
                  </li>
                ))}
              </ul>
            ) : <p className="text-xs text-gray-400">No AI tool evidence in recent pull requests.</p>}
          </>
        );
      })()}
    </Panel>
  );
}

// ── Secrets ───────────────────────────────────────────────────────────────────

export interface SecretCounts { CRITICAL: number; HIGH: number; MEDIUM: number }

export function countSecrets(findings: ReadonlyArray<{ severity?: string | null }>): SecretCounts {
  const out: SecretCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
  for (const f of findings) {
    const s = (f.severity ?? "").toUpperCase();
    if (s === "CRITICAL" || s === "HIGH") out[s]++;
    else out.MEDIUM++;
  }
  return out;
}

export function SecretsPanel({ counts }: { counts: Loadable<SecretCounts> }) {
  return (
    <Panel title="Leaked secrets" href="/secrets" cta="Secrets" label="Leaked secrets">
      {counts === null || counts === "unavailable" ? <Pending state={counts} /> : (() => {
        const total = counts.CRITICAL + counts.HIGH + counts.MEDIUM;
        const rows = [
          { k: "Critical", n: counts.CRITICAL, c: "bg-violet-500" },
          { k: "High", n: counts.HIGH, c: "bg-orange-500" },
          { k: "Medium", n: counts.MEDIUM, c: "bg-amber-400" },
        ];
        return (
          <>
            <div>
              <p className={`text-3xl font-black tabular-nums leading-none ${total ? "text-rose-600" : "text-gray-900"}`}>{total}</p>
              <p className="text-[11px] text-gray-500 mt-1">{total ? "open credentials found in code" : "no open credentials in code"}</p>
            </div>
            <div className="flex h-2 rounded-full overflow-hidden bg-gray-100" aria-hidden="true">
              {rows.map(r => r.n > 0 && <div key={r.k} className={r.c} style={{ width: `${(r.n / Math.max(total, 1)) * 100}%` }} />)}
            </div>
            <ul className="grid grid-cols-3 gap-2">
              {rows.map(r => (
                <li key={r.k} className="rounded-xl bg-gray-50 px-2.5 py-2 min-w-0">
                  <p className="flex items-center gap-1.5 text-[11px] font-semibold text-gray-500"><span className={`w-1.5 h-1.5 rounded-full shrink-0 ${r.c}`} />{r.k}</p>
                  <p className="text-lg font-black tabular-nums text-gray-900">{r.n}</p>
                </li>
              ))}
            </ul>
            {total > 0 && <p className="text-[11px] text-gray-500">Rotate the credential first, then resolve the finding.</p>}
          </>
        );
      })()}
    </Panel>
  );
}

// ── Audit evidence ────────────────────────────────────────────────────────────

const DOT: Record<EvidenceStatus, string> = { pass: "bg-emerald-500", partial: "bg-amber-400", fail: "bg-rose-500", not_tested: "bg-gray-300" };
const ORDER: EvidenceStatus[] = ["pass", "partial", "fail", "not_tested"];
const STATUS_TEXT: Record<EvidenceStatus, { label: string; cls: string }> = {
  pass:       { label: "Evidence collected", cls: "text-emerald-700 bg-emerald-50 ring-emerald-100" },
  partial:    { label: "Gaps found",         cls: "text-amber-700 bg-amber-50 ring-amber-100" },
  fail:       { label: "Failing",            cls: "text-rose-700 bg-rose-50 ring-rose-100" },
  not_tested: { label: "No evidence yet",    cls: "text-gray-500 bg-gray-50 ring-gray-100" },
};
const REPORT_FW: Record<string, string> = { soc2: "SOC2", iso27001: "ISO27001", pcidss: "PCIDSS", aigov: "AIGOV" };

/** Expanded: a card per framework listing every control with its status, then every open gap. */
export function EvidencePanel({ overview }: { overview: Loadable<EvidenceOverview> }) {
  return (
    <Panel title="Audit evidence" href="/compliance" cta="Compliance" label="Audit evidence">
      {overview === null || overview === "unavailable" ? <Pending state={overview} /> : (
        <>
          <p className="text-sm text-gray-500 -mt-2">
            What your scans, reviews and audit log prove for each framework&apos;s code-change controls. Evidence for your auditor, not a certification.
          </p>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {overview.frameworks.map(f => {
              const total = f.controls.length;
              return (
                <article key={f.id} aria-label={f.name} className="rounded-2xl ring-1 ring-gray-100 bg-gray-50/40 p-5">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h3 className="text-sm font-bold text-gray-900">{f.name}</h3>
                      <p className="text-xs text-gray-500 mt-0.5">
                        <span className="font-black text-gray-900 tabular-nums">{f.status_counts.pass}</span> of {total} controls with evidence
                      </p>
                    </div>
                    <Link href={`/reports?fw=${REPORT_FW[f.id] ?? f.id}`} className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 whitespace-nowrap">Report →</Link>
                  </div>
                  <div className="mt-3 flex h-2 rounded-full overflow-hidden bg-gray-100" aria-hidden="true">
                    {ORDER.map(s => f.status_counts[s] > 0 && <div key={s} className={DOT[s]} style={{ width: `${(f.status_counts[s] / Math.max(total, 1)) * 100}%` }} />)}
                  </div>
                  <ul className="mt-4 divide-y divide-gray-100">
                    {f.controls.map(c => (
                      <li key={c.control_id} className="flex items-start gap-3 py-2.5">
                        <span className="mt-0.5 text-[11px] font-black font-mono text-indigo-600 bg-indigo-50 rounded-md px-1.5 py-0.5 shrink-0">{c.control_id}</span>
                        <span className="min-w-0 flex-1 text-sm text-gray-700 leading-snug">{c.control_name}</span>
                        <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ring-1 whitespace-nowrap shrink-0 ${STATUS_TEXT[c.status].cls}`}>{STATUS_TEXT[c.status].label}</span>
                      </li>
                    ))}
                  </ul>
                </article>
              );
            })}
          </div>
          {overview.gaps.length > 0 ? (
            <div className="rounded-2xl ring-1 ring-amber-100 bg-amber-50/40 p-5">
              <h3 className="text-sm font-bold text-gray-900">Gaps to close</h3>
              <ul className="mt-3 space-y-2.5">
                {overview.gaps.map(g => (
                  <li key={g.key} className="flex items-start gap-3 text-sm">
                    <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${DOT[g.status]}`} />
                    <span className="text-gray-700 leading-snug"><span className="font-semibold text-gray-900">{g.label}:</span> {g.gaps.join("; ")}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : <p className="text-sm text-emerald-700">No gaps in the controls TrustLedger can evidence.</p>}
        </>
      )}
    </Panel>
  );
}

