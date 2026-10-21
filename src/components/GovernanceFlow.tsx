"use client";
/**
 * The three pages that track unreviewed risk, each with its own job -- shown at the top of each so nobody reads
 * them as three views of the same number:
 *
 *   Policy Violations -- the work queue: every file or rule out of policy, worked one by one (attest it, or close
 *                        it with a reason).
 *   Alerts            -- notifications: one per pull request that needs a sign-off, with live progress; it closes
 *                        itself when that PR is clear.
 *   Incidents         -- escalations: only when something went wrong (a CRITICAL file still unreviewed after its
 *                        deadline, an exposed secret), with an owner, a timeline and a playbook.
 */
import Link from "next/link";

export type GovernancePage = "violations" | "alerts" | "incidents";

const STEPS: ReadonlyArray<{ key: GovernancePage; href: string; name: string; role: string; detail: string }> = [
  { key: "violations", href: "/violations", name: "Policy Violations", role: "Work queue",
    detail: "Each file or rule out of policy. Attest it (a signed review that unblocks the merge) or close it with a reason (no review — the merge stays blocked)." },
  { key: "alerts", href: "/alerts", name: "Alerts", role: "Notifications",
    detail: "One per pull request waiting for sign-off, with live progress. Closes itself when the PR is clear or a newer push replaces it." },
  { key: "incidents", href: "/incidents", name: "Incidents", role: "Escalations",
    detail: "Only when something went wrong: a CRITICAL file still unreviewed past its 24 h deadline. Has an owner, a timeline and a playbook." },
];

export default function GovernanceFlow({ current }: { current: GovernancePage }) {
  return (
    <nav aria-label="How violations, alerts and incidents differ" className="grid grid-cols-1 sm:grid-cols-3 gap-2">
      {STEPS.map(s => {
        const active = s.key === current;
        return (
          <Link key={s.key} href={s.href} aria-current={active ? "page" : undefined}
            className={`rounded-xl border px-3.5 py-2.5 transition-colors ${active
              ? "border-indigo-300 bg-indigo-50/70"
              : "border-gray-200 bg-white hover:border-indigo-200 hover:bg-indigo-50/30"}`}>
            <div className="flex items-baseline gap-2">
              <span className={`text-xs font-bold ${active ? "text-indigo-700" : "text-gray-800"}`}>{s.name}</span>
              <span className={`text-[10px] font-semibold uppercase tracking-wider ${active ? "text-indigo-500" : "text-gray-400"}`}>{s.role}</span>
            </div>
            <p className="text-[11px] leading-snug text-gray-500 mt-1">{s.detail}</p>
          </Link>
        );
      })}
    </nav>
  );
}
