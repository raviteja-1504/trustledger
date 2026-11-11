"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { limitStatus } from "@/lib/limits";
import { UPGRADE_LINE } from "@/lib/planGate-text";

/** "Free trial: 2 of 3 scans used this month", amber from 80%, and what happens at the limit. Renders nothing until it knows. */
export default function PlanBanner() {
  const [u, setU] = useState<{ used: number; limit: number } | null>(null);
  useEffect(() => {
    if (isSeedMode()) return;
    let live = true;
    Promise.resolve(authedFetch<{ usage: { used: number; limit: number } | null }>("/api/plan-usage")).then(r => { if (live && r?.usage) setU(r.usage); }).catch(() => {});
    return () => { live = false; };
  }, []);
  if (!u) return null;
  const s = limitStatus(u.used, u.limit);
  const tone = s.level === "ok" ? "border-gray-200 bg-white text-gray-700"
    : s.level === "warn" ? "border-amber-200 bg-amber-50 text-amber-800" : "border-rose-200 bg-rose-50 text-rose-800";
  return (
    <div role="status" data-level={s.level} className={`flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border px-4 py-2.5 text-sm ${tone}`}>
      <span className="font-semibold">Free trial: {s.used} of {s.limit} scans used this month</span>
      {s.level === "warn" && <span>{s.remaining} left. {UPGRADE_LINE}</span>}
      {(s.level === "full" || s.level === "over") && <span>New pull requests are not scanned until the 1st. Existing scans can still be viewed and attested. {UPGRADE_LINE}</span>}
      <Link href="/billing" className="ml-auto text-xs font-bold underline underline-offset-2">Usage</Link>
    </div>
  );
}
