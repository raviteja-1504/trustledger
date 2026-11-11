"use client";
/**
 * "Finish setting up" card for the overview: shown to the creator of an organisation until the setup wizard has been
 * completed. Leaving the wizard part-way does not complete it, and it always starts from the first step.
 */
import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth";
import { authedFetch } from "@/lib/useRealData";
import { needsSetup, type OnboardingStatus } from "@/lib/onboardingGate";
import { DOABLE_STEPS, loadDoneSteps } from "@/lib/onboardingProgress";

export default function SetupBanner() {
  const { profile } = useAuth();
  const [show, setShow] = useState(false);
  const [doneCount, setDoneCount] = useState(0);

  useEffect(() => {
    if (!profile?.org_id || profile.role !== "admin") return;
    let alive = true;
    authedFetch<OnboardingStatus>("/api/onboarding").then(s => { if (alive) { setShow(needsSetup(s)); setDoneCount(loadDoneSteps().length); } }).catch(() => {});
    return () => { alive = false; };
  }, [profile?.org_id, profile?.role]);

  if (!show) return null;
  return (
    <section aria-label="Finish setting up" className="rounded-2xl border border-indigo-200 bg-indigo-50 px-5 py-4 flex flex-wrap items-center justify-between gap-3">
      <div className="min-w-0">
        <p className="text-sm font-black text-indigo-900">Finish setting up TrustLedger</p>
        <p className="text-xs text-indigo-700 mt-0.5">
          {doneCount > 0 ? `${doneCount} of ${DOABLE_STEPS.length} steps done. ` : ""}Setup isn&apos;t finished yet. It takes about two minutes: connect GitHub, invite your team and set your policy.
        </p>
      </div>
      <Link href="/onboarding" className="shrink-0 px-4 py-2 rounded-xl text-sm font-bold bg-indigo-600 text-white hover:bg-indigo-700">{doneCount > 0 ? "Continue setup" : "Start setup"}</Link>
    </section>
  );
}
