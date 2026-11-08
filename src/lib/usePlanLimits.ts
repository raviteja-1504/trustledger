"use client";

import { useEffect, useState } from "react";
import { authedFetch } from "@/lib/useRealData";

export interface PlanQuota {
  limits: { scans: number; attestations: number; repos: number; members: number; reports: number };
  usage: { scans_this_month: number; attestations_this_month: number; repos_active: number; members: number; reports_this_month: number };
}

/**
 * The organisation's plan limits and usage, for pages where a user adds something the plan caps (a member, a
 * repository). Best effort: null until loaded, and stays null if it can't be loaded, so those pages work without it.
 */
export function usePlanLimits(enabled = true): PlanQuota | null {
  const [quota, setQuota] = useState<PlanQuota | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let live = true;
    Promise.resolve(authedFetch<PlanQuota>("/api/billing")).then(r => { if (live && r?.limits && r?.usage) setQuota({ limits: r.limits, usage: r.usage }); }).catch(() => undefined);
    return () => { live = false; };
  }, [enabled]);
  return quota;
}
