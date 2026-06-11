"use client";
/**
 * Feature Flag System
 * Lightweight feature flags with Supabase backend + localStorage cache.
 *
 * Flags can be:
 *   - Boolean: on/off
 *   - Percentage rollout: enabled for N% of orgs (hash-based, deterministic)
 *   - Plan-gated: only for specific plans
 *   - Org-specific: override for specific org IDs
 *
 * Usage:
 *   const flags = useFlags();
 *   if (flags.isEnabled("new_dashboard")) { ... }
 */

import { useState, useEffect, useCallback } from "react";

export interface FeatureFlag {
  key:         string;
  description: string;
  enabled:     boolean;
  rollout_pct?: number;       // 0-100, hash-based
  plans?:       string[];     // only for these plans
  org_ids?:     string[];     // specific org overrides
}

// ── Default flags (shipped with the app) ─────────────────────────────────────
// Override via Supabase `feature_flags` table or localStorage `tl_flags`

const DEFAULT_FLAGS: FeatureFlag[] = [
  { key:"new_dashboard",         description:"Redesigned dashboard with real-time widgets",   enabled:true                                    },
  { key:"ai_attribution",        description:"AI model attribution on PR review page",        enabled:true                                    },
  { key:"realtime_presence",     description:"Show other reviewers on PR page",               enabled:true                                    },
  { key:"keyboard_shortcuts",    description:"Global keyboard navigation shortcuts",          enabled:true                                    },
  { key:"dark_mode",             description:"Dark mode toggle",                              enabled:true                                    },
  { key:"scan_comparison",       description:"Side-by-side scan diff view",                   enabled:true                                    },
  { key:"aibom_page",            description:"AI Bill of Materials inventory page",           enabled:true                                    },
  { key:"sla_dashboard",         description:"Dedicated SLA breach tracking page",            enabled:true                                    },
  { key:"bitbucket_integration", description:"Bitbucket PR scanning",                         enabled:true                                    },
  { key:"gitlab_integration",    description:"GitLab MR scanning",                            enabled:true                                    },
  { key:"custom_roles",          description:"Custom RBAC roles",                             enabled:true,  plans:["growth","enterprise"]    },
  { key:"advanced_analytics",    description:"Trend analysis and velocity metrics",           enabled:false, plans:["growth","enterprise"]    },
  { key:"white_label",           description:"Custom branding and white-label",               enabled:false, plans:["enterprise"]             },
  { key:"self_hosted_scanner",   description:"Local scanner mode (zero code egress)",        enabled:true,  plans:["enterprise"]             },
  { key:"scim_provisioning",     description:"SCIM 2.0 user provisioning",                   enabled:true,  plans:["enterprise"]             },
  { key:"beta_scan_scheduling",  description:"Scheduled automatic repository scanning",      enabled:false, rollout_pct:20                   },
  { key:"beta_pr_comment_bot",   description:"Detailed PR comment with risk breakdown",      enabled:false, rollout_pct:50                   },
];

const FLAGS_KEY = "tl_flags_cache";
const FLAGS_TTL = 5 * 60 * 1000; // 5 minutes

interface FlagsCache {
  flags:    FeatureFlag[];
  cached_at:number;
}

function loadCached(): FeatureFlag[] | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(FLAGS_KEY);
    if (!raw) return null;
    const cache = JSON.parse(raw) as FlagsCache;
    if (Date.now() - cache.cached_at > FLAGS_TTL) return null;
    return cache.flags;
  } catch { return null; }
}

function saveCache(flags: FeatureFlag[]) {
  try { localStorage.setItem(FLAGS_KEY, JSON.stringify({ flags, cached_at: Date.now() })); } catch {}
}

/** Deterministic hash — same org always gets same rollout result. */
function hashOrgId(orgId: string, flagKey: string): number {
  let h = 0;
  const s = `${orgId}:${flagKey}`;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) & 0xffffffff;
  }
  return Math.abs(h) % 100;
}

// ── Hook ───────────────────────────────────────────────────────────────────────

export interface FlagsContext {
  flags:     FeatureFlag[];
  isEnabled: (key: string, orgId?: string, plan?: string) => boolean;
  loading:   boolean;
  refresh:   () => void;
}

export function useFlags(orgId?: string, plan?: string): FlagsContext {
  const [flags,   setFlags]   = useState<FeatureFlag[]>(loadCached() ?? DEFAULT_FLAGS);
  const [loading, setLoading] = useState(false);

  const fetchFlags = useCallback(async () => {
    setLoading(true);
    try {
      // Try to fetch overrides from Supabase
      const { supabase } = await import("./supabase");
      const { data } = await supabase
        .from("feature_flags")
        .select("key, enabled, rollout_pct, plans, org_ids") as { data: Partial<FeatureFlag>[] | null };

      if (data && data.length > 0) {
        // Merge DB overrides with defaults
        const overrideMap = new Map(data.map(f => [f.key!, f]));
        const merged = DEFAULT_FLAGS.map(def => {
          const override = overrideMap.get(def.key);
          return override ? { ...def, ...override } : def;
        });
        // Add any new flags from DB not in defaults
        data.forEach(f => {
          if (!merged.find(m => m.key === f.key) && f.key) {
            merged.push({ key:f.key, description:"", enabled:f.enabled??false, ...f });
          }
        });
        setFlags(merged);
        saveCache(merged);
      }
    } catch { /* use defaults */ }
    setLoading(false);
  }, []);

  useEffect(() => { fetchFlags(); }, [fetchFlags]);

  const isEnabled = useCallback((key: string, oid?: string, p?: string): boolean => {
    const flag = flags.find(f => f.key === key);
    if (!flag) return false;
    if (!flag.enabled) return false;

    // Plan gate
    const effectivePlan = p ?? plan;
    if (flag.plans && flag.plans.length > 0 && effectivePlan) {
      if (!flag.plans.includes(effectivePlan)) return false;
    }

    // Org-specific override
    const effectiveOrgId = oid ?? orgId;
    if (flag.org_ids && flag.org_ids.length > 0 && effectiveOrgId) {
      return flag.org_ids.includes(effectiveOrgId);
    }

    // Percentage rollout
    if (flag.rollout_pct !== undefined && flag.rollout_pct < 100 && effectiveOrgId) {
      return hashOrgId(effectiveOrgId, key) < flag.rollout_pct;
    }

    return true;
  }, [flags, orgId, plan]);

  return { flags, isEnabled, loading, refresh: fetchFlags };
}

// ── Singleton for use outside React ───────────────────────────────────────────

let _flagsCache: FeatureFlag[] = DEFAULT_FLAGS;

export function isFeatureEnabled(key: string, orgId?: string, plan?: string): boolean {
  const flag = _flagsCache.find(f => f.key === key);
  if (!flag || !flag.enabled) return false;
  if (flag.plans && plan && !flag.plans.includes(plan)) return false;
  if (flag.rollout_pct !== undefined && flag.rollout_pct < 100 && orgId) {
    return hashOrgId(orgId, key) < flag.rollout_pct;
  }
  return true;
}

/** Call on app init to warm the singleton cache. */
export function initFlags(flags: FeatureFlag[]) { _flagsCache = flags; }
