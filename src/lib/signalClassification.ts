import type { FileResult } from "@/types";

export type SignalSev = "critical" | "high" | "medium" | "low";

// SIGNAL_META (src/app/pr/[id]/page.tsx) is a static table that can drift
// from what a detector actually computes per-instance -- either missing an
// id entirely (falls back to a generic label at "low" severity and gets
// miscategorized as an AI signal, even for a real, CWE-mapped security
// finding) or carrying a stale severity that no longer matches the real,
// potentially probabilistic value the detector assigned (e.g. a heuristic
// backdoor-detection instance scored "low" confidence still showing as a
// static "critical" regardless). Both directions are real bugs found via
// direct scanner testing. These two helpers prefer the real per-instance
// data from file.indicators and only fall back to the static table when no
// instance data is available at all.
export function isSecuritySignal(
  sig: string,
  file: FileResult,
  staticSecurity: boolean | undefined,
): boolean {
  if (staticSecurity) return true;
  return (file.indicators ?? []).some(i => i.id === sig && !!i.cwe);
}

export function realSeverity(
  instances: FileResult["indicators"],
  staticSev: SignalSev | undefined,
): SignalSev {
  const raw = instances?.[0]?.severity;
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low") return raw;
  return staticSev ?? "low";
}

// ── Reachability ─────────────────────────────────────────────────────────────
//
// Reachability is inherently per-instance in the same way severity turned
// out not to be reliably static: the same rule id can be reachable from an
// entry point at one line and sit in provably dead code at another line in
// the same file (see src/lib/reachability.ts's scoreExploitability(), fixed
// earlier to classify per-indicator rather than once for the whole file).
// There is no static per-id table for this at all -- unlike SIGNAL_META,
// which at least has a stale fallback, reachability simply doesn't exist
// until a file has been (re)scanned with this feature live, so "no instance
// data" always means "unknown," never a guessable default.

export type Reachability = "unreachable" | "reachable" | "tainted-path" | "entry-point" | "unknown";

// Ranks tiers by how urgent they are to act on -- used to pick the single
// worst (most urgent) reachability when a UI groups multiple instances of
// one signal id together, and to sort findings by urgency.
const REACH_RANK: Record<Reachability, number> = {
  "entry-point": 4, "tainted-path": 3, "reachable": 2, "unreachable": 1, "unknown": 0,
};

// Unlike realSeverity() (which reads instances[0] because a detector's own
// findings share one severity), reachability is NOT uniform across
// instances of the same signal id, so this takes the worst across all of
// them rather than just the first.
export function realReachability(instances: FileResult["indicators"]): Reachability {
  let worst: Reachability = "unknown";
  for (const i of instances ?? []) {
    const r = i.reachability;
    if (r && REACH_RANK[r] > REACH_RANK[worst]) worst = r;
  }
  return worst;
}

export const REACH_COLORS: Record<Reachability, { badge: string; dot: string }> = {
  "entry-point":  { badge: "bg-rose-100 text-rose-800 ring-rose-300",       dot: "bg-rose-500"   },
  "tainted-path": { badge: "bg-orange-100 text-orange-800 ring-orange-300", dot: "bg-orange-500" },
  "reachable":    { badge: "bg-amber-100 text-amber-800 ring-amber-300",    dot: "bg-amber-400"  },
  "unreachable":  { badge: "bg-gray-100 text-gray-500 ring-gray-300",       dot: "bg-gray-400"   },
  "unknown":      { badge: "bg-gray-50 text-gray-400 ring-gray-200",        dot: "bg-gray-300"   },
};

export const REACH_LABEL: Record<Reachability, string> = {
  "entry-point":  "Entry point",
  "tainted-path": "Tainted path",
  "reachable":    "Reachable",
  "unreachable":  "Unreachable",
  "unknown":      "Unknown",
};

export const REACH_DESC: Record<Reachability, string> = {
  "entry-point":  "Directly reachable from an API route or handler with no other function call between it and this code — the highest-confidence attack surface.",
  "tainted-path": "Reachable, and the call graph traced attacker-controlled data flowing along the path to this code.",
  "reachable":    "Reachable from at least one entry point, but no tainted data path was confirmed to it.",
  "unreachable":  "No path found from any entry point in this file's call graph — likely dead code, or the call graph couldn't trace it (e.g. dynamic dispatch, or a language without call-graph support).",
  "unknown":      "This scan predates reachability analysis, or this finding wasn't a scored security indicator.",
};

// ── Remediation urgency ─────────────────────────────────────────────────────
//
// Computed alongside reachability by the same scoreExploitability() pass
// (src/lib/reachability.ts) and persisted on every ScanIndicator since that
// phase shipped, but never rendered anywhere in the UI until now -- confirmed
// via a direct grep across every .tsx file. Same per-instance reasoning as
// reachability above (the same rule id can score differently at different
// lines), so this mirrors realReachability()'s worst-case-across-instances
// shape exactly. Unlike Reachability, ScanIndicator.remediation_urgency has
// no "unknown" tier in its own type -- an indicator either has a real,
// scored value or the field is simply absent (never scored, e.g. an
// AI-signal id) -- so "no data" is represented as `null`, the caller's
// signal to skip rendering the badge entirely, rather than a synthetic
// "unknown" member.

export type Urgency = "immediate" | "sprint" | "backlog" | "monitor";

const URGENCY_RANK: Record<Urgency, number> = {
  immediate: 3, sprint: 2, backlog: 1, monitor: 0,
};

export function realRemediationUrgency(instances: FileResult["indicators"]): Urgency | null {
  let worst: Urgency | null = null;
  for (const i of instances ?? []) {
    const u = i.remediation_urgency;
    if (u && (!worst || URGENCY_RANK[u] > URGENCY_RANK[worst])) worst = u;
  }
  return worst;
}

export const URGENCY_COLORS: Record<Urgency, { badge: string; dot: string }> = {
  immediate: { badge: "bg-rose-100 text-rose-800 ring-rose-300",       dot: "bg-rose-500"   },
  sprint:    { badge: "bg-orange-100 text-orange-800 ring-orange-300", dot: "bg-orange-500" },
  backlog:   { badge: "bg-amber-100 text-amber-800 ring-amber-300",    dot: "bg-amber-400"  },
  monitor:   { badge: "bg-gray-100 text-gray-500 ring-gray-300",       dot: "bg-gray-400"   },
};

export const URGENCY_LABEL: Record<Urgency, string> = {
  immediate: "Fix immediately",
  sprint:    "Fix this sprint",
  backlog:   "Backlog",
  monitor:   "Monitor",
};

export const URGENCY_DESC: Record<Urgency, string> = {
  immediate: "Exploitability score ≥ 8.0 — reachable (often from an entry point) with high real-world impact. Prioritize over other open findings.",
  sprint:    "Exploitability score ≥ 6.0 — meaningful real-world risk; plan a fix within the current sprint.",
  backlog:   "Exploitability score ≥ 4.0 — lower reachability/impact right now; track and fix without urgent priority.",
  monitor:   "Exploitability score below 4.0 — low real-world risk today (often unreachable); revisit if reachability changes.",
};
