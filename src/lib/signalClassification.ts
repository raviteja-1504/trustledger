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
