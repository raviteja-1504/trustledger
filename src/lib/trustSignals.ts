/**
 * Signals shown on the Trust Score page next to the score's own dimensions: dependencies, incidents and audit
 * evidence. They aren't part of the 0-1000 number (that comes from lib/governanceScore.ts), but they are part of
 * how trustworthy the code is, so they sit beside it. Each is built from its real source only; a source that
 * hasn't loaded is "unknown" -- never a default number. Pure, client-safe.
 *
 * (These were the Security posture page's extra cards; that page otherwise repeated the Trust Score.)
 */
import type { EvidenceOverview } from "./evidenceEngine";

export interface SignalSources {
  dependencies: { vulnerable: number; hallucinated: number; typosquatting: number; critical: number; exploits: number; license_issues: number } | null | "unavailable";
  incidents: ReadonlyArray<{ status: string; severity: string }> | null | "unavailable";
  evidence: EvidenceOverview | null | "unavailable";
}

export interface TrustSignal {
  key: "dependencies" | "incidents" | "evidence";
  name: string;
  /** Where the numbers come from, in a few words. */
  source: string;
  status: "good" | "warn" | "bad" | "unknown";
  headline: string;
  headlineLabel: string;
  /** 0-1 bar, when the signal is a proportion. */
  value: number | null;
  facts: string[];
  href: string;
  cta: string;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function unknown(key: TrustSignal["key"], name: string, source: string, href: string, cta: string, loading: boolean): TrustSignal {
  return { key, name, source, status: "unknown", headline: "—", headlineLabel: loading ? "Loading…" : "Couldn't load", value: null, facts: [], href, cta };
}

export function buildTrustSignals(s: SignalSources): TrustSignal[] {
  const out: TrustSignal[] = [];

  // Dependencies.
  if (s.dependencies == null || s.dependencies === "unavailable") {
    out.push(unknown("dependencies", "Dependencies", "Latest scan of each repository", "/dependencies", "dependencies", s.dependencies == null));
  } else {
    const c = s.dependencies;
    const risky = c.vulnerable + c.hallucinated + c.typosquatting;
    out.push({
      key: "dependencies", name: "Dependencies", source: "Latest scan of each repository",
      status: c.critical > 0 || c.hallucinated > 0 || c.typosquatting > 0 || c.exploits > 0 ? "bad" : c.vulnerable > 0 || c.license_issues > 0 ? "warn" : "good",
      headline: String(risky), headlineLabel: risky === 1 ? "risky package" : "risky packages", value: null,
      facts: [
        `${plural(c.vulnerable, "known-vulnerable package")}${c.critical ? ` (${c.critical} critical)` : ""}`,
        ...(c.exploits ? [`${plural(c.exploits, "package")} with a public exploit`] : []),
        ...(c.hallucinated || c.typosquatting ? [`${plural(c.hallucinated, "package")} that doesn't exist, ${plural(c.typosquatting, "possible typosquat")}`] : []),
        ...(c.license_issues ? [`${plural(c.license_issues, "license")} to review`] : []),
      ],
      href: "/dependencies", cta: "dependencies",
    });
  }

  // Incidents (active only).
  if (s.incidents == null || s.incidents === "unavailable") {
    out.push(unknown("incidents", "Incidents", "Active incidents", "/incidents", "incidents", s.incidents == null));
  } else {
    const active = s.incidents.filter(i => i.status === "active");
    const p1 = active.filter(i => i.severity === "P1").length;
    out.push({
      key: "incidents", name: "Incidents", source: "Active incidents",
      status: p1 > 0 ? "bad" : active.length > 0 ? "warn" : "good",
      headline: String(active.length), headlineLabel: active.length === 1 ? "active incident" : "active incidents", value: null,
      facts: active.length ? [`${p1} P1 · ${active.length - p1} lower severity`] : ["No active incidents"],
      href: "/incidents", cta: "incidents",
    });
  }

  // Audit evidence.
  if (s.evidence == null || s.evidence === "unavailable") {
    out.push(unknown("evidence", "Audit evidence", "Control evidence", "/compliance", "compliance", s.evidence == null));
  } else {
    const fws = s.evidence.frameworks;
    const total = fws.reduce((a, f) => a + f.controls.length, 0);
    const pass = fws.reduce((a, f) => a + f.status_counts.pass, 0);
    const failing = s.evidence.gaps.filter(g => g.status === "fail").length;
    out.push({
      key: "evidence", name: "Audit evidence", source: `${fws.map(f => f.short).join(" · ")}`,
      status: failing > 0 ? "bad" : s.evidence.gaps.length > 0 ? "warn" : total ? "good" : "unknown",
      headline: total ? `${pass}/${total}` : "—", headlineLabel: "controls with evidence", value: total ? pass / total : null,
      facts: s.evidence.gaps.slice(0, 3).map(g => `${g.label}: ${g.gaps[0]}`),
      href: "/compliance", cta: "compliance",
    });
  }
  return out;
}
