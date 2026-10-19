/**
 * Security posture domains: one card per governance area, each built from a real source and nothing else.
 * A source that hasn't loaded is "unknown" (never a default number). Pure, client-safe.
 */
import type { Dimension, GovernanceScore } from "./governanceScore";
import type { EvidenceOverview } from "./evidenceEngine";

export interface PostureSources {
  score: GovernanceScore | null;
  dependencies: { vulnerable: number; hallucinated: number; typosquatting: number; critical: number; exploits: number; license_issues: number } | null | "unavailable";
  incidents: ReadonlyArray<{ status: string; severity: string }> | null | "unavailable";
  evidence: EvidenceOverview | null | "unavailable";
}

export interface PostureDomain {
  key: string;
  name: string;
  /** Where the numbers come from, in a few words. */
  source: string;
  status: "good" | "warn" | "bad" | "unknown";
  grade?: Dimension["grade"];
  headline: string;
  headlineLabel: string;
  /** 0-1 bar, for score-style domains. */
  value: number | null;
  facts: string[];
  href: string;
  cta: string;
}

const DIM: Record<Dimension["key"], { name: string; href: string; cta: string }> = {
  exposure:  { name: "Open risk",                   href: "/violations",  cta: "violations" },
  review:    { name: "Review of risky code",         href: "/dashboard#review-queue", cta: "review queue" },
  sla:       { name: "Fix deadlines",                href: "/sla",         cta: "SLA tracker" },
  secrets:   { name: "Leaked secrets",               href: "/secrets",     cta: "secrets" },
  shadow_ai: { name: "Approved AI tools",            href: "/shadow-ai",   cta: "Shadow AI" },
  coverage:  { name: "Scan coverage",                href: "/scans",       cta: "scan history" },
};

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const fromGrade = (g: Dimension["grade"]): PostureDomain["status"] => g === "A" || g === "B" ? "good" : g === "C" ? "warn" : "bad";

function unknown(key: string, name: string, source: string, href: string, cta: string, loading: boolean): PostureDomain {
  return { key, name, source, status: "unknown", headline: "—", headlineLabel: loading ? "Loading…" : "Couldn't load", value: null, facts: [], href, cta };
}

export function buildPostureDomains(s: PostureSources): PostureDomain[] {
  const out: PostureDomain[] = [];

  // The six Trust Score dimensions, as computed by the server.
  const order: Dimension["key"][] = ["exposure", "review", "sla", "secrets", "shadow_ai", "coverage"];
  for (const key of order) {
    const meta = DIM[key];
    const d = s.score?.dimensions.find(x => x.key === key);
    if (!d) { out.push(unknown(key, meta.name, "Trust Score", meta.href, meta.cta, s.score == null)); continue; }
    out.push({
      key, name: meta.name, source: `Trust Score · ${d.points}/${d.max_points} pts`, status: fromGrade(d.grade), grade: d.grade,
      headline: `${Math.round(d.value * 100)}%`, headlineLabel: d.label, value: d.value, facts: d.facts, href: meta.href, cta: meta.cta,
    });
  }

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
