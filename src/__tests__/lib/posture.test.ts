/**
 * Security posture domains (lib/posture.ts): each from its real source; unknown when a source hasn't loaded,
 * never a default number.
 */
import { buildPostureDomains } from "@/lib/posture";
import type { Dimension, GovernanceScore } from "@/lib/governanceScore";
import type { EvidenceOverview } from "@/lib/evidenceEngine";

const dim = (key: Dimension["key"], value: number, grade: Dimension["grade"], facts: string[] = []): Dimension =>
  ({ key, label: key, weight: 0.2, value, points: Math.round(value * 100), max_points: 100, gain: 0, grade, formula: "", facts, actions: [] });
const score: GovernanceScore = {
  total: 700, band: "Good", computed_at: "x", repos: [],
  dimensions: [dim("exposure", 0.8, "B", ["2 open CRITICAL"]), dim("review", 0.6, "C"), dim("sla", 0.3, "F"), dim("secrets", 1, "A"), dim("shadow_ai", 0.9, "A"), dim("coverage", 0.5, "D")],
};
const evidence: EvidenceOverview = {
  period_start: "a", period_end: "b", generated_at: "c",
  frameworks: [{ id: "soc2", name: "SOC 2", short: "SOC 2", status_counts: { pass: 3, partial: 1, fail: 0, not_tested: 0 }, controls: [1, 2, 3, 4].map(i => ({ control_id: `c${i}`, control_name: "x", status: "pass" as const })) }],
  gaps: [{ key: "review", label: "High-risk changes reviewed", status: "partial", gaps: ["3 files not reviewed"] }],
};

describe("buildPostureDomains", () => {
  it("score domains come from the Trust Score dimensions, graded as the server graded them", () => {
    const d = Object.fromEntries(buildPostureDomains({ score, dependencies: null, incidents: null, evidence: null }).map(x => [x.key, x]));
    expect(d.exposure).toMatchObject({ status: "good", grade: "B", headline: "80%", value: 0.8, facts: ["2 open CRITICAL"], href: "/violations" });
    expect(d.review).toMatchObject({ status: "warn", grade: "C" });
    expect(d.sla).toMatchObject({ status: "bad", grade: "F", href: "/sla" });
    expect(d.coverage.status).toBe("bad");
  });

  it("nothing loaded → every domain unknown, with no numbers", () => {
    const all = buildPostureDomains({ score: null, dependencies: null, incidents: null, evidence: null });
    expect(all).toHaveLength(9);
    expect(all.every(x => x.status === "unknown" && x.headline === "—" && x.headlineLabel === "Loading…")).toBe(true);
    const failed = buildPostureDomains({ score: null, dependencies: "unavailable", incidents: "unavailable", evidence: "unavailable" });
    expect(failed.filter(x => x.key === "dependencies" || x.key === "incidents" || x.key === "evidence").map(x => x.headlineLabel)).toEqual(["Couldn't load", "Couldn't load", "Couldn't load"]);
  });

  it("dependencies: critical, exploits, made-up or typosquatted packages are at risk; plain vulnerable needs work", () => {
    const deps = (o: Partial<{ vulnerable: number; hallucinated: number; typosquatting: number; critical: number; exploits: number; license_issues: number }>) =>
      buildPostureDomains({ score, dependencies: { vulnerable: 0, hallucinated: 0, typosquatting: 0, critical: 0, exploits: 0, license_issues: 0, ...o }, incidents: [], evidence }).find(x => x.key === "dependencies")!;
    expect(deps({}).status).toBe("good");
    expect(deps({ vulnerable: 2 })).toMatchObject({ status: "warn", headline: "2" });
    expect(deps({ vulnerable: 2, critical: 1 }).status).toBe("bad");
    expect(deps({ hallucinated: 1 }).status).toBe("bad");
    expect(deps({ typosquatting: 1 }).status).toBe("bad");
    expect(deps({ vulnerable: 1, exploits: 1 }).status).toBe("bad");
    expect(deps({ license_issues: 1 }).status).toBe("warn");
  });

  it("incidents: any active P1 is at risk; other active ones need work; resolved ones don't count", () => {
    const inc = (list: Array<{ status: string; severity: string }>) => buildPostureDomains({ score, dependencies: null, incidents: list, evidence }).find(x => x.key === "incidents")!;
    expect(inc([])).toMatchObject({ status: "good", headline: "0" });
    expect(inc([{ status: "active", severity: "P2" }, { status: "resolved", severity: "P1" }])).toMatchObject({ status: "warn", headline: "1" });
    expect(inc([{ status: "active", severity: "P1" }]).status).toBe("bad");
  });

  it("audit evidence: controls with evidence across frameworks, with the gaps", () => {
    const ev = buildPostureDomains({ score, dependencies: null, incidents: [], evidence }).find(x => x.key === "evidence")!;
    expect(ev).toMatchObject({ status: "warn", headline: "3/4", value: 0.75, facts: ["High-risk changes reviewed: 3 files not reviewed"] });
    const failing = { ...evidence, gaps: [{ ...evidence.gaps[0], status: "fail" as const }] };
    expect(buildPostureDomains({ score, dependencies: null, incidents: [], evidence: failing }).find(x => x.key === "evidence")!.status).toBe("bad");
    expect(buildPostureDomains({ score, dependencies: null, incidents: [], evidence: { ...evidence, gaps: [] } }).find(x => x.key === "evidence")!.status).toBe("good");
  });
});
