/**
 * Trust Score page signals beside the score (lib/trustSignals.ts): each from its real source; unknown when a
 * source hasn't loaded, never a default number.
 */
import { buildTrustSignals } from "@/lib/trustSignals";
import type { EvidenceOverview } from "@/lib/evidenceEngine";

const evidence: EvidenceOverview = {
  period_start: "a", period_end: "b", generated_at: "c",
  frameworks: [{ id: "soc2", name: "SOC 2", short: "SOC 2", status_counts: { pass: 3, partial: 1, fail: 0, not_tested: 0 }, controls: [1, 2, 3, 4].map(i => ({ control_id: `c${i}`, control_name: "x", status: "pass" as const })) }],
  gaps: [{ key: "review", label: "High-risk changes reviewed", status: "partial", gaps: ["3 files not reviewed"] }],
};

describe("buildTrustSignals", () => {
  it("three signals, in order; nothing loaded → unknown with no numbers; failed → \"Couldn't load\"", () => {
    const all = buildTrustSignals({ dependencies: null, incidents: null, evidence: null });
    expect(all.map(x => x.key)).toEqual(["dependencies", "incidents", "evidence"]);
    expect(all.every(x => x.status === "unknown" && x.headline === "—" && x.headlineLabel === "Loading…" && x.value === null)).toBe(true);
    const failed = buildTrustSignals({ dependencies: "unavailable", incidents: "unavailable", evidence: "unavailable" });
    expect(failed.map(x => x.headlineLabel)).toEqual(["Couldn't load", "Couldn't load", "Couldn't load"]);
    expect(failed.map(x => x.href)).toEqual(["/dependencies", "/incidents", "/compliance"]);
  });

  it("dependencies: critical, exploits, made-up or typosquatted packages are at risk; plain vulnerable needs work", () => {
    const deps = (o: Partial<{ vulnerable: number; hallucinated: number; typosquatting: number; critical: number; exploits: number; license_issues: number }>) =>
      buildTrustSignals({ dependencies: { vulnerable: 0, hallucinated: 0, typosquatting: 0, critical: 0, exploits: 0, license_issues: 0, ...o }, incidents: [], evidence }).find(x => x.key === "dependencies")!;
    expect(deps({})).toMatchObject({ status: "good", headline: "0", headlineLabel: "risky packages" });
    expect(deps({ vulnerable: 2 })).toMatchObject({ status: "warn", headline: "2" });
    expect(deps({ vulnerable: 1 }).headlineLabel).toBe("risky package");
    expect(deps({ vulnerable: 2, critical: 1 })).toMatchObject({ status: "bad", facts: ["2 known-vulnerable packages (1 critical)"] });
    expect(deps({ hallucinated: 1, typosquatting: 2 })).toMatchObject({ status: "bad", headline: "3" });
    expect(deps({ hallucinated: 1 }).facts).toContain("1 package that doesn't exist, 0 possible typosquats");
    expect(deps({ typosquatting: 1 }).status).toBe("bad");
    expect(deps({ vulnerable: 1, exploits: 1 })).toMatchObject({ status: "bad", facts: ["1 known-vulnerable package", "1 package with a public exploit"] });
    expect(deps({ license_issues: 1 })).toMatchObject({ status: "warn", facts: ["0 known-vulnerable packages", "1 license to review"] });
  });

  it("incidents: any active P1 is at risk; other active ones need work; resolved ones don't count", () => {
    const inc = (list: Array<{ status: string; severity: string }>) => buildTrustSignals({ dependencies: null, incidents: list, evidence }).find(x => x.key === "incidents")!;
    expect(inc([])).toMatchObject({ status: "good", headline: "0", facts: ["No active incidents"] });
    expect(inc([{ status: "active", severity: "P2" }, { status: "resolved", severity: "P1" }])).toMatchObject({ status: "warn", headline: "1", headlineLabel: "active incident", facts: ["0 P1 · 1 lower severity"] });
    expect(inc([{ status: "active", severity: "P1" }, { status: "active", severity: "P1" }])).toMatchObject({ status: "bad", headlineLabel: "active incidents" });
    expect(inc([{ status: "active", severity: "P1" }]).status).toBe("bad");
  });

  it("audit evidence: controls with evidence across frameworks, with the gaps", () => {
    const ev = buildTrustSignals({ dependencies: null, incidents: [], evidence }).find(x => x.key === "evidence")!;
    expect(ev).toMatchObject({ status: "warn", headline: "3/4", value: 0.75, source: "SOC 2", facts: ["High-risk changes reviewed: 3 files not reviewed"] });
    const failing = { ...evidence, gaps: [{ ...evidence.gaps[0], status: "fail" as const }] };
    expect(buildTrustSignals({ dependencies: null, incidents: [], evidence: failing }).find(x => x.key === "evidence")!.status).toBe("bad");
    expect(buildTrustSignals({ dependencies: null, incidents: [], evidence: { ...evidence, gaps: [] } }).find(x => x.key === "evidence")!.status).toBe("good");
    // No controls at all: nothing to grade, not "good".
    const none = buildTrustSignals({ dependencies: null, incidents: [], evidence: { ...evidence, frameworks: [], gaps: [] } }).find(x => x.key === "evidence")!;
    expect(none).toMatchObject({ status: "unknown", headline: "—", value: null });
  });
});
