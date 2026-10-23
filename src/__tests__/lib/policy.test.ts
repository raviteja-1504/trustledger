import { DEFAULT_POLICY, PRESETS, loadPolicy, savePolicy, evaluatePolicy, withOrgSettings } from "@/lib/policy";

const makeFiles = (overrides: Partial<{ risk_score: string; attested: boolean; ai_percentage: number }>[]) =>
  overrides.map((o, i) => ({
    file_path: `src/file${i}.py`,
    risk_score: o.risk_score ?? "LOW",
    attested:   o.attested   ?? true,
    ai_percentage: o.ai_percentage ?? 0.1,
  }));

describe("policy lib", () => {
  beforeEach(() => localStorage.clear());

  // ── loadPolicy / savePolicy ───────────────────────────────────────────────

  it("loadPolicy returns DEFAULT_POLICY when nothing stored", () => {
    const p = loadPolicy();
    expect(p.name).toBe(DEFAULT_POLICY.name);
    expect(p.ai_flag_threshold).toBe(DEFAULT_POLICY.ai_flag_threshold);
  });

  it("loadPolicy returns saved values after savePolicy", () => {
    const custom = { ...DEFAULT_POLICY, name: "Custom", ai_flag_threshold: 0.4 };
    savePolicy(custom);
    const loaded = loadPolicy();
    expect(loaded.name).toBe("Custom");
    expect(loaded.ai_flag_threshold).toBe(0.4);
  });

  it("loadPolicy falls back to default when stored JSON is corrupt", () => {
    localStorage.setItem("tl_org_policy", "{ not valid json");
    const p = loadPolicy();
    expect(p.name).toBe(DEFAULT_POLICY.name);
  });

  // ── PRESETS ───────────────────────────────────────────────────────────────

  it("strict preset has lower ai_flag_threshold than standard", () => {
    expect(PRESETS.standard.ai_flag_threshold).toBeGreaterThan(PRESETS.strict.ai_flag_threshold);
  });

  it("strict preset blocks critical AND high AND medium", () => {
    expect(PRESETS.strict.block_on_critical).toBe(true);
    expect(PRESETS.strict.block_on_high).toBe(true);
    expect(PRESETS.strict.block_on_medium).toBe(true);
  });

  it("standard preset does not block medium", () => {
    expect(PRESETS.standard.block_on_medium).toBe(false);
  });

  // ── evaluatePolicy ────────────────────────────────────────────────────────

  it("fails when unattested CRITICAL file exists", () => {
    const files = makeFiles([{ risk_score:"CRITICAL", attested:false, ai_percentage:0.9 }]);
    const result = evaluatePolicy(DEFAULT_POLICY, files, new Set());
    expect(result.pass).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].severity).toBe("critical");
    expect(result.gated).toBe(true);
  });

  it("passes when CRITICAL file is attested", () => {
    const files = makeFiles([{ risk_score:"CRITICAL", attested:true, ai_percentage:0.9 }]);
    const result = evaluatePolicy(DEFAULT_POLICY, files, new Set());
    expect(result.pass).toBe(true);
    expect(result.violations).toHaveLength(0);
    expect(result.gated).toBe(false);
  });

  it("uses attestedSet override for unattested files", () => {
    const files  = makeFiles([{ risk_score:"CRITICAL", attested:false, ai_percentage:0.9 }]);
    const attSet = new Set(["src/file0.py"]);
    const result = evaluatePolicy(DEFAULT_POLICY, files, attSet);
    expect(result.pass).toBe(true);
  });

  it("fails when ai_percentage exceeds ai_flag_threshold on unattested HIGH file", () => {
    const policy = { ...DEFAULT_POLICY, ai_flag_threshold: 0.5 };
    const files  = makeFiles([{ risk_score:"HIGH", attested:false, ai_percentage:0.8 }]);
    const result = evaluatePolicy(policy, files, new Set());
    expect(result.pass).toBe(false);
  });

  it("the AI reason never reads 'X% exceeds X%': decimals only when whole percents would hide the excess", () => {
    const policy = { ...DEFAULT_POLICY, block_on_high: false, ai_flag_threshold: 0.8 };
    const reason = (ai: number) => evaluatePolicy(policy, makeFiles([{ risk_score: "HIGH", attested: false, ai_percentage: ai }]), new Set()).violations[0].reason;
    expect(reason(0.99)).toBe("AI content 99% exceeds org threshold of 80%");
    // rounded down, never up: 80.5 is shown as 80.5, not 81
    expect(reason(0.805)).toBe("AI content 80.5% exceeds org threshold of 80%");
    expect(reason(0.81)).toBe("AI content 81% exceeds org threshold of 80%");
    expect(reason(0.8049)).toBe("AI content 80.4% exceeds org threshold of 80%");
    expect(reason(0.80012)).toBe("AI content 80.01% exceeds org threshold of 80%");
    expect(reason(0.8000001)).toBe("AI content 80.00% exceeds org threshold of 80%");
  });

  it("counts which violations block the merge; the AI-threshold ones are to review", () => {
    const files = makeFiles([
      { risk_score: "CRITICAL", attested: false, ai_percentage: 0.1 },
      { risk_score: "HIGH", attested: false, ai_percentage: 0.95 },
      { risk_score: "HIGH", attested: false, ai_percentage: 0.1 },
    ]);
    const noHigh = evaluatePolicy({ ...DEFAULT_POLICY, block_on_high: false, ai_flag_threshold: 0.8 }, files, new Set());
    expect(noHigh.violations.map(v => v.severity)).toEqual(["critical", "medium"]);
    expect([noHigh.blocking, noHigh.gated]).toEqual([1, true]);
    const both = evaluatePolicy({ ...DEFAULT_POLICY, block_on_high: true, ai_flag_threshold: 0.8 }, files, new Set());
    expect([both.violations.length, both.blocking]).toEqual([3, 3]);
    const none = evaluatePolicy({ ...DEFAULT_POLICY, block_on_critical: false, block_on_high: false, ai_flag_threshold: 0.8 }, files, new Set());
    expect([none.blocking, none.gated, none.pass]).toEqual([0, false, false]);
  });

  it("the org's server settings win over this browser's copy; missing ones keep it", () => {
    const local = { ...DEFAULT_POLICY, block_on_high: true, ai_flag_threshold: 0.5 };
    expect(withOrgSettings(local, { block_on_critical: true, block_on_high: false, ai_threshold: 0.8 }))
      .toMatchObject({ block_on_critical: true, block_on_high: false, ai_flag_threshold: 0.8 });
    expect(withOrgSettings(local, { block_on_high: null })).toMatchObject({ block_on_high: true, ai_flag_threshold: 0.5 });
    expect(withOrgSettings(local, { block_on_critical: false })).toMatchObject({ block_on_critical: false, block_on_high: true });
    expect(withOrgSettings(local, undefined)).toBe(local);
  });

  it("passes when all files are LOW risk with no threshold breach", () => {
    const files  = makeFiles([
      { risk_score:"LOW", attested:false, ai_percentage:0.1 },
      { risk_score:"LOW", attested:false, ai_percentage:0.2 },
    ]);
    const result = evaluatePolicy(DEFAULT_POLICY, files, new Set());
    expect(result.pass).toBe(true);
  });
});
