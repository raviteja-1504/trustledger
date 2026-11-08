import { CAPS, PLAN_LIMITS, RATE_CAPS, WARN_AT, isTruncated, limitMessage, limitStatus, planLimits, rateText } from "@/lib/limits";
import { RATE_LIMITS } from "@/lib/rateLimit";
import { MAX_CHECK_ANNOTATIONS } from "@/lib/checkAnnotations";
import { MAX_LOCATIONS } from "@/lib/ruleUsage";

describe("limitStatus", () => {
  it("is ok well under the cap, warns from 80%, is full at the cap and over past it", () => {
    expect(limitStatus(50, 100).level).toBe("ok");
    expect(limitStatus(79, 100).level).toBe("ok");
    expect(limitStatus(80, 100).level).toBe("warn");
    expect(limitStatus(99, 100).level).toBe("warn");
    expect(limitStatus(100, 100).level).toBe("full");
    expect(limitStatus(101, 100).level).toBe("over");
    expect(WARN_AT).toBe(0.8);
  });
  it("reports the percentage (capped at 100) and what is left (never negative)", () => {
    expect(limitStatus(25, 100)).toMatchObject({ pct: 25, remaining: 75 });
    expect(limitStatus(150, 100)).toMatchObject({ pct: 100, remaining: 0 });
  });
  it("-1 is unlimited: no percentage, no warning, nothing remaining to count", () => {
    expect(limitStatus(5_000_000, -1)).toEqual({ used: 5_000_000, limit: -1, pct: 0, level: "unlimited", remaining: null });
  });
  it("a zero limit is full the moment anything is used, and ok when nothing is", () => {
    expect(limitStatus(0, 0).level).toBe("full");
    expect(limitStatus(1, 0)).toMatchObject({ level: "over", pct: 100 });
  });
  it("garbage usage counts as zero rather than NaN", () => {
    expect(limitStatus(NaN, 10)).toMatchObject({ used: 0, level: "ok" });
    expect(limitStatus(-4, 10).used).toBe(0);
  });
});

describe("limitMessage", () => {
  it("stays quiet while there is room", () => {
    expect(limitMessage("scans", limitStatus(10, 100))).toBeNull();
    expect(limitMessage("scans", limitStatus(1, -1))).toBeNull();
  });
  it("says how many are left when nearing the cap, and that you are at or over it", () => {
    expect(limitMessage("scans", limitStatus(90, 100))).toBe("10 of 100 scans left on your plan. Consider upgrading before you reach it.");
    expect(limitMessage("scans", limitStatus(100, 100))).toBe("At the limit: all 100 scans on your plan are used. Upgrade your plan to raise it.");
    expect(limitMessage("scans", limitStatus(1_250, 1_000))).toBe("Over the limit: 1,250 scans against 1,000 on your plan. Upgrade your plan to raise it.");
  });
  it("can leave out the upgrade nudge", () => {
    expect(limitMessage("members", limitStatus(3, 3), { upgrade: false })).toBe("At the limit: all 3 members on your plan are used.");
    expect(limitMessage("members", limitStatus(5, 6), { upgrade: false })).toBe("1 of 6 members left on your plan.");
  });
});

describe("plan limits", () => {
  it("an unknown or missing plan gets the trial limits, the most restrictive", () => {
    expect(planLimits("nonsense")).toBe(PLAN_LIMITS.trial);
    expect(planLimits(null)).toBe(PLAN_LIMITS.trial);
    expect(planLimits(undefined)).toBe(PLAN_LIMITS.trial);
  });
  it("plans only get roomier going up, and enterprise is unlimited", () => {
    const order = ["trial", "starter", "growth"] as const;
    for (const k of ["scans", "attestations", "repos", "members", "reports"] as const) {
      expect(PLAN_LIMITS[order[0]][k]).toBeLessThan(PLAN_LIMITS[order[1]][k]);
      expect(PLAN_LIMITS[order[1]][k]).toBeLessThan(PLAN_LIMITS[order[2]][k]);
      expect(PLAN_LIMITS.enterprise[k]).toBe(-1);
    }
  });
});

describe("the registry is the single source for what the server enforces", () => {
  it("rate caps match the enforcing RATE_LIMITS, in the unit users read", () => {
    const perOf = (ms: number) => (ms === 60_000 ? "minute" : ms === 3_600_000 ? "hour" : `${ms}ms`);
    for (const [cap, rl] of [["scan", RATE_LIMITS.scan], ["attest", RATE_LIMITS.attest], ["report", RATE_LIMITS.report], ["keyCreate", RATE_LIMITS.keyCreate]] as const) {
      expect({ cap, limit: RATE_CAPS[cap].limit, per: RATE_CAPS[cap].per }).toEqual({ cap, limit: rl.limit, per: perOf(rl.windowMs) });
    }
  });
  it("code that enforces a cap reads it from the registry", () => {
    expect(MAX_CHECK_ANNOTATIONS).toBe(CAPS.checkAnnotations.value);
    expect(MAX_LOCATIONS).toBe(CAPS.locationsPerRule.value);
  });
  it("every cap says what happens and what to do", () => {
    for (const [id, c] of Object.entries(CAPS)) {
      expect({ id, ok: c.value > 0 && c.effect.length > 20 && c.advice.length > 10 && /[.]$/.test(c.effect) && /[.]$/.test(c.advice) }).toEqual({ id, ok: true });
    }
  });
  it("rateText reads as a sentence", () => {
    expect(rateText("scan")).toBe("60 scan submissions per organisation per minute");
    expect(rateText("rescan")).toBe("1 rescan of the same pull request per minute");
  });
});

describe("isTruncated", () => {
  it("with a known total, compares it to what is shown", () => {
    expect(isTruncated(1000, 1000, 1432)).toBe(true);
    expect(isTruncated(1432, 1000, 1432)).toBe(false);
  });
  it("without a total, a list exactly as long as the cap is assumed cut", () => {
    expect(isTruncated(1000, 1000)).toBe(true);
    expect(isTruncated(999, 1000)).toBe(false);
  });
});
