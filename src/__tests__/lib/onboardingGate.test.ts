/**
 * @jest-environment node
 */
import { onboardingAction, needsSetup } from "@/lib/onboardingGate";

describe("who is sent to the setup wizard", () => {
  it("nobody whose onboarding is complete", () => {
    expect(onboardingAction({ complete: true, members: 1, has_scans: false }, false)).toBe("none");
  });
  it("a brand-new organisation (named by create-org, sole member, no scans): setup, once per session", () => {
    expect(onboardingAction({ complete: false, org_name: "Acme", members: 1, has_scans: false }, false)).toBe("setup");
    // the creator left the wizard on purpose: not sent back on every page, and NOT marked complete
    expect(onboardingAction({ complete: false, org_name: "Acme", members: 1, has_scans: false }, true)).toBe("none");
  });
  it("an admin who joined an organisation that already has other members: marked complete, never sent to setup", () => {
    expect(onboardingAction({ complete: false, org_name: "Acme", members: 4, has_scans: false }, false)).toBe("complete");
    expect(onboardingAction({ complete: false, org_name: "Acme", members: 4, has_scans: true }, true)).toBe("complete");
  });
  it("a creator who scanned something but skipped steps still gets setup (leaving it part-way does not complete it)", () => {
    expect(onboardingAction({ complete: false, org_name: "Acme", members: 1, has_scans: true }, false)).toBe("setup");
  });
  it("an older server answer without the counts is treated as a new organisation", () => {
    expect(onboardingAction({ complete: false, org_name: "Acme" }, false)).toBe("setup");
  });
  it("needsSetup: the overview offers setup until it is complete, to a sole member only", () => {
    expect(needsSetup({ complete: false, members: 1 })).toBe(true);
    expect(needsSetup({ complete: false })).toBe(true);
    expect(needsSetup({ complete: true, members: 1 })).toBe(false);
    expect(needsSetup({ complete: false, members: 3 })).toBe(false);
  });
});
