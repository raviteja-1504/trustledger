/**
 * @jest-environment node
 */
import { onboardingAction } from "@/lib/onboardingGate";

describe("who is sent to the setup wizard", () => {
  it("nobody whose onboarding is complete", () => {
    expect(onboardingAction({ complete: true, members: 1, has_scans: false }, false)).toBe("none");
  });
  it("a brand-new organisation (named by create-org, sole member, no scans): setup, once per session", () => {
    expect(onboardingAction({ complete: false, org_name: "Acme", members: 1, has_scans: false }, false)).toBe("setup");
    // the creator left the wizard on purpose: not sent back on every page, and NOT marked complete
    expect(onboardingAction({ complete: false, org_name: "Acme", members: 1, has_scans: false }, true)).toBe("none");
  });
  it("an admin who joined a running organisation: marked complete, never sent to setup", () => {
    expect(onboardingAction({ complete: false, org_name: "Acme", members: 4, has_scans: false }, false)).toBe("complete");
    expect(onboardingAction({ complete: false, org_name: "Acme", members: 1, has_scans: true }, false)).toBe("complete");
    expect(onboardingAction({ complete: false, org_name: "Acme", members: 4, has_scans: true }, true)).toBe("complete");
  });
  it("an older server answer without the counts is treated as a new organisation", () => {
    expect(onboardingAction({ complete: false, org_name: "Acme" }, false)).toBe("setup");
  });
});
