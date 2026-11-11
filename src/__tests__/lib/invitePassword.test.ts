/**
 * @jest-environment node
 *
 * An invited person is signed in by the emailed link with no password: they are offered one, once.
 */
import { invitePasswordUrl, needsInvitePassword } from "@/lib/invitePassword";

describe("who must choose a password", () => {
  it("every invited person who has not set one", () => {
    expect(needsInvitePassword({ invited_at: "2026-11-10T10:00:00Z" })).toBe(true);
    expect(needsInvitePassword({ invited_at: "2026-11-10T10:00:00Z", user_metadata: { name: "Ada" } as never })).toBe(true);
  });
  it("not once they have set one", () => {
    expect(needsInvitePassword({ invited_at: "2026-11-10T10:00:00Z", user_metadata: { password_set: true } })).toBe(false);
  });
  it("nothing excuses them: a 'Not now' stored by an earlier build no longer counts", () => {
    expect(needsInvitePassword({ invited_at: "2026-11-10T10:00:00Z", user_metadata: { password_prompt_dismissed: true } as never })).toBe(true);
  });
  it("not people who signed themselves up, and nobody when signed out", () => {
    expect(needsInvitePassword({})).toBe(false);
    expect(needsInvitePassword({ invited_at: null })).toBe(false);
    expect(needsInvitePassword(null)).toBe(false);
    expect(needsInvitePassword(undefined)).toBe(false);
  });
  it("only an exact true counts (a stray string does not silence the prompt)", () => {
    expect(needsInvitePassword({ invited_at: "x", user_metadata: { password_set: "true" } })).toBe(true);
  });
});

describe("invitePasswordUrl", () => {
  it("keeps where they were going, encoded", () => {
    expect(invitePasswordUrl("/pr/abc?tab=files")).toBe("/login?setup=password&next=%2Fpr%2Fabc%3Ftab%3Dfiles");
  });
});
