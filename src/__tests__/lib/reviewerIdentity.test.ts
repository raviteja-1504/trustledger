/**
 * The reviewer the PR page shows in Review & Attest (lib/reviewerIdentity.ts): signed in, always the signed-in
 * account -- a reviewer remembered in the browser from an earlier sign-in used to be shown instead.
 */
import { resolveReviewer } from "@/lib/reviewerIdentity";

const stale = { email: "old-user@a.test", github: "old-gh" };

describe("resolveReviewer", () => {
  it("signed in: the signed-in account, never the remembered reviewer", () => {
    expect(resolveReviewer({ email: "me@a.test", github_login: "me-gh" }, stale))
      .toEqual({ email: "me@a.test", github: "me-gh", signedIn: true });
    // no GitHub login on the profile: empty, not the remembered handle
    expect(resolveReviewer({ email: "me@a.test", github_login: null }, stale))
      .toEqual({ email: "me@a.test", github: "", signedIn: true });
  });

  it("no profile (demo mode): the remembered reviewer, if its email is valid", () => {
    expect(resolveReviewer(null, stale)).toEqual({ email: "old-user@a.test", github: "old-gh", signedIn: false });
    expect(resolveReviewer({ email: "" }, { email: "not-an-email", github: "" })).toEqual({ email: "", github: "", signedIn: false });
  });
});
