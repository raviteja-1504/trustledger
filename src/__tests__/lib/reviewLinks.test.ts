/**
 * Links to a high-risk file (lib/reviewLinks.ts): only someone whose role may sign the file off is sent to its
 * attestation form; a developer is sent to the file itself.
 */
import { deepLinkAction, fileReviewHref } from "@/lib/reviewLinks";

describe("fileReviewHref", () => {
  it("the sign-off for someone who may attest, the file itself for anyone else", () => {
    expect(fileReviewHref("s1", "src/pay.ts", true)).toBe("/pr/s1?attest=src%2Fpay.ts");
    expect(fileReviewHref("s1", "src/pay.ts", false)).toBe("/pr/s1?file=src%2Fpay.ts");
  });
});

describe("deepLinkAction (the PR page's ?attest= / ?file=)", () => {
  it("?attest= opens the form only for a viewer whose role may sign the file off", () => {
    expect(deepLinkAction("attest", false, true)).toBe("attest");
    // a developer following someone else's attest link: the file, read-only, with the reason
    expect(deepLinkAction("attest", false, false)).toBe("open-read-only");
  });

  it("an already signed-off file, or ?file=, just opens the file", () => {
    expect(deepLinkAction("attest", true, true)).toBe("open");
    expect(deepLinkAction("attest", true, false)).toBe("open");
    expect(deepLinkAction("file", false, true)).toBe("open");
    expect(deepLinkAction("file", false, false)).toBe("open");
  });
});
