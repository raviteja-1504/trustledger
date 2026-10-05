/**
 * @jest-environment node
 *
 * Every API write (POST/PATCH/PUT/DELETE) must check what the caller may do -- requirePermission,
 * requireRole, requirePlatformAdmin, permissionsFor -- or be one of the reviewed exceptions below.
 * A new write route without a check fails here; so does an exception that now has one (or no longer exists).
 */

type Handler = { route: string; method: string; checked: boolean };
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { audit } = require("../../../scripts/routeAuthAudit.cjs") as { audit: () => Handler[] };

/** Writes that are deliberately not permission-gated, and why. */
const EXCEPTIONS: Record<string, string> = {
  "POST alerts/recheck":        "Re-derives alert state from the database (resolves an alert only once its repo has no open violations); takes no decision from the caller.",
  "POST auth/2fa/login":        "The caller's own sign-in step.",
  "POST auth/2fa":              "The caller's own 2FA enrolment.",
  "POST auth/bootstrap":        "The caller's own first sign-in; never joins an org (invites need a confirmed email).",
  "POST claim-admin":           "Only succeeds when the org has no admin at all (recovery path).",
  "POST orgs/create":           "Runs before the caller has an org; creates their own.",
  "PATCH preferences":          "The caller's own notification preferences (identity is forced from the session).",
  "POST scan-worker":           "Queue callback, verified by QStash signature; no user.",
  "POST scim/v2/Users":         "SCIM provisioning, authenticated by the org's SCIM bearer token.",
  "PATCH scim/v2/Users/[id]":   "SCIM provisioning, authenticated by the org's SCIM bearer token.",
  "DELETE scim/v2/Users/[id]":  "SCIM provisioning, authenticated by the org's SCIM bearer token.",
  "POST slack/commands":        "Verified by Slack request signature; attest maps the Slack user to a member and checks their permissions.",
  "POST stripe/webhook":        "Verified by Stripe signature; no user.",
  "POST trust-record/verify":   "Public verification of a signed Trust Record; reads only.",
  "POST webhook/bitbucket":     "Inbound webhook, verified by signature.",
  "POST webhook/github":        "Inbound webhook, verified by signature.",
  "POST webhook/gitlab":        "Inbound webhook, verified by token.",
};

describe("API write authorization", () => {
  const handlers = audit();
  const key = (h: Handler) => `${h.method} ${h.route}`;

  it("finds the write handlers (sanity)", () => {
    expect(handlers.length).toBeGreaterThan(50);
    expect(handlers.find(h => key(h) === "POST attest")?.checked).toBe(true);
    // delegation into a same-file helper counts
    expect(handlers.find(h => key(h) === "POST scans/pr")?.checked).toBe(true);
  });

  it("every write checks permissions or is a reviewed exception", () => {
    expect(handlers.filter(h => !h.checked && !EXCEPTIONS[key(h)]).map(key)).toEqual([]);
  });

  it("no stale exceptions", () => {
    const byKey = new Map(handlers.map(h => [key(h), h]));
    expect(Object.keys(EXCEPTIONS).filter(k => !byKey.has(k) || byKey.get(k)!.checked)).toEqual([]);
  });
});
