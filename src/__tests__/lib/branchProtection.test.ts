/**
 * @jest-environment node
 *
 * Branch-protection snapshot (lib/branchProtection.ts + readBranchProtection in lib/github.ts): rulesets and classic
 * protection combined; a setting that can't be read is Unknown, never shown as off.
 */
import { normalizeProtection, protectionValue, type RawProtection } from "@/lib/branchProtection";
import { readBranchProtection } from "@/lib/github";

const raw = (over: Partial<RawProtection> = {}): RawProtection => ({ repo: "acme/api", branch: "main", protected: true, rules: [], classic: "none", ...over });

describe("normalizeProtection", () => {
  it("rulesets: pull request with approvals, stale dismissal, checks and force-push blocking", () => {
    const p = normalizeProtection(raw({ rules: [
      { type: "pull_request", parameters: { required_approving_review_count: 2, dismiss_stale_reviews_on_push: true, require_code_owner_review: false, require_last_push_approval: true } },
      { type: "required_status_checks", parameters: { required_status_checks: [{ context: "ci/test" }, { context: "TrustLedger" }] } },
      { type: "non_fast_forward" },
    ] }));
    expect(p).toMatchObject({ pull_request_required: true, approvals_required: 2, dismiss_stale_approvals: true, code_owner_review: false,
      last_push_approval: true, required_status_checks: ["TrustLedger", "ci/test"], force_push_blocked: true, admins_included: null, sources: ["ruleset"] });
    expect(p.limits).toEqual([expect.stringMatching(/bypass/)]);
  });

  it("classic protection, readable: its settings, the stricter of the two sources, checks merged once", () => {
    const p = normalizeProtection(raw({
      rules: [{ type: "pull_request", parameters: { required_approving_review_count: 1 } }, { type: "required_status_checks", parameters: { required_status_checks: [{ context: "ci/test" }] } }],
      classic: { required_pull_request_reviews: { required_approving_review_count: 3, dismiss_stale_reviews: true }, required_status_checks: { contexts: ["ci/test", "lint"] },
        enforce_admins: { enabled: true }, allow_force_pushes: { enabled: false } },
    }));
    expect(p).toMatchObject({ approvals_required: 3, dismiss_stale_approvals: true, required_status_checks: ["ci/test", "lint"], force_push_blocked: true,
      admins_included: true, sources: ["ruleset", "classic"] });
  });

  it("classic protection on but not readable: what only it could set is Unknown, and the limit is stated", () => {
    const p = normalizeProtection(raw({ classic: "unreadable" }));
    expect(p).toMatchObject({ pull_request_required: null, approvals_required: null, dismiss_stale_approvals: null, force_push_blocked: null });
    expect(p.limits.join(" ")).toMatch(/Administration: read/);
    expect(protectionValue(p.approvals_required)).toBe("Unknown");
    // a ruleset requirement is still known to be on
    expect(normalizeProtection(raw({ classic: "unreadable", rules: [{ type: "pull_request", parameters: { required_approving_review_count: 1 } }] })))
      .toMatchObject({ pull_request_required: true, approvals_required: 1, dismiss_stale_approvals: null });
  });

  it("an unprotected branch: nothing required, stated as No / 0", () => {
    const p = normalizeProtection(raw({ protected: false, classic: "none" }));
    expect(p).toMatchObject({ pull_request_required: false, approvals_required: 0, dismiss_stale_approvals: false, force_push_blocked: false, sources: [] });
    expect(p.limits).toEqual([]);
    expect([protectionValue(false), protectionValue(0), protectionValue(true)]).toEqual(["No", "0", "Yes"]);
  });

  it("a repository GitHub wouldn't show: every setting Unknown, with the reason", () => {
    const p = normalizeProtection(raw({ error: "repository 404", branch: null, protected: null }));
    expect(p).toMatchObject({ pull_request_required: null, approvals_required: null, force_push_blocked: null });
    expect(p.limits).toEqual(["GitHub couldn't be read for this repository (repository 404)"]);
  });

  it("rulesets that couldn't be read are stated", () => {
    expect(normalizeProtection(raw({ rules: null })).limits).toContain("Repository rulesets couldn't be read.");
  });
});

describe("readBranchProtection", () => {
  const realFetch = global.fetch;
  afterEach(() => { global.fetch = realFetch; });
  const respond = (routes: Record<string, [number, unknown]>) => {
    const urls: string[] = [];
    global.fetch = jest.fn(async (url: string) => {
      urls.push(url);
      const hit = Object.entries(routes).find(([k]) => url.includes(k));
      const [status, body] = hit ? hit[1] : [500, {}];
      return { ok: status < 300, status, json: async () => body } as Response;
    }) as unknown as typeof fetch;
    return urls;
  };

  it("reads the default branch, then its rulesets and classic protection (404 = none)", async () => {
    const urls = respond({
      "/branches/release%2Fv2/protection": [404, {}],
      "/rules/branches/release%2Fv2": [200, [{ type: "non_fast_forward" }]],
      "/branches/release%2Fv2": [200, { protected: true }],
      "/repos/acme/api": [200, { default_branch: "release/v2" }],
    });
    expect(await readBranchProtection("t", "acme", "api")).toEqual({
      repo: "acme/api", branch: "release/v2", protected: true, rules: [{ type: "non_fast_forward" }], classic: "none",
    });
    expect(urls[0]).toMatch(/\/repos\/acme\/api$/);
  });

  it("403 on classic protection = unreadable, not absent", async () => {
    respond({ "/branches/main/protection": [403, {}], "/rules/branches/main": [200, []], "/branches/main": [200, { protected: true }], "/repos/acme/api": [200, { default_branch: "main" }] });
    expect((await readBranchProtection("t", "acme", "api")).classic).toBe("unreadable");
  });

  it("a repository it can't read, or a network failure, comes back as an error rather than throwing", async () => {
    respond({ "/repos/acme/api": [404, {}] });
    expect(await readBranchProtection("t", "acme", "api")).toMatchObject({ error: "repository 404" });
    global.fetch = jest.fn(async () => { throw new Error("ECONNRESET"); }) as unknown as typeof fetch;
    expect(await readBranchProtection("t", "acme", "api")).toMatchObject({ error: "ECONNRESET" });
  });
});
