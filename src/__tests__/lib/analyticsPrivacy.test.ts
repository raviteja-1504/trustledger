/**
 * What reaches PostHog: no emails, names, or customer data in URLs.
 */
import { identityProperties, sanitizeAnalyticsProperties, scrubUrl, templatePath } from "@/lib/analyticsPrivacy";

describe("paths and URLs", () => {
  it("reduces paths to route patterns", () => {
    expect(templatePath("/repo/acme/payments-api")).toBe("/repo/[...slug]");
    expect(templatePath("/pr/7b1c2d3e-0000-4000-8000-000000000000")).toBe("/pr/[id]");
    expect(templatePath("/settings/team")).toBe("/settings/team");
    expect(templatePath("/scans/12345?repo=acme%2Fsecret")).toBe("/scans/[id]");
    expect(templatePath("/")).toBe("/");
  });

  it("drops query strings and fragments from URLs", () => {
    expect(scrubUrl("https://app.example/repo/acme/api?next=%2Fpr%2F1#x")).toBe("https://app.example/repo/[...slug]");
    expect(scrubUrl("https://app.example/login?error=sso_required&email=a@b.com")).toBe("https://app.example/login");
    expect(scrubUrl("not a url")).toBe("");
  });
});

describe("event properties", () => {
  it("scrubs PostHog's automatic URL properties and our page property", () => {
    const out = sanitizeAnalyticsProperties({
      $current_url: "https://app.example/repo/acme/payments-api?file=src%2Fkeys.ts",
      $pathname: "/repo/acme/payments-api",
      $referrer: "https://github.com/acme/payments-api/pull/42",
      $initial_referrer: "$direct",
      page: "/pr/42",
      file_count: 3,
    });
    expect(out).toEqual({
      $current_url: "https://app.example/repo/[...slug]",
      $pathname: "/repo/[...slug]",
      $referrer: "https://github.com",   // which site, never the path (the customer's repo)
      $initial_referrer: "",
      page: "/pr/[id]",
      file_count: 3,
    });
  });

  it("removes identity properties and masks emails anywhere else", () => {
    const out = sanitizeAnalyticsProperties({ email: "a@acme.com", $name: "Ann", note: "sent to ann@acme.com", risk: "HIGH" });
    expect(out).toEqual({ note: "sent to [email]", risk: "HIGH" });
  });

  it("identifies people by opaque ids and role only", () => {
    expect(identityProperties({ org_id: "org-uuid", role: "admin", ...{ email: "a@acme.com", org_slug: "acme" } } as never)).toEqual({ org_id: "org-uuid", role: "admin" });
  });
});

describe("PostHog setup", () => {
  it("installs the sanitiser, keeps recording off, and identifies without email", async () => {
    jest.resetModules();
    process.env.NEXT_PUBLIC_POSTHOG_KEY = "phc_test";
    const ph = { __loaded: false, init: jest.fn(), identify: jest.fn(), capture: jest.fn() };
    jest.doMock("posthog-js", () => ({ __esModule: true, default: ph }));
    const { identify } = await import("@/lib/analytics");
    await identify("user-uuid", identityProperties({ org_id: "org-uuid", role: "developer" }));
    const cfg = ph.init.mock.calls[0][1];
    expect(cfg).toMatchObject({ autocapture: false, capture_pageview: false, disable_session_recording: true });
    expect(cfg.sanitize_properties({ $current_url: "https://x.example/repo/a/b?q=1" })).toEqual({ $current_url: "https://x.example/repo/[...slug]" });
    expect(ph.identify).toHaveBeenCalledWith("user-uuid", { org_id: "org-uuid", role: "developer" });
    delete process.env.NEXT_PUBLIC_POSTHOG_KEY;
  });
});
