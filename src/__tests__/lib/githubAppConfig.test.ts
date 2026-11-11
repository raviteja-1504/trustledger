/**
 * @jest-environment node
 *
 * The GitHub App's permissions and events, in one place, checked against what the code actually does on GitHub, so the
 * one-click manifest and the setup wizard's instructions never ask for too little (comments refused) or too much.
 */
import fs from "fs";
import path from "path";
import { ACCESS_LABEL, EVENT_FORM, GITHUB_APP_EVENTS, GITHUB_APP_PERMISSIONS, PERMISSION_FORM, githubAppManifest, githubAppSettings } from "@/lib/githubAppConfig";

const read = (rel: string) => fs.readFileSync(path.join(process.cwd(), rel), "utf8");

describe("GitHub App configuration", () => {
  it("the manifest is built from the same permissions and events the wizard lists", () => {
    const m = githubAppManifest("https://app.example");
    expect(m.default_permissions).toEqual(GITHUB_APP_PERMISSIONS);
    expect(m.default_events).toEqual([...GITHUB_APP_EVENTS]);
    expect(m.hook_attributes).toEqual({ url: "https://app.example/api/webhook/github", active: true });
    expect(m.callback_url).toBe("https://app.example/api/auth/callback");
    expect(m.setup_url).toBe("https://app.example/onboarding");
    expect(m.redirect_url).toBe("https://app.example/api/github-app/manifest");
    // the homepage can differ from where the app is served (NEXT_PUBLIC_APP_URL)
    expect(githubAppManifest("https://a.example", "https://home.example").url).toBe("https://home.example");
  });

  it("every permission and event has a form label, and every access level a label", () => {
    for (const k of Object.keys(GITHUB_APP_PERMISSIONS) as Array<keyof typeof GITHUB_APP_PERMISSIONS>) {
      expect(PERMISSION_FORM[k].label).toBeTruthy();
      expect(PERMISSION_FORM[k].why).toBeTruthy();
      expect(ACCESS_LABEL[GITHUB_APP_PERMISSIONS[k]]).toBeTruthy();
    }
    for (const e of GITHUB_APP_EVENTS) expect(EVENT_FORM[e]).toBeTruthy();
  });

  it("matches what the code calls on GitHub: write for checks and PR comments, read for contents; no commit statuses", () => {
    const github = read("src/lib/github.ts");
    const comment = read("src/app/api/github-app/comment/route.ts");
    // check runs are created and updated: Checks needs write
    expect(github).toMatch(/\/check-runs`/);
    expect(GITHUB_APP_PERMISSIONS.checks).toBe("write");
    // the summary comment is POSTed / PATCHed on the issue-comments API: Pull requests needs write (read-only gets a 403)
    expect(comment).toMatch(/issues\/\$\{prNumber\}\/comments`,\s*\{\s*method: "POST"/);
    expect(GITHUB_APP_PERMISSIONS.pull_requests).toBe("write");
    expect(GITHUB_APP_PERMISSIONS.contents).toBe("read");
    expect(GITHUB_APP_PERMISSIONS.metadata).toBe("read");
    // GitHub commit statuses are never called, so they are not requested
    expect(github + comment + read("src/app/api/scan-worker/route.ts")).not.toMatch(/api\.github\.com[^"'`]*\/statuses\//);
    expect(Object.keys(GITHUB_APP_PERMISSIONS)).not.toContain("statuses");
  });

  it("subscribes to exactly the events the webhook handler acts on", () => {
    const handler = read("src/app/api/webhook/github/route.ts");
    const handled = [...handler.matchAll(/event === "([a-z_]+)"/g)].map(m => m[1]).sort();
    expect([...GITHUB_APP_EVENTS].sort()).toEqual(handled);
  });

  it("the form values for an origin", () => {
    expect(githubAppSettings("https://app.example")).toEqual({
      name: "TrustLedger",
      description: "AI code provenance, attestation, and compliance for every pull request",
      homepageUrl: "https://app.example",
      callbackUrl: "https://app.example/api/auth/callback",
      setupUrl: "https://app.example/onboarding",
      webhookUrl: "https://app.example/api/webhook/github",
    });
  });
});
