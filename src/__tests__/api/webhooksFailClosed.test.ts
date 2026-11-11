/**
 * @jest-environment node
 *
 * Webhook receivers fail CLOSED. GitLab, Bitbucket and Slack accepted every request when their secret was not configured
 * (`if (secret && ...)`, `return !secret`), and GitHub's check computed an HMAC with an empty key, which anyone can do.
 * GitLab, Bitbucket and Slack are not supported integrations (TrustLedger supports GitHub), so they are also off unless
 * explicitly enabled.
 */
import crypto from "crypto";
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

jest.mock("@/lib/supabase", () => ({ createServiceClient: () => fakeSupabase({}).client }));
jest.mock("@/lib/rateLimit", () => ({ ...jest.requireActual("@/lib/rateLimit"), checkRateLimit: async () => ({ success: true, headers: {} }) }));

import { POST as gitlab } from "@/app/api/webhook/gitlab/route";
import { POST as bitbucket } from "@/app/api/webhook/bitbucket/route";
import { POST as slack } from "@/app/api/slack/commands/route";
import { verifyWebhookSignature } from "@/lib/github";

const KEYS = ["ENABLE_GITLAB_WEBHOOK", "GITLAB_WEBHOOK_TOKEN", "ENABLE_BITBUCKET_WEBHOOK", "BITBUCKET_WEBHOOK_SECRET", "ENABLE_SLACK_COMMANDS", "SLACK_SIGNING_SECRET", "NEXT_PUBLIC_ORG"];
const saved: Record<string, string | undefined> = {};
beforeEach(() => { for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; } });
afterEach(() => { for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });

const call = async (handler: (r: NextRequest) => Promise<Response>, url: string, headers: Record<string, string>, body: string) => {
  const res = await handler(new NextRequest(new URL(url, "https://app.example"), { method: "POST", body, headers }));
  return res.status;
};

describe("GitLab (unsupported): off unless enabled; the token is mandatory", () => {
  const send = (headers: Record<string, string> = {}) => call(gitlab, "/api/webhook/gitlab", { "x-gitlab-event": "Push Hook", ...headers }, JSON.stringify({ project: { path_with_namespace: "a/b" } }));

  it("not enabled: 404, whatever is sent", async () => {
    process.env.GITLAB_WEBHOOK_TOKEN = "tok";
    expect(await send({ "x-gitlab-token": "tok" })).toBe(404);
  });
  it("enabled but no token configured: rejected (it used to accept everything)", async () => {
    process.env.ENABLE_GITLAB_WEBHOOK = "true";
    expect(await send()).toBe(401);
    expect(await send({ "x-gitlab-token": "" })).toBe(401);
  });
  it("enabled with a token: a wrong token is rejected, the right one is accepted", async () => {
    process.env.ENABLE_GITLAB_WEBHOOK = "true"; process.env.GITLAB_WEBHOOK_TOKEN = "tok";
    expect(await send({ "x-gitlab-token": "nope" })).toBe(401);
    expect(await send({ "x-gitlab-token": "tok" })).toBe(200);
  });
});

describe("Bitbucket (unsupported): off unless enabled; the secret is mandatory", () => {
  const SECRET = "bb-secret";
  const sign = (body: string, secret = SECRET) => `sha256=${crypto.createHmac("sha256", secret).update(body).digest("hex")}`;
  const send = (body = "{}", headers: Record<string, string> = {}) => call(bitbucket, "/api/webhook/bitbucket", { "x-event-key": "repo:push", ...headers }, body);

  it("not enabled: 404", async () => {
    process.env.BITBUCKET_WEBHOOK_SECRET = SECRET;
    expect(await send("{}", { "x-hub-signature-256": sign("{}") })).toBe(404);
  });
  it("enabled but no secret configured: rejected, even with a signature made with an empty key", async () => {
    process.env.ENABLE_BITBUCKET_WEBHOOK = "true";
    expect(await send("{}")).toBe(401);
    expect(await send("{}", { "x-hub-signature-256": sign("{}", "") })).toBe(401);
  });
  it("enabled with a secret: a bad signature is rejected, a good one accepted", async () => {
    process.env.ENABLE_BITBUCKET_WEBHOOK = "true"; process.env.BITBUCKET_WEBHOOK_SECRET = SECRET;
    expect(await send("{}", { "x-hub-signature-256": sign("{}", "wrong") })).toBe(401);
    expect(await send("{}", { "x-hub-signature-256": sign("{}") })).toBe(200);
  });
});

describe("Slack commands (unsupported): off unless enabled; the signing secret is mandatory", () => {
  const SECRET = "slack-secret";
  const body = "team_id=T1&user_id=U1&text=help";
  const signed = (secret: string) => {
    const ts = String(Math.floor(Date.now() / 1000));
    return { "x-slack-request-timestamp": ts, "x-slack-signature": `v0=${crypto.createHmac("sha256", secret).update(`v0:${ts}:${body}`).digest("hex")}` };
  };
  const send = (headers: Record<string, string> = {}) => call(slack, "/api/slack/commands", { "content-type": "application/x-www-form-urlencoded", ...headers }, body);

  it("not enabled: 404", async () => {
    process.env.SLACK_SIGNING_SECRET = SECRET;
    expect(await send(signed(SECRET))).toBe(404);
  });
  it("enabled but no signing secret configured: rejected (anyone could read an organisation's status)", async () => {
    process.env.ENABLE_SLACK_COMMANDS = "true";
    expect(await send()).toBe(401);
    expect(await send(signed(""))).toBe(401);
  });
  it("enabled with a secret: an unsigned or wrongly signed request is rejected, a signed one accepted", async () => {
    process.env.ENABLE_SLACK_COMMANDS = "true"; process.env.SLACK_SIGNING_SECRET = SECRET;
    expect(await send()).toBe(401);
    expect(await send(signed("wrong"))).toBe(401);
    expect(await send(signed(SECRET))).toBe(200);
  });
});

describe("GitHub: an empty webhook secret verifies nothing", () => {
  const payload = JSON.stringify({ action: "opened" });
  const sig = (secret: string) => `sha256=${crypto.createHmac("sha256", secret).update(payload).digest("hex")}`;

  it("rejects a signature made with an empty key when no secret is configured", () => {
    expect(verifyWebhookSignature(payload, sig(""), "")).toBe(false);
  });
  it("still accepts the right signature, and rejects a wrong or missing one", () => {
    expect(verifyWebhookSignature(payload, sig("s3cret"), "s3cret")).toBe(true);
    expect(verifyWebhookSignature(payload, sig("other"), "s3cret")).toBe(false);
    expect(verifyWebhookSignature(payload, null, "s3cret")).toBe(false);
  });
});
