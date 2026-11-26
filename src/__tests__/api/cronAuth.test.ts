/**
 * @jest-environment node
 *
 * The cron routes run with the service-role database client. Comparing the Authorization header with
 * `Bearer ${process.env.CRON_SECRET}` accepted the literal "Bearer undefined" whenever the secret was not configured.
 * With no secret, nobody may call them; with one, only an exact match.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { cronAuthorized } from "@/lib/cronAuth";

let dbCalls = 0;
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => { dbCalls++; return fakeSupabase({ organizations: [], scans: [], violations: [], webhook_configs: [], alerts: [], ops_events: [], audit_log: [] }).client; },
}));
jest.mock("@/lib/slaMonitor", () => ({ checkSLABreaches: async () => { dbCalls++; return { breaches: 0 }; } }));
jest.mock("@/lib/opsEvents", () => ({ recordEvent: async () => {} }));

import { GET as pipelineHealth } from "@/app/api/cron/pipeline-health/route";
import { GET as sla } from "@/app/api/cron/sla/route";
import { GET as weeklyReport } from "@/app/api/cron/weekly-report/route";
import { GET as webhookRetry } from "@/app/api/cron/webhook-retry/route";

const saved = process.env.CRON_SECRET;
afterEach(() => { if (saved === undefined) delete process.env.CRON_SECRET; else process.env.CRON_SECRET = saved; dbCalls = 0; });
beforeEach(() => { dbCalls = 0; });

const req = (authorization?: string) => new NextRequest(new URL("https://app.example/api/cron/x"), { headers: authorization === undefined ? {} : { authorization } });
const ROUTES = { "pipeline-health": pipelineHealth, sla, "weekly-report": weeklyReport, "webhook-retry": webhookRetry } as const;

describe("cronAuthorized", () => {
  it("accepts exactly 'Bearer <secret>'", () => {
    process.env.CRON_SECRET = "s3cret-value";
    expect(cronAuthorized(req("Bearer s3cret-value"))).toBe(true);
  });

  it("refuses everything when no secret is configured, including the literal 'Bearer undefined'", () => {
    delete process.env.CRON_SECRET;
    for (const h of ["Bearer undefined", "Bearer ", "Bearer", "undefined", "", "Bearer null", "Bearer s3cret-value"]) {
      expect({ h, ok: cronAuthorized(req(h)) }).toEqual({ h, ok: false });
    }
    expect(cronAuthorized(req())).toBe(false);
  });

  it("an empty or whitespace-only secret counts as not configured", () => {
    for (const s of ["", "   ", "\n", "﻿"]) {
      process.env.CRON_SECRET = s;
      expect({ s, ok: cronAuthorized(req("Bearer ")) }).toEqual({ s, ok: false });
      expect(cronAuthorized(req("Bearer undefined"))).toBe(false);
    }
  });

  it("refuses a wrong secret, a missing header, another scheme, a prefix, an extension and a different case", () => {
    process.env.CRON_SECRET = "s3cret-value";
    for (const h of ["Bearer wrong", "s3cret-value", "Basic s3cret-value", "Bearer s3cret-valu", "Bearer s3cret-value!", "bearer s3cret-value", "Bearer  s3cret-value", "Bearer S3CRET-VALUE"]) {
      expect({ h, ok: cronAuthorized(req(h)) }).toEqual({ h, ok: false });
    }
    expect(cronAuthorized(req())).toBe(false);
  });

  it("a secret with a trailing newline (pasted into a dashboard) still works with the clean header", () => {
    process.env.CRON_SECRET = "s3cret-value\n";
    expect(cronAuthorized(req("Bearer s3cret-value"))).toBe(true);
  });
});

describe.each(Object.entries(ROUTES))("/api/cron/%s", (_name, handler) => {
  it("with no CRON_SECRET configured, 'Bearer undefined' is refused and nothing runs", async () => {
    delete process.env.CRON_SECRET;
    const res = await handler(req("Bearer undefined"));
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
    expect(dbCalls).toBe(0);
  });

  it("with no CRON_SECRET configured, no header is refused and nothing runs", async () => {
    delete process.env.CRON_SECRET;
    expect((await handler(req())).status).toBe(401);
    expect(dbCalls).toBe(0);
  });

  it("with a secret configured, a wrong or missing header is refused and nothing runs", async () => {
    process.env.CRON_SECRET = "s3cret-value";
    expect((await handler(req("Bearer wrong"))).status).toBe(401);
    expect((await handler(req("Bearer undefined"))).status).toBe(401);
    expect((await handler(req())).status).toBe(401);
    expect(dbCalls).toBe(0);
  });

  it("with the right secret, it runs", async () => {
    process.env.CRON_SECRET = "s3cret-value";
    const res = await handler(req("Bearer s3cret-value"));
    expect(res.status).toBe(200);
    expect(dbCalls).toBeGreaterThan(0);
  });
});
