/**
 * @jest-environment node
 *
 * The cron jobs in vercel.json: each points at a real route that refuses anyone without the CRON_SECRET, and the schedule is one
 * the plan allows (daily or slower, few of them), so a deployment is not rejected or a job silently never runs.
 */
import fs from "fs";
import path from "path";

const ROOT = path.join(__dirname, "../../..");
const config = JSON.parse(fs.readFileSync(path.join(ROOT, "vercel.json"), "utf8")) as { crons?: Array<{ path: string; schedule: string }> };
const crons = config.crons ?? [];

describe("vercel.json crons", () => {
  it("has the daily maintenance run", () => {
    expect(crons.find(c => c.path === "/api/cron/pipeline-health")).toMatchObject({ schedule: "0 3 * * *" });
  });

  it("only schedules routes that exist, export GET, and check the CRON_SECRET", () => {
    for (const c of crons) {
      const file = path.join(ROOT, "src/app", c.path, "route.ts");
      expect(fs.existsSync(file)).toBe(true);
      const src = fs.readFileSync(file, "utf8");
      expect(src).toMatch(/export (async )?function GET/);
      expect(src).toContain("cronAuthorized(req)");
    }
  });

  it("uses schedules a Hobby plan accepts: at most 2 jobs, each once a day or less often (fixed minute and hour)", () => {
    expect(crons.length).toBeLessThanOrEqual(2);
    for (const c of crons) {
      const [minute, hour] = c.schedule.split(/\s+/);
      expect(c.schedule.split(/\s+/)).toHaveLength(5);
      expect(minute).toMatch(/^\d+$/);
      expect(hour).toMatch(/^\d+$/);
    }
  });

  it("the cron route refuses a request without the secret, and with no secret configured", async () => {
    const { NextRequest } = await import("next/server");
    jest.resetModules();
    jest.doMock("@/lib/supabase", () => ({ createServiceClient: () => { throw new Error("must not be reached"); } }));
    const { GET } = await import("@/app/api/cron/pipeline-health/route");
    const saved = process.env.CRON_SECRET;
    try {
      process.env.CRON_SECRET = "s3cret";
      expect((await GET(new NextRequest("https://app.example/api/cron/pipeline-health"))).status).toBe(401);
      expect((await GET(new NextRequest("https://app.example/api/cron/pipeline-health", { headers: { authorization: "Bearer wrong" } }))).status).toBe(401);
      delete process.env.CRON_SECRET;
      expect((await GET(new NextRequest("https://app.example/api/cron/pipeline-health", { headers: { authorization: "Bearer undefined" } }))).status).toBe(401);
    } finally { if (saved === undefined) delete process.env.CRON_SECRET; else process.env.CRON_SECRET = saved; }
  });
});
