/**
 * @jest-environment node
 *
 * Operations monitoring: the platform's health checks (and the endpoint an uptime monitor polls), the public status page's data, and the
 * alerts raised when a job dies, an audit entry cannot be written, or a webhook is given up on. No customer data in any of it.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let dbDown = false;
const notifyOps = jest.fn(async () => true);
const recordEvent = jest.fn(async () => {});

jest.mock("@/lib/supabase", () => ({ createServiceClient: () => { if (dbDown) throw new Error("no database"); return db.client; } }));
jest.mock("@/lib/opsAlert", () => ({ notifyOps: (...a: unknown[]) => (notifyOps as unknown as (...x: unknown[]) => unknown)(...a) }));
jest.mock("@/lib/opsEvents", () => ({ recordEvent: (...a: unknown[]) => (recordEvent as unknown as (...x: unknown[]) => unknown)(...a) }));
jest.mock("@/lib/logger", () => ({ logger: { error: jest.fn(), warn: jest.fn(), info: jest.fn() } }));

import { GET as opsStatusGET } from "@/app/api/ops/status/route";
import { GET as publicStatusGET } from "@/app/api/status/route";
import { opsStatus, LIMITS } from "@/lib/opsStatus";
import { componentsFrom, loadNotices } from "@/lib/platformStatus";
import { finishJob, MAX_ATTEMPTS } from "@/lib/scanJobs";
import { writeAuditLog } from "@/lib/audit";

const NOW = Date.parse("2026-11-29T12:00:00Z");
const ago = (ms: number) => new Date(NOW - ms).toISOString();
const MIN = 60_000, H = 3600_000;
const job = (id: string, org: string, status: string, extra: Record<string, unknown> = {}) => ({ id, org_id: org, status, created_at: ago(5 * MIN), updated_at: ago(5 * MIN), started_at: null, ...extra });

function healthy() {
  db = fakeSupabase({ organizations: [{ id: "o1" }], scan_jobs: [], ops_events: [], webhook_failed_deliveries: [], platform_notices: [], audit_log: [] });
}
const check = (s: Awaited<ReturnType<typeof opsStatus>>, name: string) => s.checks.find(c => c.name === name)!;
const req = (secret?: string) => new NextRequest("https://app.example/api/ops/status", { headers: secret ? { Authorization: `Bearer ${secret}` } : {} });

beforeEach(() => { dbDown = false; jest.clearAllMocks(); healthy(); process.env.CRON_SECRET = "ops-secret"; });
afterAll(() => { delete process.env.CRON_SECRET; });

describe("opsStatus", () => {
  it("is ok when nothing is wrong, and every check says what it measured", async () => {
    const s = await opsStatus(db.client as never, NOW);
    expect(s.status).toBe("ok");
    expect(s.checks.map(c => c.name)).toEqual(["database", "queue_oldest_waiting", "scans_stuck_running", "scan_jobs_dead_24h", "audit_write_failures_1h", "audit_checkpoints_refused_24h", "webhooks_given_up_24h"]);
    expect(s.checks.every(c => c.ok && c.value !== null)).toBe(true);
  });

  it("a scan waiting longer than the limit fails the queue check", async () => {
    (db.tables.scan_jobs as unknown[]).push(job("j1", "o1", "queued", { created_at: ago((LIMITS.oldestWaitingMinutes + 5) * MIN) }));
    const s = await opsStatus(db.client as never, NOW);
    expect(check(s, "queue_oldest_waiting")).toMatchObject({ ok: false, value: LIMITS.oldestWaitingMinutes + 5 });
    expect(s.status).toBe("degraded");
  });

  it("a recent scan waiting is fine; so is a long-finished one", async () => {
    (db.tables.scan_jobs as unknown[]).push(job("j1", "o1", "queued", { created_at: ago(2 * MIN) }), job("j2", "o1", "succeeded", { created_at: ago(5 * H) }));
    expect(check(await opsStatus(db.client as never, NOW), "queue_oldest_waiting").ok).toBe(true);
  });

  it("scans stuck running, dead scans, audit failures, refused checkpoints and given-up webhooks each fail their own check", async () => {
    (db.tables.scan_jobs as unknown[]).push(job("j1", "o1", "running", { started_at: ago(40 * MIN) }), job("j2", "o1", "dead", { updated_at: ago(2 * H) }));
    (db.tables.ops_events as unknown[]).push({ id: 1, kind: "audit.write_failed", created_at: ago(10 * MIN) }, { id: 2, kind: "audit.checkpoint_refused", created_at: ago(3 * H) });
    for (let i = 0; i < LIMITS.webhooksGivenUp24h + 1; i++) (db.tables.webhook_failed_deliveries as unknown[]).push({ id: `w${i}`, permanently_failed: true, created_at: ago(H) });
    const s = await opsStatus(db.client as never, NOW);
    for (const name of ["scans_stuck_running", "scan_jobs_dead_24h", "audit_write_failures_1h", "audit_checkpoints_refused_24h", "webhooks_given_up_24h"]) expect(check(s, name).ok).toBe(false);
    expect(s.status).toBe("degraded");
  });

  it("old problems age out: an audit failure two hours ago, a dead scan three days ago", async () => {
    (db.tables.scan_jobs as unknown[]).push(job("j2", "o1", "dead", { updated_at: ago(72 * H) }));
    (db.tables.ops_events as unknown[]).push({ id: 1, kind: "audit.write_failed", created_at: ago(2 * H) });
    const s = await opsStatus(db.client as never, NOW);
    expect(check(s, "scan_jobs_dead_24h").ok).toBe(true);
    expect(check(s, "audit_write_failures_1h").ok).toBe(true);
  });

  it("a table that does not exist yet is skipped, not a failure", async () => {
    db = fakeSupabase({ organizations: [{ id: "o1" }] }, { errorFor: t => (t === "scan_jobs" || t === "ops_events" || t === "webhook_failed_deliveries" ? { code: "42P01", message: `relation "${t}" does not exist` } : null) });
    const s = await opsStatus(db.client as never, NOW);
    expect(s.status).toBe("ok");
    expect(s.checks.filter(c => c.skipped).length).toBeGreaterThanOrEqual(5);
  });

  it("no database answer fails the database check", async () => {
    db = fakeSupabase({ organizations: [{ id: "o1" }] }, { errorFor: t => (t === "organizations" ? { message: "connection refused" } : null) });
    expect(check(await opsStatus(db.client as never, NOW), "database")).toMatchObject({ ok: false, value: null });
  });

  it("names the organisations with the most failed scans by opaque id and count only", async () => {
    const rows = db.tables.scan_jobs as unknown[];
    rows.push(job("a", "org-A", "dead"), job("b", "org-A", "dead"), job("c", "org-B", "failed"), job("d", "org-C", "succeeded"));
    const s = await opsStatus(db.client as never, NOW);
    expect(s.failing_orgs).toEqual([{ org_id: "org-A", dead: 2, failed: 0 }, { org_id: "org-B", dead: 0, failed: 1 }]);
    expect(Object.keys(s.failing_orgs[0]).sort()).toEqual(["dead", "failed", "org_id"]);
  });
});

describe("GET /api/ops/status", () => {
  it("needs the operator's secret", async () => {
    expect((await opsStatusGET(req())).status).toBe(401);
    expect((await opsStatusGET(req("wrong"))).status).toBe(401);
    delete process.env.CRON_SECRET;
    expect((await opsStatusGET(req("undefined"))).status).toBe(401);       // an unset secret never matches anything
    process.env.CRON_SECRET = "ops-secret";
  });

  it("is 200 when healthy and 503 when a check fails, so a plain HTTP monitor can alert on the status code", async () => {
    expect((await opsStatusGET(req("ops-secret"))).status).toBe(200);
    (db.tables.scan_jobs as unknown[]).push({ id: "j", org_id: "o1", status: "dead", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
    const res = await opsStatusGET(req("ops-secret"));
    expect(res.status).toBe(503);
    expect((await res.json()).checks.find((c: { name: string }) => c.name === "scan_jobs_dead_24h").ok).toBe(false);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("with no database it is 503, not an error page", async () => {
    dbDown = true;
    expect((await opsStatusGET(req("ops-secret"))).status).toBe(503);
  });

  it("carries no customer data: no repository, person or payload", async () => {
    (db.tables.scan_jobs as unknown[]).push({ id: "j", org_id: "o1", status: "dead", repo_full_name: "acme/secret", last_error: "boom in auth.ts", job: { x: 1 }, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
    const text = JSON.stringify(await (await opsStatusGET(req("ops-secret"))).json());
    for (const leaked of ["acme/secret", "boom", "auth.ts"]) expect(text).not.toContain(leaked);
  });
});

describe("the public status page's data", () => {
  it("shows a state per component and nothing numeric or tenant-specific", async () => {
    (db.tables.scan_jobs as unknown[]).push({ id: "j", org_id: "org-secret", status: "dead", created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
    const res = await publicStatusGET();
    const body = await res.json();
    expect(body.components.map((c: { key: string; state: string }) => [c.key, c.state])).toEqual([["database", "operational"], ["scans", "degraded"], ["audit_log", "operational"], ["webhooks", "operational"]]);
    expect(JSON.stringify(body)).not.toContain("org-secret");
    expect(res.headers.get("Cache-Control")).toContain("s-maxage=30");
  });

  it("no database: it says the database is down instead of failing", async () => {
    dbDown = true;
    expect((await (await publicStatusGET()).json()).components[0]).toMatchObject({ key: "database", state: "down" });
  });

  it("maps checks to component states", () => {
    const c = (name: string, ok: boolean, value: number | null = 1) => ({ name, ok, value, limit: 1, unit: "x", note: "" });
    expect(componentsFrom([c("database", true)]).every(x => x.state === "operational")).toBe(true);
    expect(componentsFrom([c("database", false, null)])[0].state).toBe("down");
    expect(componentsFrom([c("database", false, 5000)])[0].state).toBe("degraded");
    expect(componentsFrom([c("database", true), c("scans_stuck_running", false)]).find(x => x.key === "scans")!.state).toBe("degraded");
    expect(componentsFrom([c("database", true), c("audit_write_failures_1h", false)]).find(x => x.key === "audit_log")!.state).toBe("degraded");
  });

  it("shows open notices and recently resolved ones, and drops old resolved ones", async () => {
    (db.tables.platform_notices as unknown[]).push(
      { id: "n1", severity: "outage", title: "Scans are delayed", body: "We are investigating.", started_at: ago(H), updated_at: ago(H), resolved_at: null },
      { id: "n2", severity: "degraded", title: "Slow exports", body: "", started_at: ago(5 * 86400_000), updated_at: ago(4 * 86400_000), resolved_at: ago(4 * 86400_000) },
      { id: "n3", severity: "info", title: "Old maintenance", body: "", started_at: ago(60 * 86400_000), updated_at: ago(60 * 86400_000), resolved_at: ago(59 * 86400_000) },
    );
    const notices = await loadNotices(db.client as never, NOW);
    expect(notices.map(n => n.id)).toEqual(["n1", "n2"]);
  });

  it("without the notices table there are simply no notices", async () => {
    db = fakeSupabase({}, { errorFor: t => (t === "platform_notices" ? { code: "42P01", message: "does not exist" } : null) });
    expect(await loadNotices(db.client as never, NOW)).toEqual([]);
  });
});

describe("alerts at the moment something goes wrong", () => {
  it("a scan job that runs out of attempts is recorded and alerted, by opaque ids only", async () => {
    (db.tables.scan_jobs as unknown[]).push({ id: "job-1", org_id: "o1", status: "running", attempts: MAX_ATTEMPTS, dedupe_key: "k" });
    await finishJob(db.client as never, "o1", "job-1", MAX_ATTEMPTS, { ok: false, error: "scan_failed: boom" });
    expect(notifyOps).toHaveBeenCalledWith("scan_job_dead", { org_id: "o1", job_id: "job-1", attempts: MAX_ATTEMPTS });
    expect(recordEvent).toHaveBeenCalledWith(expect.objectContaining({ kind: "scan.job_dead", org_id: "o1" }));
  });

  it("a failed attempt that will be retried does not alert", async () => {
    (db.tables.scan_jobs as unknown[]).push({ id: "job-1", org_id: "o1", status: "running", attempts: 1, dedupe_key: "k" });
    await finishJob(db.client as never, "o1", "job-1", 1, { ok: false, error: "scan_failed" });
    expect(notifyOps).not.toHaveBeenCalled();
  });

  it("an audit entry that cannot be written is recorded and alerted", async () => {
    const real = db.client.from;
    (db.client as unknown as { from: unknown }).from = ((t: string) => {
      const q = (real as unknown as (x: string) => Record<string, unknown>)(t);
      if (t === "audit_log") q.insert = () => Promise.resolve({ error: { code: "42501", message: "permission denied" } });
      return q;
    });
    await writeAuditLog(db.client as never, { org_id: "o1", event_type: "api_key_created", payload: {} }, { strict: false });
    expect(notifyOps).toHaveBeenCalledWith("audit_write_failed", { org_id: "o1", event_type: "api_key_created" });
    expect(recordEvent).toHaveBeenCalledWith(expect.objectContaining({ kind: "audit.write_failed" }));
  });

  it("a successful audit write alerts nobody", async () => {
    await writeAuditLog(db.client as never, { org_id: "o1", event_type: "api_key_created", payload: {} });
    expect(notifyOps).not.toHaveBeenCalled();
  });
});

describe("the runbook stays true", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const fs = require("fs") as typeof import("fs");
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const path = require("path") as typeof import("path");
  const read = (f: string) => fs.readFileSync(path.join(__dirname, "../../../docs/operations", f), "utf8");

  it("explains every check the status endpoint runs (a new check cannot ship undocumented)", async () => {
    const runbook = read("runbook.md");
    healthy();
    const s = await opsStatus(db.client as never, NOW);
    for (const c of s.checks) expect(runbook).toContain("`" + c.name + "`");
  });

  it("names the settings it tells the operator to make, and the files and scripts it points at", () => {
    const runbook = read("runbook.md");
    const restore = read("backup-and-restore.md");
    for (const name of ["OPS_ALERT_WEBHOOK_URL", "CRON_SECRET", "/api/ops/status", "/api/health", "platform_notices"]) expect(runbook).toContain(name);
    for (const name of ["scripts/restore-check.cjs", "DATA_ENCRYPTION_KEY", "ATTESTATION_SIGNING_KEY", "EXPORT_SIGNING_PRIVATE_KEY", "RPO", "RTO"]) expect(restore).toContain(name);
    expect(fs.existsSync(path.join(__dirname, "../../../scripts/restore-check.cjs"))).toBe(true);
    expect(fs.existsSync(path.join(__dirname, "../../../supabase/migrations/20261129_platform_notices.sql"))).toBe(true);
  });

  it("the secrets inventory lists every signing and encryption key the code reads", () => {
    const restore = read("backup-and-restore.md");
    const src = (f: string) => fs.readFileSync(path.join(__dirname, "../../..", f), "utf8");
    for (const [file, name] of [["src/lib/secretBox.ts", "DATA_ENCRYPTION_KEY"], ["src/lib/attestationSigning.ts", "ATTESTATION_SIGNING_KEY"], ["src/lib/exportSigning.ts", "EXPORT_SIGNING_PRIVATE_KEY"]]) {
      expect(src(file)).toContain(name);
      expect(restore).toContain("`" + name + "`");
    }
  });
});
