/**
 * @jest-environment node
 *
 * Shadow AI alerts: one in-app alert per (repo, PR, set of tools), delivered through the org's own channels;
 * repeated pushes of the same PR don't repeat it, a newly added unapproved tool does.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";

const delivered: Array<{ config: Record<string, unknown>; alert: Record<string, unknown> }> = [];
jest.mock("@/lib/alertDelivery", () => ({
  deliverAlert: async (config: Record<string, unknown>, alert: Record<string, unknown>) => { delivered.push({ config, alert }); return { slack: true, email: false, pagerduty: false, teams: false }; },
}));

import { notifyUnapprovedTools } from "@/lib/shadowAiStore";

let db: ReturnType<typeof fakeSupabase>;
const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const pr = { repo: "acme/app", pr_number: 12, scan_id: "s1", author: "dev-a" };
const cursor = [{ tool: "cursor", label: "Cursor" }];

beforeEach(() => {
  delivered.length = 0;
  db = fakeSupabase({
    organizations: [{ id: "org-1", name: "Acme", slack_webhook: "https://hooks.slack.example/x", teams_webhook: null }],
    alerts: [],
  });
});

it("raises one alert and delivers it through the org's Slack webhook", async () => {
  expect(await notifyUnapprovedTools(db.client as never, "org-1", pr, cursor)).toBe(true);
  expect(rows("alerts")).toEqual([expect.objectContaining({
    org_id: "org-1", alert_type: "shadow_ai", severity: "P3", status: "firing", repo: "acme/app", scan_id: "s1",
    title: "Unapproved AI tool in app #12: Cursor",
  })]);
  expect(String(rows("alerts")[0].body)).toContain("The merge is not blocked");
  expect(delivered).toHaveLength(1);
  expect(delivered[0].config).toMatchObject({ slack_webhook: "https://hooks.slack.example/x" });
  expect(delivered[0].alert).toMatchObject({ severity: "P3", pr_number: 12, org_name: "Acme" });
});

it("a later push of the same PR with the same tools doesn't alert again; a new tool does", async () => {
  await notifyUnapprovedTools(db.client as never, "org-1", pr, cursor);
  expect(await notifyUnapprovedTools(db.client as never, "org-1", { ...pr, scan_id: "s2" }, cursor)).toBe(false);
  expect(await notifyUnapprovedTools(db.client as never, "org-1", { ...pr, scan_id: "s3" }, [...cursor, { tool: "gemini", label: "Gemini" }])).toBe(true);
  expect(rows("alerts").map(a => a.title)).toEqual(["Unapproved AI tool in app #12: Cursor", "Unapproved AI tools in app #12: Cursor, Gemini"]);
  expect(delivered).toHaveLength(2);
});

it("nothing to report: no alert, no delivery", async () => {
  expect(await notifyUnapprovedTools(db.client as never, "org-1", pr, [])).toBe(false);
  expect(rows("alerts")).toEqual([]);
  expect(delivered).toEqual([]);
});

it("another org's identical alert doesn't suppress this one", async () => {
  rows("alerts").push({ id: "x", org_id: "org-2", alert_type: "shadow_ai", repo: "acme/app", title: "Unapproved AI tool in app #12: Cursor" });
  expect(await notifyUnapprovedTools(db.client as never, "org-1", pr, cursor)).toBe(true);
});
