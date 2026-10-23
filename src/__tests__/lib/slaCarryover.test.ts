/**
 * @jest-environment node
 *
 * A file's review deadline belongs to its pull request (lib/slaCarryover.ts): a rescan or push keeps it while the
 * file still waits for a sign-off, so rescanning no longer postpones the overdue-CRITICAL incident.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";
import { openSlaDeadlines } from "@/lib/slaCarryover";

const ORG = "org-1";
const db = () => fakeSupabase({
  scans: [
    { id: "p1", org_id: ORG, repo_full_name: "acme/api", pr_number: 1 },
    { id: "p2", org_id: ORG, repo_full_name: "acme/api", pr_number: 1 },
    { id: "now", org_id: ORG, repo_full_name: "acme/api", pr_number: 1 },
    { id: "other-pr", org_id: ORG, repo_full_name: "acme/api", pr_number: 2 },
    { id: "other-org", org_id: "org-2", repo_full_name: "acme/api", pr_number: 1 },
  ],
  violations: [
    { org_id: ORG, scan_id: "p1", file_path: "a.ts", status: "open", sla_deadline: "2026-10-24T14:00:00Z" },
    { org_id: ORG, scan_id: "p2", file_path: "a.ts", status: "open", sla_deadline: "2026-10-24T16:00:00Z" },   // later: the earlier one wins
    { org_id: ORG, scan_id: "p1", file_path: "b.ts", status: "resolved", sla_deadline: "2026-10-20T00:00:00Z" }, // signed off: new clock
    { org_id: ORG, scan_id: "p2", file_path: "c.ts", status: "open", sla_deadline: null },
    { org_id: ORG, scan_id: "other-pr", file_path: "d.ts", status: "open", sla_deadline: "2026-10-01T00:00:00Z" },
    { org_id: "org-2", scan_id: "other-org", file_path: "e.ts", status: "open", sla_deadline: "2026-10-01T00:00:00Z" },
    { org_id: ORG, scan_id: "now", file_path: "f.ts", status: "open", sla_deadline: "2026-10-30T00:00:00Z" },     // this scan's own
  ],
}).client;

it("the earliest deadline of this PR's earlier, still-open violation of each file", async () => {
  const m = await openSlaDeadlines(db(), ORG, "acme/api", 1, "now", ["a.ts", "b.ts", "c.ts", "d.ts", "e.ts", "f.ts"]);
  expect(Object.fromEntries(m)).toEqual({ "a.ts": "2026-10-24T14:00:00Z" });
});

it("only the files asked about; nothing without a PR or paths", async () => {
  expect((await openSlaDeadlines(db(), ORG, "acme/api", 1, "now", ["b.ts"])).size).toBe(0);
  expect((await openSlaDeadlines(db(), ORG, "acme/api", null, "now", ["a.ts"])).size).toBe(0);
  expect((await openSlaDeadlines(db(), ORG, "acme/api", 1, "now", [])).size).toBe(0);
});

it("a read error keeps the old behaviour (a new deadline)", async () => {
  expect((await openSlaDeadlines({ from: () => { throw new Error("down"); } }, ORG, "acme/api", 1, "now", ["a.ts"])).size).toBe(0);
});
