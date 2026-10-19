/**
 * Shared violation-status loading: the server's overrides (same on every device) with this tab's fresh sign-offs on
 * top; concurrent callers share one request; browser-held details are uploaded without overriding the server.
 */
let fetchImpl: () => Promise<unknown>;
const calls: string[] = [];
let seed = false;
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => seed,
  authedFetch: jest.fn((url: string) => { calls.push(url); return fetchImpl(); }),
}));

import { detailsFromOverrides, fetchServerOverrides, invalidateServerStatuses, loadStatuses, localDetailUploads, statusesOf } from "@/lib/violationStatuses";
import { recordLocalStatuses } from "@/lib/localStatuses";

const T = 1_800_000_000_000;
beforeEach(() => {
  calls.length = 0; seed = false; localStorage.clear(); invalidateServerStatuses();
  fetchImpl = async () => ({ overrides: { "high::s1::a.ts": { status: "resolved" }, "crit::s1::b.ts": { status: "open" } } });
});

describe("fetchServerOverrides", () => {
  it("callers within a few seconds share one request; after that, or after invalidate, it fetches again", async () => {
    await Promise.all([fetchServerOverrides(T), fetchServerOverrides(T + 100)]);
    expect(calls).toEqual(["/api/violation-status"]);
    await fetchServerOverrides(T + 3_000);
    expect(calls).toHaveLength(2);
    invalidateServerStatuses();
    await fetchServerOverrides(T + 3_001);
    expect(calls).toHaveLength(3);
  });

  it("a failure isn't shared: the next call retries", async () => {
    fetchImpl = async () => { throw new Error("down"); };
    await expect(fetchServerOverrides(T)).rejects.toThrow("down");
    fetchImpl = async () => ({ overrides: { x: { status: "resolved" } } });
    await expect(fetchServerOverrides(T + 1)).resolves.toEqual({ x: { status: "resolved" } });
  });

  it("demo mode never calls the server", async () => {
    seed = true;
    await expect(fetchServerOverrides(T)).resolves.toEqual({});
    expect(calls).toEqual([]);
  });
});

describe("loadStatuses", () => {
  it("server statuses, with this tab's fresh local ones on top", async () => {
    recordLocalStatuses({ "crit::s1::b.ts": "resolved" });
    expect(await loadStatuses()).toEqual({ "high::s1::a.ts": "resolved", "crit::s1::b.ts": "resolved" });
  });

  it("server unreachable → local ones alone", async () => {
    fetchImpl = async () => { throw new Error("down"); };
    recordLocalStatuses({ "crit::s1::b.ts": "resolved" });
    expect(await loadStatuses()).toEqual({ "crit::s1::b.ts": "resolved" });
  });

  it("statusesOf keeps only the status", () => {
    expect(statusesOf({ a: { status: "in_review", note: "n" } })).toEqual({ a: "in_review" });
  });
});

describe("violation details", () => {
  it("detailsFromOverrides reads assignee, note and escalation", () => {
    const d = detailsFromOverrides({
      a: { status: "open", assigned_email: "x@y.io", note: "waiting on vendor", escalated: true },
      b: { status: "open", assigned_email: null, note: null, escalated: false },
    });
    expect(d.assignees).toEqual({ a: "x@y.io" });
    expect(d.notes).toEqual({ a: "waiting on vendor" });
    expect(Array.from(d.escalated)).toEqual(["a"]);
  });

  it("uploads only what the server lacks, one PATCH per violation, keeping its current status", () => {
    const server = { a: { status: "in_review", note: "server note" }, b: { status: "resolved", assigned_email: "s@y.io" } };
    const ups = localDetailUploads(server, {
      assignees: { a: "me@y.io", b: "other@y.io", c: "not-an-email" },
      notes: { a: "local note", c: "note c" },
      escalated: ["a", "d", 7],
    });
    expect(ups).toEqual([
      { violation_id: "a", status: "in_review", assigned_email: "me@y.io", escalated: true },
      { violation_id: "c", status: "open", note: "note c" },
      { violation_id: "d", status: "open", escalated: true },
    ]);
  });

  it("an escalation the server already has isn't uploaded again", () => {
    expect(localDetailUploads({ a: { status: "open", escalated: true } }, { assignees: {}, notes: {}, escalated: ["a"] })).toEqual([]);
  });

  it("nothing local → nothing to upload; long notes are cut to the server's limit", () => {
    expect(localDetailUploads({}, { assignees: {}, notes: {}, escalated: [] })).toEqual([]);
    expect(localDetailUploads({}, { assignees: {}, notes: { a: "x".repeat(2500) }, escalated: [] })[0].note).toHaveLength(2000);
  });
});
