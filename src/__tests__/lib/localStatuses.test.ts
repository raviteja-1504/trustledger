/**
 * The browser's violation statuses are a short-lived bridge (a sign-off shows before the next fetch), not a source
 * of truth: outside demo mode an entry counts for 10 minutes only, so one browser can't keep disagreeing with every
 * other device about a file that was reopened or revoked elsewhere.
 */
import { LOCAL_STATUS_AT_KEY, LOCAL_STATUS_KEY, LOCAL_STATUS_TTL_MS, readLocalStatuses, recordLocalStatuses } from "@/lib/localStatuses";
import { patchDataWithAttestations } from "@/lib/trustScore";
import type { DashboardData } from "@/types";

const T = 1_800_000_000_000;
beforeEach(() => localStorage.clear());

describe("local violation statuses", () => {
  it("a just-recorded status counts, and keeps counting until the TTL", () => {
    recordLocalStatuses({ "high::s1::a.ts": "resolved" }, T);
    expect(readLocalStatuses(T)).toEqual({ "high::s1::a.ts": "resolved" });
    expect(readLocalStatuses(T + LOCAL_STATUS_TTL_MS - 1)).toEqual({ "high::s1::a.ts": "resolved" });
  });

  it("an expired one no longer counts and is removed from storage", () => {
    recordLocalStatuses({ "high::s1::a.ts": "resolved" }, T);
    recordLocalStatuses({ "crit::s2::b.ts": "resolved" }, T + 5 * 60_000);
    expect(readLocalStatuses(T + LOCAL_STATUS_TTL_MS)).toEqual({ "crit::s2::b.ts": "resolved" });
    expect(JSON.parse(localStorage.getItem(LOCAL_STATUS_KEY)!)).toEqual({ "crit::s2::b.ts": "resolved" });
    expect(Object.keys(JSON.parse(localStorage.getItem(LOCAL_STATUS_AT_KEY)!))).toEqual(["crit::s2::b.ts"]);
  });

  it("entries written before timestamps existed are ignored (that's the old, never-expiring data)", () => {
    localStorage.setItem(LOCAL_STATUS_KEY, JSON.stringify({ "high::old::x.ts": "resolved" }));
    expect(readLocalStatuses(T)).toEqual({});
    expect(localStorage.getItem(LOCAL_STATUS_KEY)).toBe("{}");
  });

  it("a timestamp in the future (clock change) doesn't make an entry last forever", () => {
    recordLocalStatuses({ "high::s1::a.ts": "resolved" }, T + 60_000);
    expect(readLocalStatuses(T)).toEqual({});
  });

  it("re-recording refreshes the timestamp", () => {
    recordLocalStatuses({ "high::s1::a.ts": "resolved" }, T);
    recordLocalStatuses({ "high::s1::a.ts": "resolved" }, T + 9 * 60_000);
    expect(readLocalStatuses(T + 15 * 60_000)).toEqual({ "high::s1::a.ts": "resolved" });
  });

  it("demo mode keeps every entry (its seed data lives here)", () => {
    localStorage.setItem("tl_force_seed", "1");
    localStorage.setItem(LOCAL_STATUS_KEY, JSON.stringify({ "high::seed::x.ts": "resolved", bad: 3 }));
    expect(readLocalStatuses(T)).toEqual({ "high::seed::x.ts": "resolved" });
  });

  it("garbage in storage reads as nothing", () => {
    localStorage.setItem(LOCAL_STATUS_KEY, "not json");
    expect(readLocalStatuses(T)).toEqual({});
    localStorage.setItem(LOCAL_STATUS_KEY, "[1,2]");
    expect(readLocalStatuses(T)).toEqual({});
    localStorage.setItem("tl_force_seed", "1");
    localStorage.setItem(LOCAL_STATUS_KEY, JSON.stringify(["resolved"]));
    expect(readLocalStatuses(T)).toEqual({});
  });

  it("a timestamp that isn't a number doesn't count", () => {
    localStorage.setItem(LOCAL_STATUS_KEY, JSON.stringify({ "high::s1::a.ts": "resolved" }));
    localStorage.setItem(LOCAL_STATUS_AT_KEY, JSON.stringify({ "high::s1::a.ts": String(T) }));
    expect(readLocalStatuses(T + 1000)).toEqual({});
  });

  it("patchDataWithAttestations' default uses only the fresh local entries", () => {
    const data = {
      attestation_rate: 0, repos: [],
      top_risk_files: [
        { repo: "r", scan_id: "s1", file_path: "a.ts", risk_score: "HIGH", attested: false },
        { repo: "r", scan_id: "s1", file_path: "b.ts", risk_score: "HIGH", attested: false },
      ],
    } as unknown as DashboardData;
    localStorage.setItem(LOCAL_STATUS_KEY, JSON.stringify({ "high::s1::b.ts": "attested" }));   // stale, no timestamp
    recordLocalStatuses({ "high::s1::a.ts": "attested" });
    const out = patchDataWithAttestations(data);
    expect(out.top_risk_files.map(f => f.attested)).toEqual([true, false]);
  });

  it("a file closed without review is handled, but never counts as attested", () => {
    const data = {
      attestation_rate: 0.5, repos: [{ repo: "r", attestation_rate: 0.5 }],
      top_risk_files: [
        { repo: "r", scan_id: "s1", file_path: "a.ts", risk_score: "HIGH", attested: true },
        { repo: "r", scan_id: "s1", file_path: "b.ts", risk_score: "HIGH", attested: false },
        { repo: "r", scan_id: "s1", file_path: "c.ts", risk_score: "CRITICAL", attested: false },
      ],
    } as unknown as DashboardData;
    // b.ts closed on the Violations page; c.ts just attested in this tab
    const out = patchDataWithAttestations(data, { "high::s1::b.ts": "resolved", "crit::s1::c.ts": "attested" });
    expect(out.top_risk_files.map(f => [f.file_path, f.attested, !!f.resolved])).toEqual([
      ["a.ts", true, false], ["b.ts", false, true], ["c.ts", true, false],
    ]);
    // 2 of 3 signed off: the closed one doesn't raise the rate (it used to make this 100%)
    expect(out.attestation_rate).toBeCloseTo(2 / 3);
    expect(out.repos[0].attestation_rate).toBeCloseTo(2 / 3);
  });
});
