/**
 * @jest-environment node
 *
 * The free trial's limits, enforced on the server: 3 scans a month, 1 repository, 2 team members. Reading and attesting are never
 * gated, and a database hiccup never blocks a scan.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";
import { checkMemberSlot, checkScanAllowed, monthStartIso, repoSlotsLeft, scanUsage } from "@/lib/planGate";
import type { SupabaseClient } from "@supabase/supabase-js";

const asDb = (d: ReturnType<typeof fakeSupabase>) => d.client as unknown as SupabaseClient;
const thisMonth = () => new Date().toISOString();
const lastMonth = () => new Date(Date.now() - 40 * 86_400_000).toISOString();
const scans = (n: number, created = thisMonth()) => Array.from({ length: n }, (_, i) => ({ id: `s${i}-${created}`, org_id: "org-1", created_at: created }));
const base = (over: Record<string, unknown[]> = {}) => fakeSupabase({
  organizations: [{ id: "org-1", plan: "free" }], scans: [], repositories: [{ id: "r1", org_id: "org-1", repo_full_name: "acme/api", is_active: true }],
  org_members: [{ id: "m1", org_id: "org-1" }], ...over,
});

describe("monthStartIso", () => {
  it("is the first instant of the UTC month", () => { expect(monthStartIso(new Date("2026-11-11T17:00:00Z"))).toBe("2026-11-01T00:00:00.000Z"); });
});

describe("checkScanAllowed", () => {
  it("allows scans while under 3 this month, for the connected repository", async () => {
    expect((await checkScanAllowed(asDb(base({ scans: scans(2) })), "org-1", "acme/api")).allowed).toBe(true);
  });

  it("refuses the 4th scan of the month with a message that says how many, that nothing is lost, and to contact us", async () => {
    const v = await checkScanAllowed(asDb(base({ scans: scans(3) })), "org-1", "acme/api");
    expect(v).toMatchObject({ allowed: false, reason: "scans" });
    expect(v.title).toBe("Plan limit reached: 3 of 3 scans used this month");
    expect(v.summary).toMatch(/can still be viewed and attested/);
    expect(v.summary).toMatch(/Contact us to upgrade/);
  });

  it("last month's scans do not count; another organisation's do not count", async () => {
    const d = base({ scans: [...scans(5, lastMonth()), ...scans(5).map(s => ({ ...s, org_id: "org-2" }))] });
    expect((await checkScanAllowed(asDb(d), "org-1", "acme/api")).allowed).toBe(true);
  });

  it("a second repository is refused; the connected one still scans", async () => {
    const d = base();
    expect(await checkScanAllowed(asDb(d), "org-1", "acme/other")).toMatchObject({ allowed: false, reason: "repos" });
    expect((await checkScanAllowed(asDb(d), "org-1", "acme/api")).allowed).toBe(true);
  });

  it("an unknown plan name is the free trial too (there is no other plan)", async () => {
    const d = base({ organizations: [{ id: "org-1", plan: "growth" }], scans: scans(3) });
    expect((await checkScanAllowed(asDb(d), "org-1", "acme/api")).allowed).toBe(false);
  });

  it("fails open when the database errors", async () => {
    const broken = { from: () => { throw new Error("down"); } } as unknown as SupabaseClient;
    expect((await checkScanAllowed(broken, "org-1", "acme/api")).allowed).toBe(true);
  });
});

describe("repoSlotsLeft / checkMemberSlot / scanUsage", () => {
  it("repositories: none left once the one is connected", async () => {
    expect(await repoSlotsLeft(asDb(base()), "org-1")).toEqual({ left: 0, limit: 1 });
    expect(await repoSlotsLeft(asDb(base({ repositories: [] })), "org-1")).toEqual({ left: 1, limit: 1 });
  });
  it("members: a 3rd is refused, with a message", async () => {
    expect((await checkMemberSlot(asDb(base()), "org-1")).allowed).toBe(true);
    const full = await checkMemberSlot(asDb(base({ org_members: [{ id: "m1", org_id: "org-1" }, { id: "m2", org_id: "org-1" }] })), "org-1");
    expect(full.allowed).toBe(false);
    expect(full.message).toMatch(/2 team members/);
  });
  it("scan usage for the dashboard", async () => {
    expect(await scanUsage(asDb(base({ scans: scans(2) })), "org-1")).toEqual({ plan: "free", used: 2, limit: 3 });
  });
});
