/**
 * @jest-environment node
 *
 * Redis commands are what the plan counts. Reading many keys one by one costs one command each; one MGET costs one however many keys it
 * reads (a dependency report of hundreds of packages), and a result only worth reusing inside one server instance needs none at all.
 */
const commands = { get: 0, mget: 0, set: 0, del: 0 };
const store = new Map<string, string>();

jest.mock("@upstash/redis", () => ({
  Redis: class {
    async get(k: string) { commands.get++; const v = store.get(k); if (v === undefined) return null; try { return JSON.parse(v); } catch { return v; } }
    async mget(...ks: string[]) { commands.mget++; return ks.map(k => { const v = store.get(k); if (v === undefined) return null; try { return JSON.parse(v); } catch { return v; } }); }
    async set(k: string, v: string) { commands.set++; store.set(k, v); return "OK"; }
    async del(...ks: string[]) { commands.del++; for (const k of ks) store.delete(k); return ks.length; }
  },
}));

process.env.UPSTASH_REDIS_REST_URL = "https://fake.upstash.io";
process.env.UPSTASH_REDIS_REST_TOKEN = "t";

import { cacheGetMany, cacheSet, memoryCached } from "@/lib/cache";

beforeEach(() => { store.clear(); commands.get = commands.mget = commands.set = commands.del = 0; });

describe("cacheGetMany", () => {
  it("reads 450 keys in 3 commands (200 per MGET), in order, with misses as null", async () => {
    for (let i = 0; i < 450; i += 2) await cacheSet(`k${i}`, { n: i }, 60);        // every other key exists
    commands.set = 0;
    const keys = Array.from({ length: 450 }, (_, i) => `k${i}`);
    const got = await cacheGetMany<{ n: number }>(keys);
    expect(commands.mget).toBe(3);
    expect(commands.get).toBe(0);
    expect(got).toHaveLength(450);
    expect(got[0]).toEqual({ n: 0 });
    expect(got[1]).toBeNull();
    expect(got[448]).toEqual({ n: 448 });
    expect(got.filter(v => v !== null)).toHaveLength(225);
  });

  it("gives the same answers as reading one by one: arrays, objects, strings", async () => {
    await cacheSet("a", ["GHSA-1", "GHSA-2"], 60); await cacheSet("b", { id: "x", aliases: [] }, 60); await cacheSet("c", [], 60);
    expect(await cacheGetMany(["a", "b", "c", "missing"])).toEqual([["GHSA-1", "GHSA-2"], { id: "x", aliases: [] }, [], null]);
  });

  it("an empty list reads nothing", async () => {
    expect(await cacheGetMany([])).toEqual([]);
    expect(commands.mget).toBe(0);
  });
});

describe("memoryCached", () => {
  it("computes once and then answers from this instance's memory, with no Redis command at all", async () => {
    let computed = 0;
    const fn = async () => { computed++; return { open: ["f1"], n: computed }; };
    const a = await memoryCached("incident:org-1:v1", 60, fn);
    const b = await memoryCached("incident:org-1:v1", 60, fn);
    expect(computed).toBe(1);
    expect(b).toEqual(a);
    expect(commands).toEqual({ get: 0, mget: 0, set: 0, del: 0 });
  });

  it("a different key (a new data version) is a new computation; concurrent callers share one", async () => {
    let computed = 0;
    const slow = async () => { computed++; await new Promise(r => setTimeout(r, 20)); return computed; };
    const [x, y] = await Promise.all([memoryCached("k:v2", 60, slow), memoryCached("k:v2", 60, slow)]);
    expect(x).toBe(y);
    expect(computed).toBe(1);
    await memoryCached("k:v3", 60, slow);
    expect(computed).toBe(2);
  });
});

describe("cache lifetimes", () => {
  it("the lists that pages poll live long enough to be hits: they are invalidated on change, not by a short expiry", async () => {
    const { TTL } = await import("@/lib/cache");
    expect(TTL.VIOLATIONS).toBeGreaterThanOrEqual(300);   // keyed by the org's data version
    expect(TTL.SECRETS).toBeGreaterThanOrEqual(300);      // deleted on every write
  });
});
