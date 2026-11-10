/**
 * @jest-environment node
 *
 * Upstash rejects a request body over about 1 MB, and the cache swallows write errors -- so a scan's files (several MB
 * with their source) were never cached, and every view of a large PR re-read the whole scan from the database. The
 * fake Redis below enforces that limit and, like the real client, hands back JSON values already parsed.
 */
const LIMIT = 1_000_000;
const store = new Map<string, string>();
const setCalls: Array<{ key: string; size: number }> = [];

jest.mock("@upstash/redis", () => ({
  Redis: class {
    async get(k: string) {
      const v = store.get(k);
      if (v === undefined) return null;
      try { return JSON.parse(v); } catch { return v; }
    }
    async set(k: string, v: string) {
      if (v.length > LIMIT) throw new Error("ERR max request size exceeded");
      setCalls.push({ key: k, size: v.length });
      store.set(k, v);
      return "OK";
    }
    async del(...ks: string[]) { for (const k of ks) store.delete(k); return ks.length; }
  },
}));

process.env.UPSTASH_REDIS_REST_URL = "https://fake.upstash.io";
process.env.UPSTASH_REDIS_REST_TOKEN = "t";

import { cacheGet, cacheSet } from "@/lib/cache";

beforeEach(() => { store.clear(); setCalls.length = 0; });

const files = (n: number, bodyBytes: number) => Array.from({ length: n }, (_, i) => ({ file_path: `src/f${i}.ts`, content: `// ${i}\n` + "const x = require('y');\n".repeat(Math.ceil(bodyBytes / 24)) }));
const noise = (bytes: number) => Array.from({ length: bytes }, () => Math.floor(Math.random() * 36).toString(36)).join("");

describe("large cached values", () => {
  it("a scan-sized value (several MB of source) is stored and read back intact", async () => {
    const value = files(1242, 4000);
    expect(JSON.stringify(value).length).toBeGreaterThan(4_000_000);
    await cacheSet("scanfiles:v2:big", value, 60);
    expect(await cacheGet<typeof value>("scanfiles:v2:big")).toEqual(value);
    // nothing sent to Redis exceeded its request limit
    expect(Math.max(...setCalls.map(c => c.size))).toBeLessThanOrEqual(LIMIT);
  });

  it("a value that does not compress is split across keys and reassembled", async () => {
    const value = { blob: noise(2_500_000) };
    await cacheSet("k", value, 60);
    expect(setCalls.length).toBeGreaterThan(2);
    expect(setCalls.every(c => c.size <= LIMIT)).toBe(true);
    expect(await cacheGet<typeof value>("k")).toEqual(value);
  });

  it("a missing chunk is a miss, never a corrupt value", async () => {
    await cacheSet("k", { blob: noise(2_500_000) }, 60);
    store.delete("k~1");
    expect(await cacheGet("k")).toBeNull();
  });

  it("small values are stored as plain JSON, exactly as before", async () => {
    await cacheSet("small", { a: 1, list: ["x"] }, 60);
    expect(store.get("small")).toBe(JSON.stringify({ a: 1, list: ["x"] }));
    expect(await cacheGet("small")).toEqual({ a: 1, list: ["x"] });
  });

  it("a plain string value still round-trips", async () => {
    await cacheSet("s", "hello", 60);
    expect(await cacheGet("s")).toBe("hello");
  });
});
