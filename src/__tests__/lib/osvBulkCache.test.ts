/**
 * @jest-environment node
 *
 * A dependency report used to read the cache once per package (and once per vulnerability): hundreds of Redis commands each time a scan
 * changed the dependencies, even when everything was cached. It is now one bulk read per 200 keys.
 */
const commands = { get: 0, mget: 0, set: 0 };
const store = new Map<string, string>();
jest.mock("@upstash/redis", () => ({
  Redis: class {
    private read(k: string) { const v = store.get(k); if (v === undefined) return null; try { return JSON.parse(v); } catch { return v; } }
    async get(k: string) { commands.get++; return this.read(k); }
    async mget(...ks: string[]) { commands.mget++; return ks.map(k => this.read(k)); }
    async set(k: string, v: string) { commands.set++; store.set(k, v); return "OK"; }
    async del() { return 1; }
  },
}));
process.env.UPSTASH_REDIS_REST_URL = "https://fake.upstash.io";
process.env.UPSTASH_REDIS_REST_TOKEN = "t";

import { lookupVulnerabilities } from "@/lib/osvClient";

const fetchMock = jest.fn();
beforeEach(() => { store.clear(); commands.get = commands.mget = commands.set = 0; fetchMock.mockReset(); global.fetch = fetchMock as unknown as typeof fetch; });

const pkg = (i: number) => ({ ecosystem: "npm", name: `pkg-${i}`, version: "1.0.0" });
const pkgKey = (i: number) => `osvpkg:npm:pkg-${i}:1.0.0`;

it("300 packages, all cached and clean: 2 Redis commands, no network, no per-package reads", async () => {
  for (let i = 0; i < 300; i++) store.set(pkgKey(i), JSON.stringify([]));
  const result = await lookupVulnerabilities(Array.from({ length: 300 }, (_, i) => pkg(i)));
  expect(result.size).toBe(300);
  expect(commands.mget).toBe(2);
  expect(commands.get).toBe(0);
  expect(commands.set).toBe(0);
  expect(fetchMock).not.toHaveBeenCalled();
});

it("vulnerable packages: their cached details are read in one bulk read too, and nothing is fetched", async () => {
  for (let i = 0; i < 60; i++) {
    store.set(pkgKey(i), JSON.stringify([`GHSA-${i % 5}`]));
  }
  for (let v = 0; v < 5; v++) store.set(`osvvuln:v2:GHSA-${v}`, JSON.stringify({ id: `GHSA-${v}`, aliases: [], summary: `s${v}`, severity: "high", fixedIn: "2.0.0" }));
  const result = await lookupVulnerabilities(Array.from({ length: 60 }, (_, i) => pkg(i)));
  expect(result.get("npm|pkg-7|1.0.0")?.[0]).toMatchObject({ id: "GHSA-2", severity: "high" });
  expect(commands.mget).toBe(2);       // one for the 60 packages, one for the 5 distinct vulnerability ids
  expect(commands.get).toBe(0);
  expect(fetchMock).not.toHaveBeenCalled();
});
