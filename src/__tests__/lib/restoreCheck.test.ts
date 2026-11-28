/**
 * @jest-environment node
 *
 * scripts/restore-check.cjs: what a restore can break at the SQL level -- an audit entry whose parent is gone, and forks.
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { checkChainLinks } = require("../../../scripts/restore-check.cjs") as { checkChainLinks: (rows: Array<{ id: number; prev_hash: string | null; entry_hash: string }>) => { orphans: number[]; forks: number[] } };

const chain = (n: number) => Array.from({ length: n }, (_, i) => ({ id: i + 1, prev_hash: i === 0 ? null : `h${i}`, entry_hash: `h${i + 1}` }));

it("an intact chain has no orphans and no forks", () => {
  expect(checkChainLinks(chain(5))).toEqual({ orphans: [], forks: [] });
});

it("a restore that lost rows in the middle leaves orphans from the first missing parent", () => {
  const rows = chain(6).filter(r => r.id !== 3);                    // entry 3 gone: 4 points at h3
  expect(checkChainLinks(rows).orphans).toEqual([4]);
});

it("a restore that lost the newest rows is not detected by links alone (the checkpoints are what catch that): no false alarm", () => {
  expect(checkChainLinks(chain(6).slice(0, 4))).toEqual({ orphans: [], forks: [] });
});

it("a first entry that already has a parent, or a later entry with none, is an orphan", () => {
  expect(checkChainLinks([{ id: 1, prev_hash: "gone", entry_hash: "h1" }]).orphans).toEqual([1]);
  expect(checkChainLinks([...chain(2), { id: 3, prev_hash: null, entry_hash: "x" }]).orphans).toEqual([3]);
});

it("two entries sharing a parent are reported as forks", () => {
  const rows = [...chain(3), { id: 4, prev_hash: "h2", entry_hash: "other" }];
  expect(checkChainLinks(rows).forks).toEqual([4]);
});

it("exits 2 with a message when it is not given a database", () => {
  const { spawnSync } = require("child_process") as typeof import("child_process");
  const r = spawnSync(process.execPath, ["scripts/restore-check.cjs"], { encoding: "utf8", env: { PATH: process.env.PATH ?? "", NODE_ENV: "test" } as NodeJS.ProcessEnv, cwd: require("path").join(__dirname, "../../..") });
  expect(r.status).toBe(2);
  expect(r.stderr).toMatch(/SUPABASE_URL/);
});
