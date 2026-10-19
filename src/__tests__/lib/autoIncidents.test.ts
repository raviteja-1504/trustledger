import { backlogTitle, syncAutoIncidents } from "@/lib/autoIncidents";
import { fetchUnattestedRiskState } from "@/lib/dashboardAggregate";

jest.mock("@/lib/dashboardAggregate", () => ({ fetchUnattestedRiskState: jest.fn() }));
const cacheStore = new Map<string, unknown>();
let realCache = false;
jest.mock("@/lib/cache", () => ({
  cached: async (k: string, _t: number, fn: () => unknown) => {
    if (!realCache) return fn();
    if (cacheStore.has(k)) return cacheStore.get(k);
    const v = await fn(); cacheStore.set(k, v); return v;
  },
  cacheKeys: { autoIncidentState: (o: string) => `a:${o}` },
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn() }));

type Row = Record<string, unknown> & { id: string };
const structuredCopy = (r: Row): Row => JSON.parse(JSON.stringify(r));

/** Just enough of the Supabase query builder for syncAutoIncidents, over in-memory tables. */
function fakeDb(tables: Record<string, Row[]> = {}) {
  const store: Record<string, Row[]> = { incidents: [], ...tables };
  let seq = 0;
  const db = {
    from: (table: string) => {
      const rows = (store[table] ??= []);
      const filters: Array<(r: Row) => boolean> = [];
      let pending: { kind: "update"; patch: Record<string, unknown> } | null = null;
      let desc: string | null = null, max: number | null = null;
      const pick = () => {
        let hit = rows.filter(r => filters.every(f => f(r)));
        if (desc) hit = [...hit].sort((a, b) => String(b[desc!]).localeCompare(String(a[desc!])));
        if (max != null) hit = hit.slice(0, max);
        return hit;
      };
      const b = {
        select: () => b,
        eq: (c: string, v: unknown) => { filters.push(r => r[c] === v); return b; },
        neq: (c: string, v: unknown) => { filters.push(r => r[c] !== v); return b; },
        is: (c: string, v: unknown) => { filters.push(r => (r[c] ?? null) === v); return b; },
        order: (c: string, o?: { ascending?: boolean }) => { if (o?.ascending === false) desc = c; return b; },
        limit: (n: number) => { max = n; return b; },
        // Reads return copies, like a real database: a later update must not rewrite what was already read.
        single: () => { const r = pick()[0]; return Promise.resolve({ data: r ? structuredCopy(r) : null }); },
        maybeSingle: () => { const r = pick()[0]; return Promise.resolve({ data: r ? structuredCopy(r) : null, error: null }); },
        update: (patch: Record<string, unknown>) => { pending = { kind: "update", patch }; return b; },
        insert: (row: Record<string, unknown>) => {
          const r = { id: `i${++seq}`, ...row } as Row;
          rows.push(r);
          return { select: () => ({ single: () => Promise.resolve({ data: { id: r.id } }) }) };
        },
        then: (res: (v: unknown) => unknown) => {
          const hit = pick();
          if (pending) for (const r of hit) Object.assign(r, pending.patch);
          return Promise.resolve({ data: hit.map(structuredCopy), error: null }).then(res);
        },
      };
      return b;
    },
  };
  return { db: db as never, rows: store.incidents, store };
}

const state = (files: Array<{ repo: string; file_path: string; scan_id?: string }>, extra: { closed_files?: string[]; unattested_deploy_count?: number; repos?: Array<{ repo: string; attestation_rate: number }> } = {}) => ({
  top_risk_files: files.map(f => ({ scan_id: "s1", ...f, ai_pct: 0.9, risk_score: "CRITICAL", pr_number: 1, attested: false })),
  closed_files: extra.closed_files ?? [],
  unattested_deploy_count: extra.unattested_deploy_count ?? 0, repos: extra.repos ?? [], attestation_rate: 1,
});
const mockState = fetchUnattestedRiskState as jest.Mock;

beforeEach(() => { mockState.mockReset(); cacheStore.clear(); realCache = false; });

describe("syncAutoIncidents", () => {
  it("reuses one incident per file as it leaves and re-enters the open set, instead of inserting a new one", async () => {
    const { db, rows } = fakeDb();
    const f = { repo: "acme/api", file_path: "src/auth.ts" };
    mockState.mockResolvedValueOnce(state([f]));
    await syncAutoIncidents(db, "o1");
    mockState.mockResolvedValueOnce(state([]));          // another PR's scan is now the repo's latest
    await syncAutoIncidents(db, "o1");
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("resolved");
    mockState.mockResolvedValueOnce(state([f]));          // back again
    await syncAutoIncidents(db, "o1");
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("active");
    expect((rows[0].timeline as Array<{ action: string }>).map(t => t.action)).toEqual([
      "CRITICAL file detected by TrustLedger scan", "P1 incident auto-created",
      "Auto-resolved: attested, resolved, or no longer a CRITICAL file in the repository's latest scan",
      "Re-opened: CRITICAL file is unattested again in the latest scan",
    ]);
  });

  it("treats the same path in two repositories as two incidents, resolved independently", async () => {
    const { db, rows } = fakeDb();
    const api = { repo: "acme/api", file_path: "src/db.ts" }, web = { repo: "acme/web", file_path: "src/db.ts" };
    mockState.mockResolvedValueOnce(state([api, web]));
    await syncAutoIncidents(db, "o1");
    mockState.mockResolvedValueOnce(state([api]));        // acme/web's copy was attested
    await syncAutoIncidents(db, "o1");
    const status = Object.fromEntries(rows.map(r => [r.affected_repo, r.status]));
    expect(status).toEqual({ "acme/api": "active", "acme/web": "resolved" });
  });

  it("a finding resolved or accepted on the violations page ends its incident too", async () => {
    const f = { repo: "acme/api", file_path: "src/pay.ts", scan_id: "s9" };
    // Resolved in the violations table:
    const a = fakeDb();
    mockState.mockResolvedValueOnce(state([f]));
    await syncAutoIncidents(a.db, "o1");
    mockState.mockResolvedValueOnce(state([f], { closed_files: ["acme/api::src/pay.ts"] }));
    await syncAutoIncidents(a.db, "o1");
    expect(a.rows[0].status).toBe("resolved");
    // Resolved as a status override ("crit::<scan>::<path>"), the way the violations page records it:
    const b = fakeDb({ violation_overrides: [] });
    mockState.mockResolvedValueOnce(state([f]));
    await syncAutoIncidents(b.db, "o1");
    b.store.violation_overrides.push({ id: "o", org_id: "o1", violation_id: "crit::s9::src/pay.ts", status: "resolved" });
    mockState.mockResolvedValueOnce(state([f]));
    await syncAutoIncidents(b.db, "o1");
    expect(b.rows[0].status).toBe("resolved");
    // Another org's override doesn't count.
    const c = fakeDb({ violation_overrides: [{ id: "o", org_id: "o2", violation_id: "crit::s9::src/pay.ts", status: "resolved" }] });
    mockState.mockResolvedValue(state([f]));
    await syncAutoIncidents(c.db, "o1");
    expect(c.rows[0].status).toBe("active");
  });

  it("right after an attestation the cached state isn't reused: the cache key carries the data version", async () => {
    realCache = true;
    const { db, rows, store } = fakeDb({ attestations: [], scans: [{ id: "s1", org_id: "o1", created_at: "2026-10-19T10:00:00Z" }], violation_overrides: [] });
    const f = { repo: "acme/api", file_path: "src/auth.ts" };
    mockState.mockResolvedValueOnce(state([f]));
    await syncAutoIncidents(db, "o1");
    expect(rows[0].status).toBe("active");
    // The file is attested: a new attestation row changes the version, so the fresh state is loaded.
    store.attestations.push({ id: "a1", org_id: "o1", created_at: "2026-10-19T10:05:00Z" });
    mockState.mockResolvedValueOnce(state([]));
    await syncAutoIncidents(db, "o1");
    expect(rows[0].status).toBe("resolved");
    expect(mockState).toHaveBeenCalledTimes(2);
  });

  it("an active backlog incident's title follows the current count", async () => {
    const { db, rows } = fakeDb();
    mockState.mockResolvedValueOnce(state([], { unattested_deploy_count: 8, repos: [{ repo: "acme/api", attestation_rate: 0.2 }, { repo: "acme/web", attestation_rate: 0.5 }] }));
    await syncAutoIncidents(db, "o1");
    expect(rows[0].title).toBe("8 CRITICAL/HIGH files unattested across 2 repos");
    mockState.mockResolvedValueOnce(state([], { unattested_deploy_count: 5, repos: [{ repo: "acme/api", attestation_rate: 0.6 }, { repo: "acme/web", attestation_rate: 0.5 }] }));
    await syncAutoIncidents(db, "o1");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ status: "active", title: "5 CRITICAL/HIGH files unattested across 2 repos" });
    expect(backlogTitle(1, 1)).toBe("1 CRITICAL/HIGH file unattested across 1 repo");
  });
});
