import { syncAutoIncidents } from "@/lib/autoIncidents";
import { fetchUnattestedRiskState } from "@/lib/dashboardAggregate";

jest.mock("@/lib/dashboardAggregate", () => ({ fetchUnattestedRiskState: jest.fn() }));
jest.mock("@/lib/cache", () => ({
  cached: (_k: string, _t: number, fn: () => unknown) => fn(),
  cacheKeys: { autoIncidentState: (o: string) => `a:${o}` },
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn() }));

type Row = Record<string, unknown> & { id: string };
const structuredCopy = (r: Row): Row => JSON.parse(JSON.stringify(r));

/** Just enough of the Supabase query builder for syncAutoIncidents, over an in-memory incidents table. */
function fakeDb() {
  const rows: Row[] = [];
  let seq = 0;
  const db = {
    from: () => {
      const filters: Array<(r: Row) => boolean> = [];
      let pending: { kind: "update"; patch: Record<string, unknown> } | null = null;
      const b = {
        select: () => b,
        eq: (c: string, v: unknown) => { filters.push(r => r[c] === v); return b; },
        is: (c: string, v: unknown) => { filters.push(r => (r[c] ?? null) === v); return b; },
        order: () => b,
        // Reads return copies, like a real database: a later update must not rewrite what was already read.
        single: () => { const r = rows.find(x => filters.every(f => f(x))); return Promise.resolve({ data: r ? structuredCopy(r) : null }); },
        update: (patch: Record<string, unknown>) => { pending = { kind: "update", patch }; return b; },
        insert: (row: Record<string, unknown>) => {
          const r = { id: `i${++seq}`, ...row } as Row;
          rows.push(r);
          return { select: () => ({ single: () => Promise.resolve({ data: { id: r.id } }) }) };
        },
        then: (res: (v: unknown) => unknown) => {
          const hit = rows.filter(r => filters.every(f => f(r)));
          if (pending) for (const r of hit) Object.assign(r, pending.patch);
          return Promise.resolve({ data: hit.map(structuredCopy) }).then(res);
        },
      };
      return b;
    },
  };
  return { db: db as never, rows };
}

const state = (files: Array<{ repo: string; file_path: string }>) => ({
  top_risk_files: files.map(f => ({ ...f, ai_pct: 0.9, risk_score: "CRITICAL", pr_number: 1, attested: false })),
  unattested_deploy_count: 0, repos: [], attestation_rate: 1,
});
const mockState = fetchUnattestedRiskState as jest.Mock;

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
      "Auto-resolved: no longer an unattested CRITICAL file in the repository's latest scan",
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
});
