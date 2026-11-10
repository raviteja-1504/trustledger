import { fetchContentByHash } from "@/lib/contentByHash";

// A minimal stand-in for the Supabase query builder: records each query's filters and serves rows from an
// in-memory table in which the same source text is stored on several rows (a file carried through scans).
type Row = { org_id: string; content_hash: string; content: string | null };

function fakeDb(rows: Row[]) {
  const queries: Array<{ hash?: string; limit?: number }> = [];
  const db = {
    from: () => {
      const q: { org?: string; hash?: string; notNull?: boolean; limit?: number } = {};
      const builder = {
        select: () => builder,
        eq: (col: string, v: string) => { if (col === "org_id") q.org = v; if (col === "content_hash") q.hash = v; return builder; },
        not: () => { q.notNull = true; return builder; },
        limit: (n: number) => {
          q.limit = n;
          queries.push({ hash: q.hash, limit: n });
          const hits = rows.filter(r => r.org_id === q.org && r.content_hash === q.hash && (!q.notNull || r.content !== null));
          return Promise.resolve({ data: hits.slice(0, n) });
        },
      };
      return builder;
    },
  };
  return { db: db as never, queries };
}

describe("fetchContentByHash", () => {
  const rows: Row[] = [
    ...Array.from({ length: 20 }, () => ({ org_id: "o1", content_hash: "h1", content: "source one" })),
    { org_id: "o1", content_hash: "h2", content: null },
    { org_id: "o1", content_hash: "h2", content: "source two" },
    { org_id: "o2", content_hash: "h3", content: "other org" },
  ];

  it("returns one copy per hash, asking for a single row each time", async () => {
    const { db, queries } = fakeDb(rows);
    const out = await fetchContentByHash(db, "o1", ["h1", "h2", "h1"]);
    expect(Object.fromEntries(out)).toEqual({ h1: "source one", h2: "source two" });
    expect(queries).toHaveLength(2);
    expect(queries.every(q => q.limit === 1)).toBe(true);
  });

  it("stays inside the caller's org and skips hashes nobody holds", async () => {
    const { db } = fakeDb(rows);
    const out = await fetchContentByHash(db, "o1", ["h3", "missing"]);
    expect(out.size).toBe(0);
  });
});
