/**
 * A small in-memory stand-in for the Supabase query builder, enough to run API route handlers end to end in
 * tests: select/eq/neq/in/lt/order/limit/single/maybeSingle, count+head, and no-op writes (recorded).
 */
type Row = Record<string, unknown>;

class FakeQuery implements PromiseLike<unknown> {
  private filters: Array<(r: Row) => boolean> = [];
  private countMode = false;
  private head = false;
  private one: "single" | "maybe" | null = null;
  private orderBy: [string, boolean] | null = null;
  private max: number | null = null;
  private write: string | null = null;

  constructor(private rows: Row[], private writes: Array<{ table: string; op: string; payload?: unknown }>, private table: string) {}

  select(_cols?: string, opts?: { count?: string; head?: boolean }) {
    if (opts?.count) { this.countMode = true; this.head = !!opts.head; }
    return this;
  }
  eq(c: string, v: unknown) { this.filters.push(r => r[c] === v); return this; }
  neq(c: string, v: unknown) { this.filters.push(r => r[c] !== v); return this; }
  in(c: string, vs: unknown[]) { this.filters.push(r => vs.includes(r[c])); return this; }
  lt(c: string, v: string) { this.filters.push(r => String(r[c]) < v); return this; }
  order(c: string, o?: { ascending?: boolean }) { this.orderBy = [c, o?.ascending ?? true]; return this; }
  limit(n: number) { this.max = n; return this; }
  single() { this.one = "single"; return this; }
  maybeSingle() { this.one = "maybe"; return this; }
  insert(payload: unknown) { this.write = "insert"; this.writes.push({ table: this.table, op: "insert", payload }); return this; }
  update(payload: unknown) { this.write = "update"; this.writes.push({ table: this.table, op: "update", payload }); return this; }
  upsert(payload: unknown) { this.write = "upsert"; this.writes.push({ table: this.table, op: "upsert", payload }); return this; }
  delete() { this.write = "delete"; this.writes.push({ table: this.table, op: "delete" }); return this; }

  then<A, B>(ok?: ((v: unknown) => A | PromiseLike<A>) | null, bad?: ((e: unknown) => B | PromiseLike<B>) | null): PromiseLike<A | B> {
    return Promise.resolve(this.result()).then(ok, bad);
  }

  private result() {
    if (this.write) return { data: null, error: null };
    let rows = this.rows.filter(r => this.filters.every(f => f(r)));
    if (this.orderBy) {
      const [c, asc] = this.orderBy;
      rows = [...rows].sort((a, b) => (String(a[c]) < String(b[c]) ? -1 : String(a[c]) > String(b[c]) ? 1 : 0) * (asc ? 1 : -1));
    }
    if (this.max != null) rows = rows.slice(0, this.max);
    if (this.countMode) return { data: this.head ? null : rows, count: rows.length, error: null };
    if (this.one) return rows[0] ? { data: rows[0], error: null } : { data: null, error: this.one === "single" ? { message: "no rows" } : null };
    return { data: rows, error: null };
  }
}

export function fakeSupabase(tables: Record<string, Row[]>) {
  const writes: Array<{ table: string; op: string; payload?: unknown }> = [];
  return {
    writes,
    client: { from: (table: string) => new FakeQuery(tables[table] ?? [], writes, table) },
  };
}
