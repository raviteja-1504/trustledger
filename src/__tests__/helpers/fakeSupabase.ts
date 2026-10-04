/**
 * A small in-memory stand-in for the Supabase query builder, enough to run API route handlers end to end in
 * tests: select/eq/neq/is/in/lt/order/limit/single/maybeSingle, count+head. Writes are recorded in `writes`
 * AND applied to the in-memory rows (insert appends; update/upsert/delete act on the filtered rows), and
 * `.select()` after a write returns the affected rows, as PostgREST does.
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
  private payload: unknown = undefined;
  private returning = false;

  constructor(private rows: Row[], private writes: Array<{ table: string; op: string; payload?: unknown }>, private table: string) {}

  select(_cols?: string, opts?: { count?: string; head?: boolean }) {
    if (this.write) { this.returning = true; return this; }
    if (opts?.count) { this.countMode = true; this.head = !!opts.head; }
    return this;
  }
  eq(c: string, v: unknown) { this.filters.push(r => r[c] === v); return this; }
  neq(c: string, v: unknown) { this.filters.push(r => r[c] != null && r[c] !== v); return this; } // SQL: NULL != x is not true
  /** PostgREST or-filter: "col.op.value,col.op.value" with op eq / neq / is (null|true|false). */
  or(expr: string) {
    const conds = expr.split(",").map(part => {
      const [c, op, ...rest] = part.split(".");
      const raw = rest.join(".");
      const v: unknown = raw === "null" ? null : raw === "true" ? true : raw === "false" ? false : raw;
      if (op === "is") return (r: Row) => (v === null ? r[c] == null : r[c] === v);
      if (op === "eq") return (r: Row) => r[c] != null && String(r[c]) === String(v);
      if (op === "neq") return (r: Row) => r[c] != null && String(r[c]) !== String(v);
      throw new Error(`fakeSupabase: unsupported or() operator ${op}`);
    });
    this.filters.push(r => conds.some(f => f(r)));
    return this;
  }
  is(c: string, v: unknown) { this.filters.push(r => (v === null ? r[c] == null : r[c] === v)); return this; }
  in(c: string, vs: unknown[]) { this.filters.push(r => vs.includes(r[c])); return this; }
  lt(c: string, v: string) { this.filters.push(r => String(r[c]) < v); return this; }
  order(c: string, o?: { ascending?: boolean }) { this.orderBy = [c, o?.ascending ?? true]; return this; }
  limit(n: number) { this.max = n; return this; }
  single() { this.one = "single"; return this; }
  maybeSingle() { this.one = "maybe"; return this; }
  insert(payload: unknown) { this.write = "insert"; this.payload = payload; this.writes.push({ table: this.table, op: "insert", payload }); return this; }
  update(payload: unknown) { this.write = "update"; this.payload = payload; this.writes.push({ table: this.table, op: "update", payload }); return this; }
  upsert(payload: unknown) { this.write = "upsert"; this.payload = payload; this.writes.push({ table: this.table, op: "upsert", payload }); return this; }
  delete() { this.write = "delete"; this.writes.push({ table: this.table, op: "delete" }); return this; }

  then<A, B>(ok?: ((v: unknown) => A | PromiseLike<A>) | null, bad?: ((e: unknown) => B | PromiseLike<B>) | null): PromiseLike<A | B> {
    return Promise.resolve(this.result()).then(ok, bad);
  }

  private applied: { data: unknown; error: null } | null = null;

  private result() {
    if (this.write) return (this.applied ??= this.applyWrite());
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

  private applyWrite(): { data: unknown; error: null } {
    let affected: Row[] = [];
    if (this.write === "insert" || this.write === "upsert") {
      affected = (Array.isArray(this.payload) ? this.payload : [this.payload]).map(p => ({ ...(p as Row) }));
      this.rows.push(...affected);
    } else if (this.write === "update") {
      affected = this.rows.filter(r => this.filters.every(f => f(r)));
      for (const r of affected) Object.assign(r, this.payload as Row);
    } else if (this.write === "delete") {
      affected = this.rows.filter(r => this.filters.every(f => f(r)));
      for (const r of affected) this.rows.splice(this.rows.indexOf(r), 1);
    }
    if (!this.returning) return { data: null, error: null };
    if (this.one) return { data: affected[0] ?? null, error: null };
    return { data: affected, error: null };
  }
}

export function fakeSupabase(tables: Record<string, Row[]>) {
  const writes: Array<{ table: string; op: string; payload?: unknown }> = [];
  return {
    writes,
    client: { from: (table: string) => new FakeQuery((tables[table] ??= []), writes, table) },
  };
}
