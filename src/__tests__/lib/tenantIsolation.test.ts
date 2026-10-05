/**
 * @jest-environment node
 *
 * Tenant isolation guard: every server-side query on a customer-data table (one with org_id) must be limited
 * to one organisation -- by its own org_id filter, or as a reviewed entry in lib/tenantScopeExceptions.ts.
 * A new query that skips the filter fails here; so does an exception that no longer matches any query.
 */
import { TENANT_SCOPE_EXCEPTIONS } from "@/lib/tenantScopeExceptions";

type Query = { file: string; line: number; table: string; op: string; scope: string; keys: string[]; text: string };
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { audit, orgTables, analyseSource } = require("../../../scripts/tenantScopeAudit.cjs") as {
  audit: () => Query[];
  orgTables: () => Set<string>;
  analyseSource: (src: string, file: string, tables: Set<string>) => Query[];
};

const sig = (q: { file: string; table: string; op: string; keys: string[] }) => JSON.stringify([q.file, q.table, q.op, q.keys]);

describe("tenant scope classifier", () => {
  const tables = new Set(["violations", "scans"]);
  const scopeOf = (code: string) => analyseSource(code, "x.ts", tables).map(q => q.scope);

  it("accepts an org_id filter or an insert payload that sets org_id", () => {
    expect(scopeOf(`db.from("violations").select("id").eq("id", id).eq("org_id", org_id)`)).toEqual(["direct"]);
    expect(scopeOf(`db.from("violations").update(u).match({ id, org_id })`)).toEqual(["direct"]);
    expect(scopeOf(`db.from("scans").insert({ org_id, repo_full_name: r })`)).toEqual(["direct"]);
  });

  it("flags an id-only filter, no filter, and an insert without org_id -- also through `as any` wrappers", () => {
    expect(scopeOf(`db.from("violations").update({ notes }).eq("id", body.id)`)).toEqual(["indirect"]);
    expect(scopeOf(`(db.from("scans") as any).select("health").eq("id", scanId).single()`)).toEqual(["indirect"]);
    expect(scopeOf(`db.from("scans").select("*")`)).toEqual(["none"]);
    expect(scopeOf(`db.from("scans").insert(row)`)).toEqual(["insert-without-org"]);
    // a .neq on org_id is not a scope
    expect(scopeOf(`db.from("scans").select("id").neq("org_id", x)`)).toEqual(["indirect"]);
  });

  it("ignores tables without org_id", () => {
    expect(analyseSource(`db.from("feature_flags").select("*")`, "x.ts", tables)).toEqual([]);
  });

  it("reads the customer-data tables from the migrations", () => {
    const t = orgTables();
    for (const name of ["scans", "violations", "scan_files", "attestations", "org_members", "ops_events"]) expect(t.has(name)).toBe(true);
    for (const name of ["organizations", "feature_flags", "vuln_catalog"]) expect(t.has(name)).toBe(false);
  });
});

describe("tenant isolation of server queries", () => {
  const unscoped = audit().filter(q => q.scope !== "direct");
  const live = new Map<string, Query[]>();
  for (const q of unscoped) live.set(sig(q), [...(live.get(sig(q)) ?? []), q]);

  it("every query without an org_id filter is a reviewed exception", () => {
    const allowed = new Map(TENANT_SCOPE_EXCEPTIONS.map(e => [sig(e), e.count ?? 1]));
    const unreviewed = [...live.entries()]
      .filter(([k, qs]) => qs.length > (allowed.get(k) ?? 0))
      .flatMap(([, qs]) => qs.map(q => `${q.file}:${q.line}  ${q.op} ${q.table} [${q.keys.join(", ")}]  ${q.text}`));
    expect(unreviewed).toEqual([]);
  });

  it("has no stale exceptions", () => {
    const stale = TENANT_SCOPE_EXCEPTIONS
      .filter(e => (live.get(sig(e))?.length ?? 0) < (e.count ?? 1))
      .map(e => `${e.file} ${e.op} ${e.table} [${e.keys.join(", ")}]`);
    expect(stale).toEqual([]);
  });

  it("lists each exception once", () => {
    const sigs = TENANT_SCOPE_EXCEPTIONS.map(sig);
    expect(new Set(sigs).size).toBe(sigs.length);
  });
});
