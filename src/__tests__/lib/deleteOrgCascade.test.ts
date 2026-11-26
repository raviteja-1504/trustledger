/**
 * @jest-environment node
 *
 * Drift guard for supabase/migrations/20261127_delete_org_cascade.sql. The SQL cannot run in the unit tests, so this
 * checks what can go wrong without running it: a new customer-data table (any table with org_id) that nobody added to
 * the deletion list would survive an organisation's deletion, and the function must stay callable only by the server.
 */
import fs from "fs";
import path from "path";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { orgTables } = require("../../../scripts/tenantScopeAudit.cjs") as { orgTables: () => Set<string> };

const MIGRATION = path.join(__dirname, "../../../supabase/migrations/20261127_delete_org_cascade.sql");
const sql = fs.readFileSync(MIGRATION, "utf8");

/** Immutable evidence, retained on purpose (see the policy comment in the migration). */
const RETAINED = new Set(["audit_log", "attestations", "audit_checkpoints", "signing_keys"]);

const listed = (): string[] => {
  const m = /tbls\s+text\[\]\s*:=\s*ARRAY\[([\s\S]*?)\];/.exec(sql);
  if (!m) throw new Error("table list not found in the migration");
  return [...m[1].matchAll(/'(\w+)'/g)].map(x => x[1]);
};

describe("delete_org_cascade table list", () => {
  it("covers every org-scoped table except the retained evidence tables", () => {
    const expected = [...orgTables()].filter(t => !RETAINED.has(t)).sort();
    expect([...listed()].sort()).toEqual(expected);
  });

  it("never lists a retained evidence table", () => {
    for (const t of listed()) expect(RETAINED.has(t)).toBe(false);
  });

  it("has no duplicates", () => {
    expect(new Set(listed()).size).toBe(listed().length);
  });
});

describe("delete_org_cascade permissions", () => {
  it("is executable by service_role only", () => {
    expect(sql).toMatch(/REVOKE ALL ON FUNCTION delete_org_cascade\(uuid\) FROM PUBLIC;/);
    expect(sql).toMatch(/REVOKE ALL ON FUNCTION delete_org_cascade\(uuid\) FROM anon, authenticated;/);
    expect(sql).toMatch(/GRANT EXECUTE ON FUNCTION delete_org_cascade\(uuid\) TO service_role;/);
    expect(sql).not.toMatch(/GRANT EXECUTE[^;]*(anon|authenticated|PUBLIC)/i);
  });

  it("does not try to delete the immutable tables or the organizations row", () => {
    expect(sql).not.toMatch(/DELETE FROM (audit_log|attestations|audit_checkpoints|signing_keys|organizations)\b/i);
  });
});
