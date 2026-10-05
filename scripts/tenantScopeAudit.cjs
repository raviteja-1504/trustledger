/**
 * Tenant-scope audit: every server-side Supabase query against a table that holds customer data (has org_id),
 * classified by how it is limited to one organisation. Shared by the tenantIsolation test and for ad-hoc runs:
 *
 *   node scripts/tenantScopeAudit.cjs            → summary + every non-direct query
 *
 *   direct    .eq("org_id", …) / .match({ org_id }) / insert-upsert payload that sets org_id
 *   indirect  filtered by another key (scan_id, id, user_id, …) — safe only if that key was itself checked
 *   none      no filter at all
 */
const fs = require("fs");
const path = require("path");
const ts = require("typescript");

const ROOT = path.join(__dirname, "..");
const MIGRATIONS = path.join(ROOT, "supabase", "migrations");

function orgTables() {
  const out = new Set();
  for (const f of fs.readdirSync(MIGRATIONS)) {
    const s = fs.readFileSync(path.join(MIGRATIONS, f), "utf8");
    for (const m of s.matchAll(/create table(?: if not exists)?\s+(?:public\.)?(\w+)\s*\(([\s\S]*?)\n\);/gi)) if (/\borg_id\b/.test(m[2])) out.add(m[1]);
    for (const m of s.matchAll(/alter table(?: if exists)?\s+(?:public\.)?(\w+)\s+add column(?: if not exists)?\s+org_id/gi)) out.add(m[1]);
  }
  return out;
}

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]);
}

/** Server code: API routes and lib modules (client components use the anon key under RLS). */
function serverFiles() {
  return walk(path.join(ROOT, "src")).filter(f =>
    /\.(ts|tsx)$/.test(f) && !f.includes(`${path.sep}__tests__${path.sep}`) &&
    (f.includes(`${path.sep}app${path.sep}api${path.sep}`) || f.includes(`${path.sep}lib${path.sep}`)) &&
    !/^\s*["']use client["']/.test(fs.readFileSync(f, "utf8")));
}

const FILTERS = new Set(["eq", "neq", "in", "match", "or", "filter", "is", "contains", "lt", "lte", "gt", "gte", "like", "ilike"]);

/** Classify every query in one source text; `file` is the repo-relative path to report. */
function analyseSource(src, file, tables) {
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, file.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const found = [];
  const visit = node => {
    // .from("table")
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "from" &&
        node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0]) && tables.has(node.arguments[0].text)) {
      const table = node.arguments[0].text;
      // climb the method chain: from(...).select(...).eq(...)...
      let cur = node; const chain = [];
      // see through `(db.from("t") as any)` and `x!` wrappers between links
      const unwrap = () => { while (cur.parent && (ts.isParenthesizedExpression(cur.parent) || ts.isAsExpression(cur.parent) || ts.isNonNullExpression(cur.parent))) cur = cur.parent; };
      unwrap();
      while (cur.parent && ts.isPropertyAccessExpression(cur.parent) && cur.parent.parent && ts.isCallExpression(cur.parent.parent) && cur.parent.parent.expression === cur.parent) {
        chain.push({ name: cur.parent.name.text, args: cur.parent.parent.arguments });
        cur = cur.parent.parent;
        unwrap();
      }
      const op = chain.find(c => ["select", "insert", "update", "upsert", "delete"].includes(c.name))?.name ?? "select";
      const argText = a => a.getText(sf);
      let scope = "none"; const keys = [];
      for (const c of chain) {
        if (!FILTERS.has(c.name)) continue;
        const a0 = c.args[0];
        if (c.name === "match" && a0 && ts.isObjectLiteralExpression(a0)) {
          for (const p of a0.properties) { const k = p.name && p.name.getText(sf).replace(/["']/g, ""); keys.push(k); if (k === "org_id") scope = "direct"; }
          continue;
        }
        if (c.name === "or" && a0) { keys.push(`or(${argText(a0).slice(0, 40)})`); continue; }
        if (a0 && ts.isStringLiteral(a0)) { keys.push(a0.text); if (a0.text === "org_id" && (c.name === "eq" || c.name === "in")) scope = "direct"; }
      }
      if (scope !== "direct" && (op === "insert" || op === "upsert")) {
        const payload = chain.find(c => c.name === op)?.args[0];
        const text = payload ? argText(payload) : "";
        if (/\borg_id\b/.test(text)) scope = "direct";
        else if (payload) scope = "insert-without-org";
      }
      if (scope === "none" && keys.length > 0) scope = "indirect";
      const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
      found.push({ file, line: line + 1, table, op, scope, keys,
        text: cur.getText(sf).replace(/\s+/g, " ").slice(0, 160) });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

function audit() {
  const tables = orgTables();
  return serverFiles().flatMap(f => analyseSource(fs.readFileSync(f, "utf8"), path.relative(ROOT, f).replace(/\\/g, "/"), tables));
}

module.exports = { audit, orgTables, analyseSource };

if (require.main === module) {
  const all = audit();
  const by = s => all.filter(q => q.scope === s);
  console.log(`queries on org tables: ${all.length}  direct: ${by("direct").length}  indirect: ${by("indirect").length}  none: ${by("none").length}  insert-without-org: ${by("insert-without-org").length}`);
  for (const s of ["none", "insert-without-org", "indirect"]) {
    console.log(`\n── ${s} ──`);
    for (const q of by(s)) console.log(`${q.file}:${q.line}  ${q.op} ${q.table}  [${q.keys.join(", ")}]  ${q.text}`);
  }
}
