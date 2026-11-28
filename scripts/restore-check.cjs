#!/usr/bin/env node
/**
 * Checks a database after a restore (docs/operations/backup-and-restore.md): is the data there, how recent is it, and is the audit trail
 * intact. Read-only. Run it against the RESTORED project, never by mistake against production data you are about to overwrite.
 *
 *   SUPABASE_URL=https://<restored-ref>.supabase.co SUPABASE_SERVICE_ROLE_KEY=... node scripts/restore-check.cjs [--incident-at 2026-11-29T10:00:00Z]
 *
 * Prints, per table, the row count and the newest row's time; per organisation, whether the audit log's links are all in place. The
 * newest audit entry against the time of the incident (--incident-at) is the data lost: the measured recovery point. Exit code 0 when
 * every check passes, 1 when something is missing or the audit links are broken, 2 when it cannot run.
 *
 * Hash CONTENT verification needs the application (Audit page > "Check the whole log", or scripts/verify-audit-bundle.cjs on an export);
 * this script checks what a restore can break at the SQL level: missing tables, empty tables, and entries whose parent is gone.
 */
"use strict";

const TABLES = [
  ["organizations", "created_at"], ["org_members", "created_at"], ["repositories", "created_at"], ["scans", "created_at"],
  ["scan_files", "created_at"], ["violations", "created_at"], ["attestations", "created_at"], ["audit_log", "created_at"],
  ["audit_checkpoints", "created_at"], ["signing_keys", "created_at"], ["api_keys", "created_at"],
];
const PAGE = 1000;

/** Which entries link to a parent that is not in the log (a restore that lost rows), and how many entries share a parent. */
function checkChainLinks(rows) {
  const hashes = new Set(rows.map(r => r.entry_hash));
  const seenParents = new Set();
  const orphans = [], forks = [];
  rows.forEach((r, i) => {
    if (r.prev_hash == null) { if (i > 0) orphans.push(r.id); }
    else if (!hashes.has(r.prev_hash)) orphans.push(r.id);
    if (r.prev_hash != null) { if (seenParents.has(r.prev_hash)) forks.push(r.id); seenParents.add(r.prev_hash); }
  });
  return { orphans, forks };
}

async function allRows(db, table, columns, orderBy) {
  const out = [];
  for (let from = 0; ; from += PAGE) {
    const { data, error } = await db.from(table).select(columns).order(orderBy, { ascending: true }).range(from, from + PAGE - 1);
    if (error) throw new Error(`${table}: ${error.message}`);
    out.push(...(data || []));
    if (!data || data.length < PAGE) break;
  }
  return out;
}

async function main(argv) {
  const url = process.env.SUPABASE_URL, key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const i = argv.indexOf("--incident-at");
  const incidentAt = i >= 0 ? Date.parse(argv[i + 1]) : NaN;
  if (!url || !key) { console.error("Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (of the restored project)."); return 2; }
  let createClient;
  try { ({ createClient } = require("@supabase/supabase-js")); } catch { console.error("Run `npm install` first (needs @supabase/supabase-js)."); return 2; }
  const db = createClient(url, key, { auth: { persistSession: false } });

  let failed = false;
  console.log(`Restore check for ${url}\n`);
  console.log("table".padEnd(22), "rows".padStart(9), "  newest");
  for (const [table, col] of TABLES) {
    const head = await db.from(table).select("id", { count: "exact", head: true });
    if (head.error) { console.log(table.padEnd(22), "MISSING".padStart(9), " ", head.error.message); failed = true; continue; }
    const newest = await db.from(table).select(col).order(col, { ascending: false }).limit(1);
    console.log(table.padEnd(22), String(head.count ?? 0).padStart(9), " ", newest.data && newest.data[0] ? newest.data[0][col] : "-");
  }

  console.log("\nAudit log, per organisation:");
  const orgs = await allRows(db, "organizations", "id", "id");
  let newestAudit = 0;
  for (const org of orgs) {
    const rows = [];
    for (let from = 0; ; from += PAGE) {
      const { data, error } = await db.from("audit_log").select("id, prev_hash, entry_hash, created_at").eq("org_id", org.id).order("id", { ascending: true }).range(from, from + PAGE - 1);
      if (error) { console.log(` ${org.id}  cannot read: ${error.message}`); failed = true; break; }
      rows.push(...(data || []));
      if (!data || data.length < PAGE) break;
    }
    if (rows.length === 0) continue;
    const { orphans, forks } = checkChainLinks(rows);
    const last = Date.parse(rows[rows.length - 1].created_at);
    if (last > newestAudit) newestAudit = last;
    const bad = orphans.length > 0;
    if (bad) failed = true;
    console.log(` ${org.id}  entries ${String(rows.length).padStart(6)}  latest ${rows[rows.length - 1].created_at}  ${bad ? `BROKEN LINKS at ${orphans.slice(0, 5).join(", ")}${orphans.length > 5 ? "…" : ""}` : "links ok"}${forks.length ? `  (${forks.length} fork entries: review them on the Audit page)` : ""}`);
  }

  if (newestAudit) {
    console.log(`\nNewest audit entry in the restored data: ${new Date(newestAudit).toISOString()}`);
    if (!Number.isNaN(incidentAt)) console.log(`Recovery point (data lost before ${new Date(incidentAt).toISOString()}): ${Math.max(0, Math.round((incidentAt - newestAudit) / 60000))} minutes`);
    else console.log("Give --incident-at <time> to see the recovery point in minutes.");
  }
  console.log(failed ? "\nFAILED: see the lines above." : "\nOK: tables present, audit links in place. Now run the Audit page's full check on the restored app.");
  return failed ? 1 : 0;
}

if (require.main === module) main(process.argv.slice(2)).then(code => process.exit(code), e => { console.error(e.message); process.exit(2); });
module.exports = { checkChainLinks };
