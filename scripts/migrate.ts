#!/usr/bin/env tsx
/**
 * Database migration runner
 * Runs all pending Supabase migrations in order.
 *
 * Usage:
 *   npx tsx scripts/migrate.ts             # run all pending migrations
 *   npx tsx scripts/migrate.ts --dry-run   # show what would run
 *   npx tsx scripts/migrate.ts --status    # show migration status
 */

import * as fs   from "fs";
import * as path from "path";

const MIGRATIONS_DIR = path.join(process.cwd(), "supabase", "migrations");
const DRY_RUN   = process.argv.includes("--dry-run");
const STATUS    = process.argv.includes("--status");

async function main() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceKey  = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceKey) {
    console.error("❌ Set NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY");
    process.exit(1);
  }

  // List migration files
  const files = fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith(".sql"))
    .sort();

  if (files.length === 0) {
    console.log("No migration files found in supabase/migrations/");
    return;
  }

  console.log(`\n🗄️  TrustLedger Migration Runner`);
  console.log(`   Supabase: ${supabaseUrl}`);
  console.log(`   Found ${files.length} migration files\n`);

  // Dynamic import to avoid bundling issues
  const { createClient } = await import("@supabase/supabase-js");
  const db = createClient(supabaseUrl, serviceKey, { auth: { persistSession: false } });

  // Ensure migrations tracking table exists
  try {
    await db.rpc("exec_sql", { sql:`
      create table if not exists _migrations (
        id         serial primary key,
        filename   text unique not null,
        applied_at timestamptz not null default now()
      );
    ` });
  } catch {
    // RPC might not exist — migrations table may need manual creation
  }

  // Get already-applied migrations
  const { data: applied } = await db
    .from("_migrations")
    .select("filename") as { data: Array<{ filename: string }> | null };
  const appliedSet = new Set((applied ?? []).map(r => r.filename));

  const pending = files.filter(f => !appliedSet.has(f));

  if (STATUS) {
    console.log("Migration Status:");
    files.forEach(f => {
      const status = appliedSet.has(f) ? "✅ applied" : "⏳ pending";
      console.log(`  ${status}  ${f}`);
    });
    return;
  }

  if (pending.length === 0) {
    console.log("✅ All migrations already applied. Database is up to date.");
    return;
  }

  console.log(`📋 ${pending.length} pending migration(s):\n`);
  pending.forEach(f => console.log(`   ⏳  ${f}`));
  console.log("");

  if (DRY_RUN) {
    console.log("🔍 Dry run — no changes made.");
    return;
  }

  // Apply each pending migration
  for (const filename of pending) {
    const filepath = path.join(MIGRATIONS_DIR, filename);
    const sql      = fs.readFileSync(filepath, "utf8");

    process.stdout.write(`   Applying ${filename}... `);

    try {
      // Execute via Supabase SQL (requires service role)
      const res = await fetch(`${supabaseUrl}/rest/v1/rpc/exec_sql`, {
        method:  "POST",
        headers: { "Content-Type":"application/json", "apikey":serviceKey, "Authorization":`Bearer ${serviceKey}` },
        body:    JSON.stringify({ sql }),
      });

      if (!res.ok) {
        // Fallback: log SQL for manual execution
        console.error(`\n⚠️  Could not auto-apply (RPC not available). Run manually in Supabase SQL Editor:`);
        console.log(`\n--- ${filename} ---`);
        console.log(sql.slice(0, 500) + (sql.length > 500 ? "\n..." : ""));
        console.log("---\n");
      } else {
        // Track as applied
        await db.from("_migrations").insert({ filename });
        console.log("✅");
      }
    } catch (err) {
      console.error(`\n❌ Error: ${err}`);
      console.log(`\nRun this migration manually in Supabase SQL Editor.`);
    }
  }

  console.log("\n✨ Migration run complete.");
}

main().catch(err => {
  console.error("Migration failed:", err);
  process.exit(1);
});
