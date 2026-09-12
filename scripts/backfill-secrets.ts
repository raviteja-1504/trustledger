#!/usr/bin/env tsx
/**
 * Backfill secret_findings from historical scan_files data.
 *
 * secret_findings was only ever written by the manual/API scan endpoint
 * (api/scans/route.ts) -- the GitHub-webhook path (api/scan-worker/route.ts),
 * which is what real production PRs go through, never wrote to that table
 * until this fix. Every historical webhook scan that flagged
 * "hardcoded-secret" still has that fact recorded in scan_files
 * (risk_indicators array always; the detailed per-line `indicators` jsonb
 * column for scans after 2026-06-19) -- it just never made it into
 * secret_findings, so the Secrets page and its badge count only reflects
 * what happens from now on unless this backfill runs once.
 *
 * Usage:
 *   npx tsx scripts/backfill-secrets.ts             # run the backfill
 *   npx tsx scripts/backfill-secrets.ts --dry-run   # show what would be inserted
 */

const DRY_RUN = process.argv.includes("--dry-run");
const PAGE_SIZE = 500;

interface ScanFileRow {
  scan_id: string;
  org_id: string;
  file_path: string;
  risk_score: string;
  risk_indicators: string[];
  indicators: { id: string; label?: string; severity?: string; line?: number }[] | null;
}

function mapSeverity(raw: string | undefined, fallback: string): "CRITICAL" | "HIGH" | "MEDIUM" {
  const s = (raw ?? "").toLowerCase();
  if (s === "critical") return "CRITICAL";
  if (s === "high")     return "HIGH";
  if (s === "medium")   return "MEDIUM";
  return (fallback === "CRITICAL" || fallback === "HIGH") ? (fallback as "CRITICAL" | "HIGH") : "MEDIUM";
}

async function main() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceKey  = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceKey) {
    console.error("❌ Set NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY");
    process.exit(1);
  }

  const { createClient } = await import("@supabase/supabase-js");
  const ws = await import("ws");
  const db = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false },
    realtime: { transport: ws.default as any },
  });

  console.log(`\n🔎 Backfilling secret_findings from historical scan_files${DRY_RUN ? " (dry run)" : ""}\n`);

  // Existing (scan_id, file_path) pairs already covered — a file is only
  // ever inserted as one atomic batch (see api/scans/route.ts and
  // api/scan-worker/route.ts), so if any row exists for it, skip it rather
  // than risk duplicating findings that were already recorded correctly.
  const covered = new Set<string>();
  {
    let from = 0;
    for (;;) {
      const { data, error } = await db
        .from("secret_findings")
        .select("scan_id, file_path")
        .range(from, from + PAGE_SIZE - 1);
      if (error) { console.error("❌ Failed reading secret_findings:", error.message); process.exit(1); }
      if (!data || data.length === 0) break;
      data.forEach(r => covered.add(`${r.scan_id}::${r.file_path}`));
      if (data.length < PAGE_SIZE) break;
      from += PAGE_SIZE;
    }
  }
  console.log(`   ${covered.size} file(s) already have secret_findings rows — will be skipped.`);

  let scanned = 0, toInsert: Record<string, unknown>[] = [], totalInserted = 0;
  let from = 0;

  for (;;) {
    const { data, error } = await db
      .from("scan_files")
      .select("scan_id, org_id, file_path, risk_score, risk_indicators, indicators")
      .contains("risk_indicators", ["hardcoded-secret"])
      .range(from, from + PAGE_SIZE - 1) as { data: ScanFileRow[] | null; error: unknown };
    if (error) { console.error("❌ Failed reading scan_files:", error); process.exit(1); }
    if (!data || data.length === 0) break;

    for (const row of data) {
      scanned++;
      const key = `${row.scan_id}::${row.file_path}`;
      if (covered.has(key)) continue;

      const secretIndicators = (row.indicators ?? []).filter(i => i.id === "hardcoded-secret");
      if (secretIndicators.length > 0) {
        secretIndicators.forEach(ind => {
          toInsert.push({
            org_id: row.org_id, scan_id: row.scan_id, file_path: row.file_path,
            secret_type: "detected",
            severity: mapSeverity(ind.severity, row.risk_score),
            label: ind.label ?? "Hardcoded credential",
            masked_value: "detected",
            line_number: ind.line ?? null,
          });
        });
      } else {
        // Older scan (predates the per-line `indicators` column) — the flag
        // is still real, just without a line number.
        toInsert.push({
          org_id: row.org_id, scan_id: row.scan_id, file_path: row.file_path,
          secret_type: "detected",
          severity: mapSeverity(undefined, row.risk_score),
          label: "Hardcoded credential",
          masked_value: "detected",
          line_number: null,
        });
      }
      covered.add(key); // a file appears at most once per page pass
    }

    if (data.length < PAGE_SIZE) break;
    from += PAGE_SIZE;
  }

  console.log(`   ${scanned} scan_files row(s) flagged "hardcoded-secret"; ${toInsert.length} new finding(s) to insert.\n`);

  if (toInsert.length === 0) {
    console.log("✅ Nothing to backfill.");
    return;
  }

  if (DRY_RUN) {
    console.log("🔍 Dry run — no changes made. Sample of what would be inserted:");
    console.log(toInsert.slice(0, 5));
    return;
  }

  for (let i = 0; i < toInsert.length; i += PAGE_SIZE) {
    const batch = toInsert.slice(i, i + PAGE_SIZE);
    const { error } = await db.from("secret_findings").insert(batch);
    if (error) { console.error(`❌ Insert batch failed at offset ${i}:`, error.message); process.exit(1); }
    totalInserted += batch.length;
    console.log(`   inserted ${totalInserted}/${toInsert.length}...`);
  }

  console.log(`\n✨ Backfill complete — ${totalInserted} secret finding(s) added.`);
}

main().catch(err => {
  console.error("Backfill failed:", err);
  process.exit(1);
});
