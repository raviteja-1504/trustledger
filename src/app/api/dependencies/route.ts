/**
 * Dependency Findings API
 *
 * GET /api/dependencies → vulnerable/hallucinated/typosquatting packages
 * across every repo's latest scan (real, server-computed — see
 * lib/dependencyScan.ts).
 *
 * There's no dependencies DB table; findings are derived by parsing each
 * repo's latest scanned file content against a known-package database.
 * That used to happen ONLY in the browser (src/app/dependencies/page.tsx),
 * refetching and re-parsing every repo's files on every page load — which
 * is also why the Sidebar badge could only ever show a stale, session-
 * cached number instead of a real one (there was nothing else for it to
 * read). This endpoint runs the same derivation once, server-side, and
 * caches the result so repeated calls (this route, the Sidebar, the page
 * itself) don't re-parse the same content over and over.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { safeError } from "@/lib/errors";
import { cached, cacheKeys, TTL } from "@/lib/cache";
import { deriveFindings, type ScanForDeps, type DepFinding } from "@/lib/dependencyScan";
import { collectManifestPackages, type ManifestPackage } from "@/lib/manifestPackages";

interface DependencyResult { findings: DepFinding[]; manifestPackages: ManifestPackage[] }

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  try {
    const { findings, manifestPackages } = await cached(
      cacheKeys.dependencies(org_id), TTL.DEPENDENCIES, () => computeFindings(org_id),
    );

    const counts = {
      vulnerable:    findings.filter(f => f.type === "vulnerable").length,
      hallucinated:  findings.filter(f => f.type === "hallucinated").length,
      typosquatting: findings.filter(f => f.type === "typosquatting").length,
      critical:      findings.filter(f => f.risk === "CRITICAL").length,
      exploits:      findings.filter(f => f.exploit_public).length,
      license_issues:findings.filter(f => f.license_risk === "block" || f.license_risk === "review").length,
    };

    return NextResponse.json({ findings, counts, manifestPackages });
  } catch (err) {
    return safeError(err, { code: "dependencies_fetch_failed", message: "We couldn't load dependency findings right now. Please try again." });
  }
}

async function computeFindings(orgId: string): Promise<DependencyResult> {
  const db = createServiceClient();

  // Latest scan per repo — same "group by repo, keep newest created_at"
  // approach api/dashboard/route.ts uses, kept independent of that route so
  // this endpoint doesn't pull in everything else it aggregates.
  const { data: scans } = await db
    .from("scans")
    .select("id, repo_full_name, pr_number, created_at")
    .eq("org_id", orgId)
    .order("created_at", { ascending: false });

  const latestByRepo = new Map<string, { id: string; repo_full_name: string; pr_number: number }>();
  for (const s of scans ?? []) {
    if (!latestByRepo.has(s.repo_full_name)) latestByRepo.set(s.repo_full_name, s);
  }
  const latestScans = Array.from(latestByRepo.values());
  if (latestScans.length === 0) return { findings: [], manifestPackages: [] };

  const scanIds = latestScans.map(s => s.id);
  const { data: files } = await db
    .from("scan_files")
    .select("scan_id, file_path, content, content_hash, ai_percentage")
    .in("scan_id", scanIds);

  // Files carried forward unchanged across an incremental scan don't store
  // their own copy of `content` (see api/scan-worker/route.ts) -- backfill
  // from any other row for this org sharing the same content_hash.
  const missingHashes = [...new Set(
    (files ?? []).filter(f => !f.content && f.content_hash).map(f => f.content_hash as string),
  )];
  const contentByHash = new Map<string, string>();
  if (missingHashes.length > 0) {
    const { data: rows } = await db
      .from("scan_files")
      .select("content_hash, content")
      .eq("org_id", orgId)
      .in("content_hash", missingHashes)
      .not("content", "is", null);
    for (const r of rows ?? []) {
      if (!contentByHash.has(r.content_hash) && r.content) contentByHash.set(r.content_hash, r.content);
    }
  }

  const filesByScan = new Map<string, { file_path: string; content: string | null; ai_percentage: number }[]>();
  for (const f of files ?? []) {
    const list = filesByScan.get(f.scan_id) ?? [];
    list.push({
      file_path: f.file_path,
      ai_percentage: f.ai_percentage,
      content: f.content ?? (f.content_hash ? contentByHash.get(f.content_hash) ?? null : null),
    });
    filesByScan.set(f.scan_id, list);
  }

  const scansForDeps: ScanForDeps[] = latestScans.map(s => ({
    repo: s.repo_full_name,
    pr_number: s.pr_number,
    scan_id: s.id,
    files: filesByScan.get(s.id) ?? [],
  }));

  return {
    findings: deriveFindings(scansForDeps),
    manifestPackages: collectManifestPackages(scansForDeps),
  };
}
