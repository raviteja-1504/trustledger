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
import { cacheGet, cacheKeys, cacheSet, singleFlight, TTL } from "@/lib/cache";
import { deriveFindings, type ScanForDeps, type DepFinding } from "@/lib/dependencyScan";
import { collectManifestPackages, type ManifestPackage } from "@/lib/manifestPackages";
import { fetchContentByHash } from "@/lib/contentByHash";
import { versionedKey } from "@/lib/orgDataVersion";
import { CAPS } from "@/lib/limits";

interface DependencyResult { findings: DepFinding[]; manifestPackages: ManifestPackage[] }

const PAGE = 1000;          // the project's PostgREST max_rows
const MAX_ROWS = CAPS.bulkRows.value;
const IN_CHUNK = 200;

async function allRows<T>(page: (from: number, to: number) => PromiseLike<{ data: T[] | null; error: unknown }>): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; from < MAX_ROWS; from += PAGE) {
    const { data, error } = await page(from, from + PAGE - 1);
    if (error) throw error;
    out.push(...(data ?? []));
    if (!data || data.length < PAGE) break;
  }
  return out;
}

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  try {
    // The findings change only when a scan lands (or a release changes the package data), so the cached copy records
    // the org's latest scan and the deployment it was computed for, and is reused until either changes -- not
    // recomputed every few minutes. It stays under the plain key, which the scan pipeline deletes once a scan's files
    // are written: a copy taken while a new scan's files were still arriving is dropped then. If the latest scan
    // can't be read, compute without caching rather than risk a stale result.
    const version = await dependenciesVersion(org_id);
    const key = cacheKeys.dependencies(org_id);
    const hit = version == null ? null : await cacheGet<{ version: string; result: DependencyResult }>(key);
    const { findings, manifestPackages } = version == null
      ? await computeFindings(org_id)
      : hit?.version === version
        ? hit.result
        // concurrent misses share one computation
        : await singleFlight(versionedKey(key, version), async () => {
            const result = await computeFindings(org_id);
            await cacheSet(key, { version, result }, TTL.DEPENDENCIES);
            return result;
          });

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

/** What the findings are computed from: the org's newest scan (each repo's latest scan only changes when one lands)
 *  and the deployed code (its package and advisory data). Null when the newest scan can't be read. */
async function dependenciesVersion(orgId: string): Promise<string | null> {
  const { data, error } = await (createServiceClient().from("scans").select("id, created_at").eq("org_id", orgId)
    .order("created_at", { ascending: false }).order("id", { ascending: true }).limit(1).maybeSingle() as unknown as
    Promise<{ data: { id: string; created_at: string } | null; error: unknown }>);
  if (error) return null;
  const release = process.env.VERCEL_GIT_COMMIT_SHA ?? process.env.VERCEL_DEPLOYMENT_ID ?? "local";
  return `${release.slice(0, 12)}|${data ? `${data.created_at}|${data.id}` : "none"}`;
}

async function computeFindings(orgId: string): Promise<DependencyResult> {
  const db = createServiceClient();

  // Latest scan per repo — same "group by repo, keep newest created_at"
  // approach api/dashboard/route.ts uses, kept independent of that route so
  // this endpoint doesn't pull in everything else it aggregates.
  // Both reads are paged: past the 1000-row response cap, a repository whose latest scan is older than the org's
  // newest 1000 scans dropped out, and files beyond the first 1000 (manifests included) were silently skipped.
  type ScanRow = { id: string; repo_full_name: string; pr_number: number; created_at: string };
  const scans = await allRows<ScanRow>((from, to) => db
    .from("scans")
    .select("id, repo_full_name, pr_number, created_at")
    .eq("org_id", orgId)
    .order("created_at", { ascending: false })
    .order("id", { ascending: true })
    .range(from, to) as unknown as PromiseLike<{ data: ScanRow[] | null; error: unknown }>);

  const latestByRepo = new Map<string, { id: string; repo_full_name: string; pr_number: number }>();
  for (const s of scans) {
    if (!latestByRepo.has(s.repo_full_name)) latestByRepo.set(s.repo_full_name, s);
  }
  const latestScans = Array.from(latestByRepo.values());
  if (latestScans.length === 0) return { findings: [], manifestPackages: [] };

  const scanIds = latestScans.map(s => s.id);
  type FileRow = { scan_id: string; file_path: string; content: string | null; content_hash: string | null; ai_percentage: number };
  const files: FileRow[] = [];
  // The listing carries no source: the same text is stored on several rows (a file kept through N scans) and the
  // routes' own cache recomputes after every deploy, so reading `content` here moved it again each time. Source is
  // read once per distinct hash below (fetchContentByHash, cached); only a row with no hash keeps its own copy.
  for (let i = 0; i < scanIds.length; i += IN_CHUNK) {
    const chunk = scanIds.slice(i, i + IN_CHUNK);
    const page = (cols: string, hashless: boolean) => allRows<Omit<FileRow, "content"> & { content?: string | null }>((from, to) => {
      const q = db.from("scan_files").select(cols).eq("org_id", orgId).in("scan_id", chunk);
      return (hashless ? q.is("content_hash", null) : q.not("content_hash", "is", null))
        .order("scan_id", { ascending: true }).order("file_path", { ascending: true }).range(from, to) as unknown as PromiseLike<{ data: (Omit<FileRow, "content"> & { content?: string | null })[] | null; error: unknown }>;
    });
    for (const r of await page("scan_id, file_path, content_hash, ai_percentage", false)) files.push({ ...r, content: null });
    for (const r of await page("scan_id, file_path, content, content_hash, ai_percentage", true)) files.push({ ...r, content: r.content ?? null });
  }

  const allHashes = [...new Set((files ?? []).filter(f => !f.content && f.content_hash).map(f => f.content_hash as string))];
  const contentByHash = allHashes.length > 0 ? await fetchContentByHash(db, orgId, allHashes) : new Map<string, string>();

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
    findings: await deriveFindings(scansForDeps),
    manifestPackages: collectManifestPackages(scansForDeps),
  };
}
