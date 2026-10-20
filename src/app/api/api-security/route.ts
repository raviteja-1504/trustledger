/**
 * API Security API
 *
 * GET /api/api-security → the endpoint inventory (from code and OpenAPI specs) and API findings across every
 * repo's latest scan -- see lib/api/apiSecurityReport.ts. Derived from scanned file content, like
 * /api/dependencies, and cached the same way.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { safeError } from "@/lib/errors";
import { cached, cacheKeys, TTL } from "@/lib/cache";
import { fetchContentByHash } from "@/lib/contentByHash";
import { orgDataVersion, versionedKey } from "@/lib/orgDataVersion";
import { buildApiSecurityReport, type ApiSecurityReport, type ReportScan } from "@/lib/api/apiSecurityReport";

export const maxDuration = 60;

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });
  try {
    // Keyed by the org's data version, so a new scan shows up at once instead of after the cache expires.
    const version = await orgDataVersion(createServiceClient(), org_id);
    const report = version == null
      ? await computeReport(org_id)
      : await cached(versionedKey(cacheKeys.apiSecurity(org_id), version), TTL.DEPENDENCIES, () => computeReport(org_id));
    return NextResponse.json(report, { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    return safeError(err, { code: "api_security_fetch_failed", message: "We couldn't load the API security report right now. Please try again." });
  }
}

const PAGE = 1000;          // the project's PostgREST max_rows
const MAX_ROWS = 50_000;
const IN_CHUNK = 200;
type Page<T> = PromiseLike<{ data: T[] | null; error: unknown }>;

async function all<T>(page: (from: number, to: number) => Page<T>): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; from < MAX_ROWS; from += PAGE) {
    const { data, error } = await page(from, from + PAGE - 1);
    if (error) throw error;
    out.push(...(data ?? []));
    if (!data || data.length < PAGE) break;
  }
  return out;
}

async function computeReport(orgId: string): Promise<ApiSecurityReport> {
  const db = createServiceClient();
  // Paged: past the 1000-row cap, a repository whose latest scan is older than the org's newest 1000 scans dropped
  // out, and files beyond the first 1000 were never read. Only connected (active) repositories count.
  const { data: active } = await db.from("repositories").select("repo_full_name").eq("org_id", orgId).eq("is_active", true) as { data: { repo_full_name: string }[] | null };
  const activeRepos = new Set((active ?? []).map(r => r.repo_full_name));
  type ScanRow = { id: string; repo_full_name: string; created_at: string };
  const scans = await all<ScanRow>((f, t) => db.from("scans").select("id, repo_full_name, created_at").eq("org_id", orgId)
    .order("created_at", { ascending: false }).order("id", { ascending: true }).range(f, t) as unknown as Page<ScanRow>);

  const latestByRepo = new Map<string, ScanRow>();
  for (const s of scans) if (activeRepos.has(s.repo_full_name) && !latestByRepo.has(s.repo_full_name)) latestByRepo.set(s.repo_full_name, s);
  const latest = Array.from(latestByRepo.values());
  if (latest.length === 0) return buildApiSecurityReport([]);

  type FileRow = { scan_id: string; file_path: string; content: string | null; content_hash: string | null };
  const ids = latest.map(s => s.id);
  const files: FileRow[] = [];
  for (let i = 0; i < ids.length; i += IN_CHUNK) {
    const chunk = ids.slice(i, i + IN_CHUNK);
    files.push(...await all<FileRow>((f, t) => db.from("scan_files").select("scan_id, file_path, content, content_hash")
      .eq("org_id", orgId).in("scan_id", chunk).order("scan_id", { ascending: true }).order("file_path", { ascending: true }).range(f, t) as unknown as Page<FileRow>));
  }

  // Files carried forward unchanged by an incremental scan share another row's content (see api/dependencies).
  const missing = [...new Set(files.filter(f => !f.content && f.content_hash).map(f => f.content_hash as string))];
  const byHash = missing.length > 0 ? await fetchContentByHash(db, orgId, missing) : new Map<string, string>();

  const filesByScan = new Map<string, ReportScan["files"]>();
  for (const f of files) {
    const list = filesByScan.get(f.scan_id) ?? [];
    list.push({ file_path: f.file_path, content: f.content ?? (f.content_hash ? byHash.get(f.content_hash) ?? null : null) });
    filesByScan.set(f.scan_id, list);
  }
  return buildApiSecurityReport(latest.map(s => ({ repo: s.repo_full_name, scan_id: s.id, scanned_at: s.created_at, files: filesByScan.get(s.id) ?? [] })));
}
