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
import { buildApiSecurityReport, type ApiSecurityReport, type ReportScan } from "@/lib/api/apiSecurityReport";

export const maxDuration = 60;

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });
  try {
    const report = await cached(cacheKeys.apiSecurity(org_id), TTL.DEPENDENCIES, () => computeReport(org_id));
    return NextResponse.json(report);
  } catch (err) {
    return safeError(err, { code: "api_security_fetch_failed", message: "We couldn't load the API security report right now. Please try again." });
  }
}

async function computeReport(orgId: string): Promise<ApiSecurityReport> {
  const db = createServiceClient();
  const { data: scans } = await db
    .from("scans")
    .select("id, repo_full_name, created_at")
    .eq("org_id", orgId)
    .order("created_at", { ascending: false });

  const latestByRepo = new Map<string, { id: string; repo_full_name: string }>();
  for (const s of scans ?? []) if (!latestByRepo.has(s.repo_full_name)) latestByRepo.set(s.repo_full_name, s);
  const latest = Array.from(latestByRepo.values());
  if (latest.length === 0) return buildApiSecurityReport([]);

  const { data: files } = await db
    .from("scan_files")
    .select("scan_id, file_path, content, content_hash")
    .in("scan_id", latest.map(s => s.id));

  // Files carried forward unchanged by an incremental scan share another row's content (see api/dependencies).
  const missing = [...new Set((files ?? []).filter(f => !f.content && f.content_hash).map(f => f.content_hash as string))];
  const byHash = missing.length > 0 ? await fetchContentByHash(db, orgId, missing) : new Map<string, string>();

  const filesByScan = new Map<string, ReportScan["files"]>();
  for (const f of files ?? []) {
    const list = filesByScan.get(f.scan_id) ?? [];
    list.push({ file_path: f.file_path, content: f.content ?? (f.content_hash ? byHash.get(f.content_hash) ?? null : null) });
    filesByScan.set(f.scan_id, list);
  }
  return buildApiSecurityReport(latest.map(s => ({ repo: s.repo_full_name, scan_id: s.id, files: filesByScan.get(s.id) ?? [] })));
}
