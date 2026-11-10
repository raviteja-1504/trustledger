import type { createServiceClient } from "@/lib/supabase";
import { cacheGetMany, cacheSet, TTL } from "@/lib/cache";

type Db = ReturnType<typeof createServiceClient>;

const CONCURRENCY = 8;

/** Source text is immutable per content hash, so it is kept (per organisation) for the same hour a scan's own files are
 *  kept. Wrapped in an object so a file whose text happens to be valid JSON cannot be mistaken for a stored object. */
const contentKey = (orgId: string, hash: string) => `content:v1:${orgId}:${hash}`;

/**
 * Source text for files stored without their own `content` (rows inherited across incremental scans, see
 * api/scan-worker/route.ts), looked up by content_hash from whichever row of the org still holds it.
 *
 * One row per hash: a single `.in("content_hash", hashes)` query returns EVERY row holding that text, and a
 * file carried unchanged through N scans has N such rows -- so the old query transferred the same source N
 * times per request, which was a large share of the project's database egress. Hashes already seen in the last hour
 * come from the cache and cost the database nothing.
 */
export async function fetchContentByHash(db: Db, orgId: string, hashes: readonly string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const unique = [...new Set(hashes)];
  const queue: string[] = [];
  let hits: Array<{ c?: string } | null> = [];
  try { hits = await cacheGetMany<{ c?: string }>(unique.map(h => contentKey(orgId, h))); } catch { hits = []; }
  unique.forEach((h, i) => {
    const c = hits[i]?.c;
    if (typeof c === "string") out.set(h, c); else queue.push(h);
  });
  const worker = async () => {
    for (let h = queue.pop(); h !== undefined; h = queue.pop()) {
      const { data } = await db
        .from("scan_files")
        .select("content")
        .eq("org_id", orgId)
        .eq("content_hash", h)
        .not("content", "is", null)
        .limit(1);
      const content = (data?.[0] as { content?: string | null } | undefined)?.content;
      if (content) {
        out.set(h, content);
        try { await cacheSet(contentKey(orgId, h), { c: content }, TTL.SCAN); } catch { /* the cache is an optimisation */ }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));
  return out;
}
