import type { createServiceClient } from "@/lib/supabase";

type Db = ReturnType<typeof createServiceClient>;

const CONCURRENCY = 8;

/**
 * Source text for files stored without their own `content` (rows inherited across incremental scans, see
 * api/scan-worker/route.ts), looked up by content_hash from whichever row of the org still holds it.
 *
 * One row per hash: a single `.in("content_hash", hashes)` query returns EVERY row holding that text, and a
 * file carried unchanged through N scans has N such rows -- so the old query transferred the same source N
 * times per request, which was a large share of the project's database egress.
 */
export async function fetchContentByHash(db: Db, orgId: string, hashes: readonly string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const queue = [...new Set(hashes)];
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
      if (content) out.set(h, content);
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));
  return out;
}
