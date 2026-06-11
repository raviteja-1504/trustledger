import { NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";

export const dynamic = "force-dynamic";

interface PoolStats {
  active:   number;
  idle:     number;
  waiting:  number;
  max:      number;
}

async function getPoolStats(db: ReturnType<typeof createServiceClient>): Promise<PoolStats | null> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const result = await (db as any).rpc("get_connection_stats");
    return (result?.data as PoolStats | null) ?? null;
  } catch {
    return null;
  }
}

export async function GET() {
  const start = Date.now();

  let dbOk    = false;
  let pool: PoolStats | null = null;
  let dbDetail: string | undefined;

  if (process.env.NEXT_PUBLIC_SUPABASE_URL) {
    try {
      const db = createServiceClient();
      const { error } = await db.from("organizations").select("id").limit(1);
      dbOk  = !error;
      pool  = await getPoolStats(db);
      if (error) dbDetail = (error as { message?: string }).message;
    } catch (e) {
      dbDetail = String(e);
    }
  } else {
    dbDetail = "SUPABASE_URL not configured (demo mode)";
    dbOk = true;
  }

  const body = {
    status:     dbOk ? "ok" : "degraded",
    version:    process.env.npm_package_version ?? "0.0.1",
    db:         dbOk ? "connected" : "unavailable",
    latency_ms: Date.now() - start,
    timestamp:  new Date().toISOString(),
    ...(dbDetail ? { db_detail: dbDetail } : {}),
    ...(pool      ? { pool }               : {}),
  };

  return NextResponse.json(body, {
    status:  dbOk ? 200 : 503,
    headers: { "Cache-Control": "no-store", "X-Robots-Tag": "noindex" },
  });
}
