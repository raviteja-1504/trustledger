import { NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { cacheGet, cacheSet } from "@/lib/cache";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

interface ServiceCheck {
  status:     "ok" | "degraded" | "unavailable";
  latency_ms: number;
  detail?:    string;
}

async function checkDatabase(): Promise<ServiceCheck> {
  if (!process.env.NEXT_PUBLIC_SUPABASE_URL) {
    return { status: "unavailable", latency_ms: 0, detail: "SUPABASE_URL not configured" };
  }
  const t0 = Date.now();
  try {
    const db = createServiceClient();
    const { error: e2 } = await db.from("organizations").select("id").limit(1);
    return { status: e2 ? "degraded" : "ok", latency_ms: Date.now() - t0 };
  } catch (e) {
    return { status: "unavailable", latency_ms: Date.now() - t0, detail: String(e) };
  }
}

async function checkCache(): Promise<ServiceCheck> {
  const t0 = Date.now();
  try {
    const probe = `__health_${Date.now()}`;
    await cacheSet(probe, "1", 5);
    const val = await cacheGet<string>(probe);
    return {
      status:     val === "1" ? "ok" : "degraded",
      latency_ms: Date.now() - t0,
      detail:     process.env.UPSTASH_REDIS_REST_URL ? "redis" : "in-memory",
    };
  } catch (e) {
    return { status: "degraded", latency_ms: Date.now() - t0, detail: String(e) };
  }
}

export async function GET() {
  const start = Date.now();

  const [db, cache] = await Promise.all([checkDatabase(), checkCache()]);

  const overall =
    db.status === "unavailable" ? "unavailable" :
    db.status === "degraded" || cache.status === "degraded" ? "degraded" : "ok";

  const httpStatus = overall === "unavailable" ? 503 : overall === "degraded" ? 207 : 200;

  return NextResponse.json(
    {
      status:     overall,
      version:    process.env.npm_package_version ?? "0.0.1",
      node:       process.version,
      uptime_s:   Math.floor(process.uptime()),
      timestamp:  new Date().toISOString(),
      latency_ms: Date.now() - start,

      // named aliases used by go-live page
      db:         db.status === "ok" ? "connected" : db.status,

      services: {
        database: db,
        cache,
      },

      env: {
        supabase:  Boolean(process.env.NEXT_PUBLIC_SUPABASE_URL),
        stripe:    Boolean(process.env.STRIPE_SECRET_KEY),
        redis:     Boolean(process.env.UPSTASH_REDIS_REST_URL),
        sentry:    Boolean(process.env.NEXT_PUBLIC_SENTRY_DSN),
        sendgrid:  Boolean(process.env.SENDGRID_API_KEY),
      },
    },
    {
      status: httpStatus,
      headers: {
        "Cache-Control":  "no-store, no-cache",
        "X-Robots-Tag":   "noindex",
        "X-API-Version":  "1.0.0",
      },
    },
  );
}
