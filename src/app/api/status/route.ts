/**
 * GET /api/status -- public. The state of each component and the operator's open notices, for the /status page and anyone embedding it.
 * A state per component and the notices only; no counts, no organisation, nothing about any customer (lib/platformStatus.ts).
 * Cached for 30 seconds so a flood of visitors during an incident costs the database almost nothing.
 */
import { NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { publicStatus } from "@/lib/platformStatus";

export const dynamic = "force-dynamic";

export async function GET() {
  const headers = { "Cache-Control": "public, s-maxage=30, stale-while-revalidate=30" };
  try {
    return NextResponse.json(await publicStatus(createServiceClient()), { headers });
  } catch {
    // The status endpoint itself cannot reach the database: say so plainly instead of failing.
    return NextResponse.json({
      components: [{ key: "database", name: "Database", state: "down" }], notices: [], checked_at: new Date().toISOString(),
    }, { headers: { "Cache-Control": "no-store" } });
  }
}
