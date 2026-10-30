/**
 * POST /api/demo/scan -- the public live demo's scanner (see lib/demoScan.ts). Public, rate-limited per IP; the
 * request is validated there and only the selected sample's own files are ever scanned.
 */
import { NextResponse } from "next/server";
import { checkRateLimit } from "@/lib/rateLimit";
import { DemoScanBody, scanDemo } from "@/lib/demoScan";

export async function POST(req: Request) {
  // the platform's own client address first: x-forwarded-for's left-most entry is whatever the client wrote
  const ip = req.headers.get("x-real-ip") ?? req.headers.get("x-forwarded-for")?.split(",").pop()?.trim() ?? "unknown";
  const rl = await checkRateLimit(ip, { limit: 20, windowMs: 60_000, prefix: "demo-scan" });
  if (!rl.success) return NextResponse.json({ error: "too_many_requests" }, { status: 429, headers: rl.headers });
  let json: unknown;
  try { json = await req.json(); } catch { return NextResponse.json({ error: "invalid_json" }, { status: 400 }); }
  const parsed = DemoScanBody.safeParse(json);
  if (!parsed.success) return NextResponse.json({ error: "invalid_request" }, { status: 400 });
  const result = await scanDemo(parsed.data);
  if ("error" in result) return NextResponse.json({ error: result.error }, { status: result.status });
  return NextResponse.json(result, { headers: { "Cache-Control": "no-store" } });
}
