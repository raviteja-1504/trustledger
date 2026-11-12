/** GET /benchmarks/vulnbench.json -- TrustLedger's VulnBench 2.0 result with a per-vulnerability proof (see lib/vulnbenchReport.ts). */
import { NextResponse } from "next/server";
import { VULNBENCH } from "@/lib/vulnbenchReport";

export function GET() {
  return NextResponse.json(VULNBENCH, {
    headers: { "Cache-Control": "public, max-age=3600", "Content-Disposition": "inline; filename=\"trustledger-vulnbench-2.0.json\"" },
  });
}
