/** GET /benchmarks/report.json -- the published benchmark report, machine-readable (see lib/benchmarkReport.ts). */
import { NextResponse } from "next/server";
import { BENCHMARK_REPORT } from "@/lib/benchmarkReport";

export function GET() {
  return NextResponse.json(BENCHMARK_REPORT, {
    headers: { "Cache-Control": "public, max-age=3600", "Content-Disposition": "inline; filename=\"trustledger-benchmarks.json\"" },
  });
}
