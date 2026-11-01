/**
 * GET /api/report/change-register?period_start=…&period_end=…[&format=csv][&sample_size=25&sample_seed=…]
 *
 * The change-management register (lib/changeRegister.ts): every pull request merged in the period, with its approvals
 * relative to the merge, the TrustLedger scan before it, the sign-offs on its HIGH/CRITICAL files, and the
 * exceptions. JSON by default (with the summary, repository coverage and, when asked, a reproducible auditor sample);
 * `format=csv` for the register as a spreadsheet, one row per pull request with each row's SHA-256.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";
import { loadChangeRegister } from "@/lib/changeRegisterLoader";
import { DEFAULT_SAMPLE_SIZE, drawSample, registerToCsv } from "@/lib/changeRegister";
import { safeError } from "@/lib/errors";

const MAX_PERIOD_DAYS = 400;

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_create_reports");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });
  const rl = await checkRateLimit(auth.org_id, RATE_LIMITS.report);
  if (!rl.success) return NextResponse.json({ error: "rate_limited" }, { status: 429, headers: rl.headers });

  const q = req.nextUrl.searchParams;
  const start = q.get("period_start"), end = q.get("period_end");
  const startMs = Date.parse(start ?? ""), endMs = Date.parse(end ?? "");
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs < startMs) {
    return NextResponse.json({ error: "invalid_period", message: "Give period_start and period_end as ISO dates, end after start." }, { status: 400 });
  }
  if ((endMs - startMs) / 86400_000 > MAX_PERIOD_DAYS) {
    return NextResponse.json({ error: "period_too_long", message: `A register covers at most ${MAX_PERIOD_DAYS} days.` }, { status: 400 });
  }

  try {
    const register = await loadChangeRegister(createServiceClient(), auth.org_id, new Date(startMs).toISOString(), new Date(endMs).toISOString());
    if (q.get("format") === "csv") {
      return new NextResponse(registerToCsv(register.rows), {
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": `attachment; filename="trustledger-change-register-${start!.slice(0, 10)}-${end!.slice(0, 10)}.csv"`,
          "Cache-Control": "private, no-store",
        },
      });
    }
    const seed = q.get("sample_seed");
    const size = Number(q.get("sample_size") ?? DEFAULT_SAMPLE_SIZE);
    const sample = seed ? { seed, size: Number.isFinite(size) ? size : DEFAULT_SAMPLE_SIZE, rows: drawSample(register.rows, Number.isFinite(size) ? size : DEFAULT_SAMPLE_SIZE, seed) } : null;
    return NextResponse.json({ ...register, sample, generated_at: new Date().toISOString() }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    return safeError(err, { code: "change_register_failed", message: "We couldn't build the change register right now. Please try again." });
  }
}
