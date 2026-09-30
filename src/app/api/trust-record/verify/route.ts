/**
 * Trust Record verification
 *
 * POST /api/trust-record/verify { document } → { status, message, summary? }
 *
 * status: valid | tampered | unknown_key | unsigned | malformed | not_configured (see lib/trustRecord.ts).
 * The document is checked against this server's export signing key and never stored.
 */
import { NextRequest, NextResponse } from "next/server";
import { verifyApiKey } from "../../_middleware";
import { checkTrustRecord, CHECK_MESSAGE, type TrustRecord } from "@/lib/trustRecord";

const MAX_BYTES = 5 * 1024 * 1024;

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const raw = await req.text();
  if (raw.length > MAX_BYTES) return NextResponse.json({ error: "too_large", message: "That file is larger than 5 MB, which is bigger than any Trust Record." }, { status: 413 });
  let body: { document?: unknown };
  try { body = JSON.parse(raw); } catch { return NextResponse.json({ status: "malformed", message: CHECK_MESSAGE.malformed }); }

  const status = checkTrustRecord(body.document, process.env.EXPORT_SIGNING_KEY ?? process.env.CRON_SECRET);
  const record = status === "malformed" ? null : (body.document as { record: TrustRecord }).record;
  return NextResponse.json({
    status,
    message: CHECK_MESSAGE[status],
    summary: record ? {
      organization: record.organization, change: record.change, scanned_at: record.scan?.scanned_at, generated_at: record.generated_at,
      verdict: record.verdict, summary: record.summary, engine_version: record.scan?.engine_version,
    } : null,
  });
}
