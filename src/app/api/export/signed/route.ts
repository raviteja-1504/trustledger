/**
 * Signed Audit Log Export
 * Generates a tamper-proof audit log export with:
 *   - All audit events for the period
 *   - Hash chain verification result
 *   - HMAC-SHA256 signature of the entire export
 *   - Metadata (org, generated_at, signer)
 *
 * The signature allows external auditors to verify the export
 * was not modified after generation.
 *
 * GET /api/export/signed?period_start=...&period_end=...&format=json|csv
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { verifyAuditChain } from "@/lib/audit";
import crypto from "crypto";

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url    = new URL(req.url);
  const start  = url.searchParams.get("period_start") ?? new Date(Date.now() - 90*86400_000).toISOString();
  const end    = url.searchParams.get("period_end")   ?? new Date().toISOString();
  const format = url.searchParams.get("format") ?? "json";

  const db = createServiceClient();

  // Fetch org info
  const { data: org } = await db
    .from("organizations")
    .select("name, slug")
    .eq("id", org_id)
    .single() as { data: { name: string; slug: string } | null };

  // Fetch all audit events in period
  const { data: events } = await db
    .from("audit_log")
    .select("id, event_type, actor_email, resource_type, resource_id, payload, prev_hash, entry_hash, created_at")
    .eq("org_id", org_id)
    .gte("created_at", start)
    .lte("created_at", end)
    .order("id", { ascending: true }) as { data: Array<Record<string, unknown>> | null };

  // Verify hash chain integrity
  const chainResult = await verifyAuditChain(db, org_id);

  const exportedAt = new Date().toISOString();
  const generatorId= `TrustLedger-Export-${exportedAt}`;

  // Sign the entire export content
  const contentToSign = JSON.stringify({
    org_id,
    period_start: start,
    period_end:   end,
    exported_at:  exportedAt,
    event_count:  (events ?? []).length,
    chain_valid:  chainResult.valid,
    events,
  });

  const signingKey = process.env.EXPORT_SIGNING_KEY ?? process.env.CRON_SECRET;
  if (!signingKey) {
    return NextResponse.json({ error: "export_signing_not_configured", detail: "Set EXPORT_SIGNING_KEY or CRON_SECRET" }, { status: 503 });
  }
  const signature  = crypto.createHmac("sha256", signingKey).update(contentToSign).digest("hex");

  if (format === "csv") {
    const header = "id,event_type,actor_email,resource_type,resource_id,entry_hash,created_at";
    const rows   = (events ?? []).map(e =>
      [e.id, e.event_type, e.actor_email??"", e.resource_type??"", e.resource_id??"", e.entry_hash, e.created_at].join(",")
    );
    // Append signature as a comment at the end
    const csv = [
      `# TrustLedger Signed Audit Log Export`,
      `# Org: ${org?.name} (${org?.slug})`,
      `# Period: ${start} — ${end}`,
      `# Generated: ${exportedAt}`,
      `# Chain integrity: ${chainResult.valid ? "VERIFIED" : "BROKEN (tampered)"}`,
      `# HMAC-SHA256 signature: ${signature}`,
      `# Verify: echo -n '${contentToSign.slice(0,100)}...' | openssl dgst -sha256 -hmac YOUR_SIGNING_KEY`,
      "",
      header,
      ...rows,
    ].join("\n");

    return new NextResponse(csv, {
      headers: {
        "Content-Type":        "text/csv",
        "Content-Disposition": `attachment; filename="trustledger-audit-${org?.slug}-${exportedAt.slice(0,10)}.signed.csv"`,
        "X-TrustLedger-Signature": signature,
        "X-TrustLedger-Chain-Valid": String(chainResult.valid),
      },
    });
  }

  // JSON format
  const output = {
    schema:     "https://trustledger.dev/schemas/audit-export/1.0",
    version:    "1.0.0",
    metadata: {
      org_id,
      org_name:      org?.name ?? org_id,
      period_start:  start,
      period_end:    end,
      exported_at:   exportedAt,
      generator:     generatorId,
      event_count:   (events ?? []).length,
    },
    integrity: {
      chain_valid:      chainResult.valid,
      total_records:    chainResult.total,
      broken_at:        chainResult.broken_at ?? null,
      signature_algo:   "HMAC-SHA256",
      signature:        signature,
      verification_note:"Verify by recomputing HMAC-SHA256 of the 'content_hash_input' using your EXPORT_SIGNING_KEY env var.",
    },
    events: events ?? [],
  };

  return new NextResponse(JSON.stringify(output, null, 2), {
    headers: {
      "Content-Type":        "application/json",
      "Content-Disposition": `attachment; filename="trustledger-audit-${org?.slug}-${exportedAt.slice(0,10)}.signed.json"`,
      "X-TrustLedger-Signature":  signature,
      "X-TrustLedger-Chain-Valid":String(chainResult.valid),
    },
  });
}
