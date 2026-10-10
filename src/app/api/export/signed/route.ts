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
import { verifyApiKey, requirePermission } from "../../_middleware";
import { verifyAuditChain, writeAuditLog } from "@/lib/audit";
import { signEd25519 } from "@/lib/exportSigning";
import crypto from "crypto";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  // A bulk export of the whole audit log -- the same permission as every other export (api/export?type=audit).
  const roleErr = await requirePermission(auth, "can_export_data");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });
  const { org_id } = auth;

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

  // Public-key (Ed25519) when EXPORT_SIGNING_PRIVATE_KEY is set, so auditors verify independently; otherwise
  // the legacy HMAC scheme over the same bytes.
  const hmacKey = process.env.EXPORT_SIGNING_KEY ?? process.env.CRON_SECRET;
  const ed = signEd25519(contentToSign, "the JSON object of {org_id, period_start, period_end, exported_at, event_count, chain_valid, events}");
  if (!ed && !hmacKey) {
    return NextResponse.json({ error: "export_signing_not_configured", detail: "Set EXPORT_SIGNING_PRIVATE_KEY (preferred) or EXPORT_SIGNING_KEY" }, { status: 503 });
  }
  const signatureAlgo = ed ? ed.algorithm : "HMAC-SHA256";
  const signature     = ed ? ed.value : crypto.createHmac("sha256", hmacKey!).update(contentToSign).digest("hex");

  // Logged after the export content is fixed, so this entry is never part of the export it describes.
  await writeAuditLog(db, {
    org_id, event_type: "data_exported", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "export", resource_id: "audit_signed",
    payload: { export_type: "audit_signed", format: format === "csv" ? "csv" : "json", rows: (events ?? []).length, period_start: start, period_end: end },
  });

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
      `# Signature (${signatureAlgo}): ${signature}`,
      ...(ed
        ? [`# Public key id: ${ed.key_id}`, `# Public key: ${new URL("/.well-known/trustledger-export-signing-key", req.url).toString()}`]
        : [`# Verify: recompute HMAC-SHA256 of the signed content with your EXPORT_SIGNING_KEY`]),
      "",
      header,
      ...rows,
    ].join("\n");

    return new NextResponse(csv, {
      headers: {
        "Content-Type":        "text/csv",
        "Content-Disposition": `attachment; filename="trustledger-audit-${org?.slug}-${exportedAt.slice(0,10)}.signed.csv"`,
        "X-TrustLedger-Signature": signature,
        "X-TrustLedger-Signature-Algo": signatureAlgo,
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
      signature_algo:   signatureAlgo,
      signature:        signature,
      signed_content:   ed?.signed_content ?? "the JSON object of {org_id, period_start, period_end, exported_at, event_count, chain_valid, events}",
      ...(ed
        ? { key_id: ed.key_id, public_key_pem: ed.public_key_pem, public_key_url: new URL("/.well-known/trustledger-export-signing-key", req.url).toString(), verification_note: "Ed25519-verify base64(signature) over the signed content with the public key above; confirm key_id matches public_key_url." }
        : { verification_note: "Verify by recomputing HMAC-SHA256 of the signed content using your EXPORT_SIGNING_KEY env var." }),
    },
    events: events ?? [],
  };

  return new NextResponse(JSON.stringify(output, null, 2), {
    headers: {
      "Content-Type":        "application/json",
      "Content-Disposition": `attachment; filename="trustledger-audit-${org?.slug}-${exportedAt.slice(0,10)}.signed.json"`,
      "X-TrustLedger-Signature":  signature,
      "X-TrustLedger-Signature-Algo": signatureAlgo,
      "X-TrustLedger-Chain-Valid":String(chainResult.valid),
    },
  });
}
