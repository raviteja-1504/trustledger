/**
 * Signed Audit Log Export
 * Generates a tamper-evident audit log export with:
 *   - All audit events for the period
 *   - Hash chain verification result
 *   - A signature of the whole export (Ed25519 when EXPORT_SIGNING_PRIVATE_KEY is set, else HMAC-SHA256)
 *   - Metadata (org, generated_at, signer)
 *
 * The signature allows external auditors to verify the export was not modified after generation:
 *   scripts/verify-audit-export.cjs <file.json|file.csv> [trusted-public-key.pem]
 *
 * Complete or nothing: every event in the period is read, page by page past the database's 1000-row cap, and the number
 * read is checked against the database's own count. If the log can't be read in full, or the chain can't be checked, the
 * export fails (503) instead of signing a partial list as if it were the whole.
 *
 * The CSV signs its own bytes: everything above the "# --- signature ---" line, which holds every column the audit hash is
 * computed from (payload, prev_hash and entry_hash included), so an auditor can re-derive each entry's hash and the chain
 * links from the CSV alone.
 *
 * GET /api/export/signed?period_start=...&period_end=...&format=json|csv
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { verifyAuditChain, writeAuditLog, canonicalJson } from "@/lib/audit";
import { signEd25519, type Ed25519Signature } from "@/lib/exportSigning";
import { allRows } from "@/lib/allRows";
import { csvLine } from "@/lib/csv";
import crypto from "crypto";

const EVENT_COLUMNS = "id, event_type, actor_email, actor_id, resource_type, resource_id, payload, prev_hash, entry_hash, created_at";
// Not exported: a Next.js route file may only export its HTTP handlers and route config, or the build fails.
const CSV_SIGNATURE_MARKER = "# --- signature ---";
const CSV_FORMAT = "trustledger-audit-csv/2";   // /2 adds the actor_id column (hash v2 covers it)
const CSV_HEADER = ["id", "event_type", "actor_email", "resource_type", "resource_id", "payload", "prev_hash", "entry_hash", "created_at", "actor_id"] as const;

/** A single line of text for a comment: no line breaks or control characters, so a name can't start a new line. */
const CONTROL_CHARS = new RegExp("[" + String.fromCharCode(0) + "-" + String.fromCharCode(31, 127, 0x2028, 0x2029) + "]+", "g");
const oneLine = (s: unknown) => String(s ?? "").replace(CONTROL_CHARS, " ").trim();

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

  const incomplete = (reason: string) => NextResponse.json({
    error: "export_incomplete", reason,
    message: "The audit log could not be read in full, so nothing was signed. Please try again; an export is never produced from part of the log.",
  }, { status: 503 });

  // Every audit event in the period, paged (the database returns at most 1000 rows per request) ...
  const periodQuery = () => db.from("audit_log").select(EVENT_COLUMNS).eq("org_id", org_id).gte("created_at", start).lte("created_at", end).order("id", { ascending: true });
  const { data: events, error: eventsError } = await allRows<Record<string, unknown>>((from, to) => periodQuery().range(from, to));
  // ... checked against the database's own count, which catches a page size the server silently shortens
  const { count, error: countError } = await db.from("audit_log").select("id", { count: "exact", head: true }).eq("org_id", org_id).gte("created_at", start).lte("created_at", end);
  if (eventsError || countError || count == null) return incomplete("read_failed");
  if (events.length !== count) return incomplete("row_count_mismatch");

  // Verify hash chain integrity (the whole chain). A chain that could not be read says nothing either way.
  const chainResult = await verifyAuditChain(db, org_id);
  if (chainResult.status === "INCOMPLETE") return incomplete("chain_unreadable");

  const exportedAt = new Date().toISOString();
  const generatorId= `TrustLedger-Export-${exportedAt}`;

  // Public-key (Ed25519) when EXPORT_SIGNING_PRIVATE_KEY is set, so auditors verify independently; otherwise
  // the legacy HMAC scheme over the same bytes.
  const hmacKey = process.env.EXPORT_SIGNING_KEY ?? process.env.CRON_SECRET;
  const sign = (content: string, note: string): { algo: string; value: string; ed: Ed25519Signature | null } | null => {
    const ed = signEd25519(content, note);
    if (ed) return { algo: ed.algorithm, value: ed.value, ed };
    if (!hmacKey) return null;
    return { algo: "HMAC-SHA256", value: crypto.createHmac("sha256", hmacKey).update(content).digest("hex"), ed: null };
  };

  const eventList = events;
  // Sign the entire export content
  const contentToSign = JSON.stringify({
    org_id,
    period_start: start,
    period_end:   end,
    exported_at:  exportedAt,
    event_count:  eventList.length,
    chain_valid:  chainResult.valid,
    events:       eventList,
  });
  const signed = sign(contentToSign, "the JSON object of {org_id, period_start, period_end, exported_at, event_count, chain_valid, events}");
  if (!signed) {
    return NextResponse.json({ error: "export_signing_not_configured", detail: "Set EXPORT_SIGNING_PRIVATE_KEY (preferred) or EXPORT_SIGNING_KEY" }, { status: 503 });
  }
  const keyUrl = new URL("/.well-known/trustledger-export-signing-key", req.url).toString();

  // Logged after the export content is fixed, so this entry is never part of the export it describes.
  await writeAuditLog(db, {
    org_id, event_type: "data_exported", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "export", resource_id: "audit_signed",
    payload: { export_type: "audit_signed", format: format === "csv" ? "csv" : "json", rows: eventList.length, period_start: start, period_end: end },
  });

  if (format === "csv") {
    // Every column the audit hash is computed from, so each entry can be re-hashed from this file. created_at in the one
    // spelling the hash was computed over (ISO, UTC); payload as canonical JSON (keys sorted, no whitespace).
    const rows = eventList.map(e => csvLine([
      e.id, e.event_type, e.actor_email, e.resource_type, e.resource_id,
      canonicalJson(e.payload ?? {}), e.prev_hash, e.entry_hash,
      Number.isNaN(Date.parse(String(e.created_at))) ? e.created_at : new Date(String(e.created_at)).toISOString(),
      e.actor_id,
    ]));
    // What is signed: everything up to the signature marker, exactly as written (UTF-8, LF line endings).
    const body = [
      `# TrustLedger Signed Audit Log Export`,
      `# Format: ${CSV_FORMAT}`,
      `# Org: ${oneLine(org?.name)} (${oneLine(org?.slug)})`,
      `# Org id: ${org_id}`,
      `# Period: ${start} — ${end}`,
      `# Generated: ${exportedAt}`,
      `# Events: ${eventList.length}`,
      `# Chain integrity: ${chainResult.status === "VALID" ? "VERIFIED" : chainResult.status === "FORK_DETECTED" ? `NOT CLEAN (forked: ${chainResult.concurrent} entr${chainResult.concurrent === 1 ? "y shares" : "ies share"} a parent with an earlier one)` : "BROKEN (tampered)"}`,
      "",
      csvLine(CSV_HEADER),
      ...rows,
    ].join("\n") + "\n";
    const csvSigned = sign(body, `the bytes of this file above the "${CSV_SIGNATURE_MARKER}" line (UTF-8, LF line endings)`)!;
    const spkiBase64 = csvSigned.ed ? csvSigned.ed.public_key_pem.replace(/-----(?:BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "") : null;
    const footer = [
      CSV_SIGNATURE_MARKER,
      `# Signature (${csvSigned.algo}): ${csvSigned.value}`,
      `# Signed: every byte above the "${CSV_SIGNATURE_MARKER}" line (UTF-8, LF line endings)`,
      ...(csvSigned.ed
        ? [`# Public key id: ${csvSigned.ed.key_id}`, `# Public key (SPKI, base64): ${spkiBase64}`, `# Public key: ${keyUrl}`,
           `# Verify: node scripts/verify-audit-export.cjs <this file> <trusted-public-key.pem>`]
        : [`# Verify: recompute HMAC-SHA256 of the signed bytes with your EXPORT_SIGNING_KEY`]),
    ].join("\n") + "\n";

    return new NextResponse(body + footer, {
      headers: {
        "Content-Type":        "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="trustledger-audit-${org?.slug}-${exportedAt.slice(0,10)}.signed.csv"`,
        "X-TrustLedger-Signature": csvSigned.value,
        "X-TrustLedger-Signature-Algo": csvSigned.algo,
        "X-TrustLedger-Chain-Valid": String(chainResult.valid),
      },
    });
  }

  // JSON format
  const { algo: signatureAlgo, value: signature, ed } = signed;
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
      event_count:   eventList.length,
    },
    integrity: {
      chain_valid:      chainResult.valid,
      total_records:    chainResult.total,
      broken_at:        chainResult.broken_at ?? null,
      signature_algo:   signatureAlgo,
      signature:        signature,
      signed_content:   ed?.signed_content ?? "the JSON object of {org_id, period_start, period_end, exported_at, event_count, chain_valid, events}",
      ...(ed
        ? { key_id: ed.key_id, public_key_pem: ed.public_key_pem, public_key_url: keyUrl, verification_note: "Ed25519-verify base64(signature) over the signed content with the public key above; confirm key_id matches public_key_url. Or run scripts/verify-audit-export.cjs." }
        : { verification_note: "Verify by recomputing HMAC-SHA256 of the signed content using your EXPORT_SIGNING_KEY env var." }),
    },
    events: eventList,
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
