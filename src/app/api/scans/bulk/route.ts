/**
 * Bulk Operations API
 * POST /api/scans/bulk?op=attest   → bulk attest all files in a scan
 * POST /api/scans/bulk?op=resolve  → bulk resolve all violations for a scan
 *
 * Also handles:
 * POST /api/violations/bulk        → bulk resolve/in_review selected violations
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { buildAttestationHash } from "@/lib/scanner";
import { writeAuditLog } from "@/lib/audit";
import { cacheDel, cacheKeys } from "@/lib/cache";
import { fireOrgWebhooks } from "@/lib/outboundWebhook";

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url = new URL(req.url);
  const op  = url.searchParams.get("op");

  const body = await req.json() as {
    scan_id?:        string;
    violation_ids?:  string[];
    reviewer_email?: string;
    reviewer_github?:string;
    status?:         string;
    note?:           string;
  };

  const db  = createServiceClient();
  const now = new Date().toISOString();

  // ── Bulk attest all files in a scan ───────────────────────────────────────
  if (op === "attest") {
    if (!body.scan_id || !body.reviewer_email) {
      return NextResponse.json({ error:"scan_id and reviewer_email required" }, { status:400 });
    }

    // Get all un-attested files in this scan
    const { data: files } = await db
      .from("scan_files")
      .select("file_path, risk_score")
      .eq("scan_id", body.scan_id)
      .eq("org_id", org_id) as { data: Array<{ file_path: string; risk_score: string }> | null };

    if (!files || files.length === 0) {
      return NextResponse.json({ error:"no_files_found" }, { status:404 });
    }

    // Check which are already attested
    const { data: existing } = await db
      .from("attestations")
      .select("file_path")
      .eq("scan_id", body.scan_id) as { data: Array<{ file_path: string }> | null };

    const attestedPaths = new Set((existing ?? []).map(a => a.file_path));
    const toAttest      = files.filter(f => !attestedPaths.has(f.file_path));

    const results: Array<{ file_path: string; attestation_id: string }> = [];

    for (const file of toAttest) {
      const payloadHash = buildAttestationHash(body.scan_id, file.file_path, body.reviewer_email, now);
      const { data: att } = await db
        .from("attestations")
        .insert({
          org_id,
          scan_id:         body.scan_id,
          file_path:       file.file_path,
          risk_score:      file.risk_score,
          reviewer_id:     user_id ?? null,
          reviewer_email:  body.reviewer_email,
          reviewer_github: body.reviewer_github ?? null,
          payload_hash:    payloadHash,
        })
        .select("id")
        .single() as { data: { id: string } | null };

      if (att) {
        results.push({ file_path: file.file_path, attestation_id: att.id });

        // Resolve the violation
        await db.from("violations")
          .update({ status:"resolved", resolved_at: now, resolved_by: user_id ?? null })
          .eq("scan_id", body.scan_id)
          .eq("file_path", file.file_path);
      }
    }

    await writeAuditLog(db, {
      org_id,
      event_type:    "attestation",
      actor_id:      user_id ?? null,
      actor_email:   body.reviewer_email,
      resource_type: "scan",
      resource_id:   body.scan_id,
      payload: { bulk: true, files_attested: results.length },
    });

    // Invalidate dashboard cache
    await cacheDel(cacheKeys.dashboard(org_id, 90));

    await fireOrgWebhooks(db, org_id, {
      type: "attestation.created",
      data: { scan_id: body.scan_id, bulk: true, files_attested: results.length, reviewer: body.reviewer_email },
    });

    return NextResponse.json({ ok: true, attested: results.length, results });
  }

  // ── Bulk resolve violations ────────────────────────────────────────────────
  if (op === "resolve") {
    const ids = body.violation_ids ?? [];
    if (ids.length === 0 && !body.scan_id) {
      return NextResponse.json({ error:"violation_ids or scan_id required" }, { status:400 });
    }

    let query = db.from("violations")
      .update({ status: body.status ?? "resolved", resolved_at: now, resolved_by: user_id ?? null })
      .eq("org_id", org_id);

    if (ids.length > 0) {
      query = query.in("id", ids) as typeof query;
    } else if (body.scan_id) {
      query = query.eq("scan_id", body.scan_id) as typeof query;
    }

    const { count } = await query as { count: number | null };

    await writeAuditLog(db, {
      org_id,
      event_type:    "violation_resolved",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "violations",
      resource_id:   body.scan_id ?? ids.join(","),
      payload: { bulk: true, resolved: count ?? 0, status: body.status ?? "resolved" },
    });

    await cacheDel(cacheKeys.dashboard(org_id, 90));

    return NextResponse.json({ ok: true, resolved: count ?? 0 });
  }

  return NextResponse.json({ error:"unknown_op" }, { status:400 });
}
