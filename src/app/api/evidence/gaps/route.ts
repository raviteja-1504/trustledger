/**
 * GET /api/evidence/gaps?framework=soc2   (default soc2; soc2 | iso27001 | pcidss | aigov)
 *
 * Each control of the framework with: its status from evidence that passes verification, the evidence still
 * missing / expired / unverified, who owns it, and the remediation items (compliance_exceptions) that respond to it.
 * `flags` call out what nobody has taken up: no_owner, gap_untracked, remediation_overdue, resolved_but_gap_remains.
 *
 * Complete evidence is not compliance: every control carries sufficient_alone: false and the framework's scope
 * disclaimer comes with the report.
 *
 * Needs can_export_data, like the evidence export it mirrors.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { safeError } from "@/lib/errors";
import { getFrameworkMapping } from "@/lib/controlMapping";
import { buildOrgGapReport } from "@/lib/evidenceTracking";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  // The report carries each control's owner and remediation items, i.e. what the signed evidence package carries,
  // so it needs the same permission (can_export_data).
  const permErr = await requirePermission(auth, "can_export_data");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });
  const { org_id } = auth;

  const framework = req.nextUrl.searchParams.get("framework") ?? "soc2";
  if (!getFrameworkMapping(framework)) {
    return NextResponse.json({ error: "unknown_framework", supported: ["soc2", "iso27001", "pcidss", "aigov"] }, { status: 400 });
  }
  try {
    const out = await buildOrgGapReport(createServiceClient(), org_id, framework);
    return NextResponse.json({
      framework_id: out!.framework_id, mapping_version: out!.mapping_version, scope_disclaimer: out!.scope_disclaimer,
      summary: out!.report.summary, controls: out!.report.controls,
    }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    return safeError(err, { code: "evidence_gaps_failed", message: "We couldn't build the gap report right now. Please try again." });
  }
}
