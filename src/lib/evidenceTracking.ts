/**
 * Database reads behind the control gap report and the auditor export (Task 12). Every query is limited to one
 * organisation. Pure logic lives in controlTracking.ts and controlMapping.ts.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { rowToEvidenceRecord, type EvidenceRecord } from "./evidenceRecord";
import { frameworkCoverageSummary, getFrameworkMapping, type FrameworkCoverageSummary } from "./controlMapping";
import { anchorStatus, isTrustedEvidence, type AnchorStatus } from "./evidenceVerification";
import { buildGapReport, type ControlOwner, type GapReport, type RemediationItem } from "./controlTracking";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;
const PAGE = 1000;
const IN_CHUNK = 200;

type Row = Record<string, unknown>;
const EVIDENCE_COLS = "id, org_id, framework_id, control_id, note, file_url, collected_by, collected_by_email, created_at";

/** Every evidence record of an org + framework (optionally within a period), paged past the 1000-row cap. */
export async function loadFrameworkRecords(db: Db, orgId: string, frameworkId: string, period?: { start: string; end: string }): Promise<EvidenceRecord[]> {
  const out: EvidenceRecord[] = [];
  for (let from = 0; from < 200_000; from += PAGE) {
    let q = db.from("evidence_log").select(EVIDENCE_COLS).eq("org_id", orgId).eq("framework_id", frameworkId);
    if (period) q = q.gte("created_at", period.start).lte("created_at", period.end);
    const { data, error } = await q.order("created_at", { ascending: true }).order("id", { ascending: true }).range(from, from + PAGE - 1) as { data: Row[] | null; error: unknown };
    if (error) throw error;
    for (const row of data ?? []) {
      const rec = rowToEvidenceRecord(row as unknown as Parameters<typeof rowToEvidenceRecord>[0]);
      if (rec) out.push(rec);
    }
    if (!data || data.length < PAGE) break;
  }
  return out;
}

/** For each record, whether the audit log holds the same content hash it was collected with. */
export async function loadAnchors(db: Db, orgId: string, records: readonly EvidenceRecord[]): Promise<Map<string, AnchorStatus>> {
  const byResource = new Map<string, unknown[]>();
  const ids = records.map(r => r.evidence_id);
  for (let i = 0; i < ids.length; i += IN_CHUNK) {
    const { data, error } = await db.from("audit_log").select("resource_id, payload")
      .eq("org_id", orgId).eq("resource_type", "evidence_log").in("resource_id", ids.slice(i, i + IN_CHUNK)) as { data: Array<{ resource_id: string; payload: unknown }> | null; error: unknown };
    if (error) throw error;
    for (const r of data ?? []) byResource.set(r.resource_id, [...(byResource.get(r.resource_id) ?? []), r.payload]);
  }
  return new Map(records.map(r => [r.evidence_id, anchorStatus(byResource.get(r.evidence_id) ?? [], r.content_hash)]));
}

export async function loadControlOwners(db: Db, orgId: string, frameworkId: string): Promise<Array<ControlOwner>> {
  const { data, error } = await db.from("control_owners").select("control_id, owner_email, assigned_at, assigned_by_email")
    .eq("org_id", orgId).eq("framework_id", frameworkId).order("control_id", { ascending: true }) as { data: ControlOwner[] | null; error: unknown };
  if (error) throw error;
  return data ?? [];
}

/** The remediation register for a framework (compliance_exceptions). */
export async function loadRemediations(db: Db, orgId: string, frameworkId: string): Promise<RemediationItem[]> {
  const { data, error } = await db.from("compliance_exceptions").select("id, control_id, title, status, owner_email, due_date, risk_accepted, remediation")
    .eq("org_id", orgId).eq("framework_id", frameworkId).order("created_at", { ascending: true }) as { data: RemediationItem[] | null; error: unknown };
  if (error) throw error;
  return data ?? [];
}

export interface OrgGapReport { framework_id: string; mapping_version: string; scope_disclaimer: string; coverage: FrameworkCoverageSummary; report: GapReport }

/** Coverage counted from hash-verified records only, joined with each control's owner and remediation items. */
export async function buildOrgGapReport(db: Db, orgId: string, frameworkId: string, now = new Date()): Promise<OrgGapReport | null> {
  const fw = getFrameworkMapping(frameworkId);
  if (!fw) return null;
  const records = await loadFrameworkRecords(db, orgId, fw.framework_id);
  const [anchors, owners, remediations] = await Promise.all([loadAnchors(db, orgId, records), loadControlOwners(db, orgId, fw.framework_id), loadRemediations(db, orgId, fw.framework_id)]);
  const coverage = frameworkCoverageSummary(fw.framework_id, records, now, { isTrusted: r => isTrustedEvidence(r, anchors.get(r.evidence_id)) })!;
  return {
    framework_id: fw.framework_id, mapping_version: fw.mapping_version, scope_disclaimer: fw.scope_disclaimer, coverage,
    report: buildGapReport(coverage.controls, owners, remediations, now.toISOString().slice(0, 10)),
  };
}
