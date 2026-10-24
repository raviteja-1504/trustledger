/**
 * Evidence engine: loads an organisation's real records for an audit period and evaluates them against the
 * controls in lib/controlEvidence.ts (which defines what each control's evidence is, and what it does not cover).
 *
 * Shared by GET /api/evidence/collect (reports page, compliance page) and /api/report (the PDF), so every surface
 * shows the same evidence. Next.js route files may only export HTTP handlers, so this lives in a plain lib module.
 * Server-only (service-role client).
 */

import type { SupabaseClient } from "@supabase/supabase-js";
import { createServiceClient } from "@/lib/supabase";
import { verifyAuditChain } from "@/lib/audit";
import { loadShadowAi } from "@/lib/shadowAiStore";
import { allRows } from "@/lib/allRows";
import { builtinPermissions, canAttestAny, permissionsFromRow, type PermissionKey } from "@/lib/permissions";
import {
  FRAMEWORKS, STATUS_LABEL, countStatuses, deriveFacts, evaluateChecks, evaluateFramework, normalizeFrameworkId,
  type CheckResult, type ComplianceFacts, type EvidenceStatus, type FactRows,
} from "@/lib/controlEvidence";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export interface EvidenceItem {
  type:         string;
  description:  string;
  count:        number;
  collected_at: string;
  source:       string;
}

export interface ControlEvidence {
  control_id:   string;
  control_name: string;
  status:       EvidenceStatus;
  status_label: string;
  /** 0-100: the weakest measured check's share. Shown only as a detail, never as "% compliant". */
  score:        number;
  evidence:     EvidenceItem[];
  checks:       CheckResult[];
}

export interface EvidencePackage {
  framework:       string;
  framework_name:  string;
  standard:        string;
  /** What this evidence does and does not cover. Always shown next to the controls. */
  scope:           string;
  period_start:    string;
  period_end:      string;
  generated_at:    string;
  /** @deprecated kept for older clients: mean of the tested controls' scores. */
  overall_score:   number;
  status_counts:   Record<EvidenceStatus, number>;
  controls:        ControlEvidence[];
  audit_integrity: { valid: boolean; total: number };
  facts:           ComplianceFacts;
  summary: {
    total_scans:         number;
    total_attestations:  number;
    open_violations:     number;
    secrets_open:        number;
    secrets_resolved:    number;
    audit_events:        number;
    scan_files_total:    number;
  };
}

const MAX_SCANS = 2000;
const IN_CHUNK = 200;

// Each chunk is paged too (lib/allRows.ts): one chunk of scans can hold more than the 1000 rows a request returns.
async function inChunks<T>(ids: string[], fetch: (chunk: string[], from: number, to: number) => PromiseLike<{ data: T[] | null }>): Promise<T[]> {
  const out: T[] = [];
  for (let i = 0; i < ids.length; i += IN_CHUNK) out.push(...(await allRows<T>((from, to) => fetch(ids.slice(i, i + IN_CHUNK), from, to))).data);
  return out;
}

/** Who can sign off changes: built-in role, replaced by a custom role when one is assigned (lib/permissions.ts). */
async function loadMembers(db: Db, orgId: string): Promise<Array<{ can_attest: boolean }>> {
  let { data, error } = await db.from("org_members").select("role, custom_role_id").eq("org_id", orgId) as
    { data: Array<{ role: string; custom_role_id?: string | null }> | null; error: { code?: string } | null };
  if (error) ({ data } = await db.from("org_members").select("role").eq("org_id", orgId) as { data: Array<{ role: string }> | null; error: unknown });
  const members = data ?? [];
  const roleIds = [...new Set(members.map(m => m.custom_role_id).filter((x): x is string => !!x))];
  const { data: roles } = roleIds.length
    ? await db.from("custom_roles").select("*").eq("org_id", orgId).in("id", roleIds) as { data: Array<{ id: string } & Partial<Record<PermissionKey, unknown>>> | null }
    : { data: [] };
  const byId = new Map((roles ?? []).map(r => [r.id, r]));
  return members.map(m => {
    const custom = m.custom_role_id ? byId.get(m.custom_role_id) : undefined;
    // An assigned custom role that can't be read grants nothing (same rule as permissionResolver).
    const perms = m.custom_role_id ? (custom ? permissionsFromRow(custom) : null) : builtinPermissions(m.role);
    return { can_attest: !!perms && canAttestAny(perms) };
  });
}

export async function loadFactRows(db: Db, orgId: string, periodStart: string, periodEnd: string, now = new Date()): Promise<FactRows> {
  const [{ data: repoRows }, { data: scanRows }] = await Promise.all([
    db.from("repositories").select("repo_full_name").eq("org_id", orgId).eq("is_active", true) as unknown as Promise<{ data: Array<{ repo_full_name: string }> | null }>,
    db.from("scans").select("id, repo_full_name, pr_number, pr_author, created_at").eq("org_id", orgId)
      .gte("created_at", periodStart).lte("created_at", periodEnd)
      .order("created_at", { ascending: false }).limit(MAX_SCANS) as unknown as Promise<{ data: Array<{ id: string; repo_full_name: string; pr_number: number | null; pr_author: string | null; created_at: string }> | null }>,
  ]);
  const scans = (scanRows ?? []).map(s => ({ id: s.id, repo: s.repo_full_name, pr_number: s.pr_number, pr_author: s.pr_author, created_at: s.created_at }));
  const ids = scans.map(s => s.id);
  const days = Math.max(1, Math.ceil((now.getTime() - new Date(periodStart).getTime()) / 86400_000));

  const [riskyFiles, attestations, violations, openSecrets, openCritical, resolvedSecrets, filesAnalyzed, audit, members, ai] = await Promise.all([
    inChunks(ids, (c, f, t) => db.from("scan_files").select("scan_id, file_path, ai_percentage").eq("org_id", orgId).in("scan_id", c).in("risk_score", ["CRITICAL", "HIGH"]).order("scan_id", { ascending: true }).order("file_path", { ascending: true }).order("id", { ascending: true }).range(f, t) as unknown as PromiseLike<{ data: FactRows["riskyFiles"][number][] | null }>),
    inChunks(ids, (c, f, t) => db.from("attestations").select("scan_id, file_path, reviewer_github").eq("org_id", orgId).in("scan_id", c).order("scan_id", { ascending: true }).order("file_path", { ascending: true }).order("id", { ascending: true }).range(f, t) as unknown as PromiseLike<{ data: FactRows["attestations"][number][] | null }>),
    inChunks(ids, (c, f, t) => db.from("violations").select("scan_id, file_path, status, sla_deadline").eq("org_id", orgId).in("scan_id", c).order("scan_id", { ascending: true }).order("file_path", { ascending: true }).order("id", { ascending: true }).range(f, t) as unknown as PromiseLike<{ data: FactRows["violations"][number][] | null }>),
    db.from("secret_findings").select("id", { count: "exact", head: true }).eq("org_id", orgId).eq("status", "open"),
    db.from("secret_findings").select("id", { count: "exact", head: true }).eq("org_id", orgId).eq("status", "open").eq("severity", "CRITICAL"),
    db.from("secret_findings").select("id", { count: "exact", head: true }).eq("org_id", orgId).eq("status", "resolved").gte("resolved_at", periodStart).lte("resolved_at", periodEnd),
    db.from("scan_files").select("id", { count: "exact", head: true }).eq("org_id", orgId).gte("created_at", periodStart).lte("created_at", periodEnd),
    verifyAuditChain(db, orgId),
    loadMembers(db, orgId),
    loadShadowAi(db, orgId, days).then(r => r.summary, () => null),
  ]);

  return {
    period_start: periodStart, period_end: periodEnd, now: now.toISOString(),
    activeRepos: (repoRows ?? []).map(r => r.repo_full_name),
    scans, riskyFiles, attestations, violations,
    secrets: { open: openSecrets.count ?? 0, open_critical: openCritical.count ?? 0, resolved_in_period: resolvedSecrets.count ?? 0 },
    audit, members,
    ai: ai ? { policy_configured: ai.policy_configured, compliance: ai.compliance, open_violations: ai.open_violations } : null,
    files_analyzed: filesAnalyzed.count ?? 0,
  };
}

/** Package for one framework from already-derived facts (pure; tested directly). */
export function buildPackage(rawFramework: string, facts: ComplianceFacts, rows: Pick<FactRows, "scans" | "attestations" | "audit">, generatedAt: string): EvidencePackage {
  const fw = FRAMEWORKS.find(f => f.id === normalizeFrameworkId(rawFramework))!;
  const controls = evaluateFramework(fw, evaluateChecks(facts));
  const tested = controls.filter(c => c.status !== "not_tested");
  return {
    framework: fw.id, framework_name: fw.name, standard: fw.standard, scope: fw.scope,
    period_start: facts.period_start, period_end: facts.period_end, generated_at: generatedAt,
    overall_score: tested.length ? Math.round(tested.reduce((a, c) => a + c.score, 0) / tested.length) : 0,
    status_counts: countStatuses(controls),
    controls: controls.map(c => ({
      control_id: c.control_id, control_name: c.control_name, status: c.status, status_label: STATUS_LABEL[c.status], score: c.score,
      checks: c.checks,
      evidence: c.checks.map(k => ({ type: k.key, description: `${k.label}: ${k.summary}`, count: k.score, collected_at: generatedAt, source: "TrustLedger records" })),
    })),
    audit_integrity: { valid: rows.audit.valid, total: rows.audit.total },
    facts,
    summary: {
      total_scans: rows.scans.length,
      total_attestations: rows.attestations.length,
      open_violations: facts.findings.open,
      secrets_open: facts.secrets.open,
      secrets_resolved: facts.secrets.resolved_in_period,
      audit_events: facts.audit.total,
      scan_files_total: facts.ai.files_analyzed,
    },
  };
}

/** Every framework at a glance (dashboard card): statuses per control and the distinct gaps, from one load. */
export interface EvidenceOverview {
  period_start: string;
  period_end:   string;
  generated_at: string;
  frameworks: Array<{
    id: string; name: string; short: string;
    status_counts: Record<EvidenceStatus, number>;
    controls: Array<{ control_id: string; control_name: string; status: EvidenceStatus }>;
  }>;
  /** Checks with gaps, once each (a check feeds several frameworks). Worst first. */
  gaps: Array<{ key: string; label: string; status: EvidenceStatus; gaps: string[] }>;
}

export function buildOverview(facts: ComplianceFacts, opts: { pciApplicable: boolean }, generatedAt: string): EvidenceOverview {
  const checks = evaluateChecks(facts);
  const rank: Record<EvidenceStatus, number> = { fail: 0, partial: 1, not_tested: 2, pass: 3 };
  return {
    period_start: facts.period_start, period_end: facts.period_end, generated_at: generatedAt,
    frameworks: FRAMEWORKS.filter(f => f.id !== "pcidss" || opts.pciApplicable).map(f => {
      const controls = evaluateFramework(f, checks);
      return {
        id: f.id, name: f.name, short: f.short, status_counts: countStatuses(controls),
        controls: controls.map(c => ({ control_id: c.control_id, control_name: c.control_name, status: c.status })),
      };
    }),
    gaps: Object.values(checks).filter(c => c.gaps.length > 0)
      .sort((a, b) => rank[a.status] - rank[b.status])
      .map(c => ({ key: c.key, label: c.label, status: c.status, gaps: c.gaps })),
  };
}

export async function collectEvidenceOverview(org_id: string, periodStart: string, periodEnd: string): Promise<EvidenceOverview> {
  const now = new Date();
  const db = createServiceClient();
  const [rows, { data: org }] = await Promise.all([
    loadFactRows(db, org_id, periodStart, periodEnd, now),
    db.from("organizations").select("pci_applicable").eq("id", org_id).maybeSingle() as unknown as Promise<{ data: { pci_applicable?: boolean } | null }>,
  ]);
  return buildOverview(deriveFacts(rows), { pciApplicable: !!org?.pci_applicable }, now.toISOString());
}

export async function collectEvidence(org_id: string, rawFramework: string, periodStart: string, periodEnd: string): Promise<EvidencePackage> {
  const now = new Date();
  const rows = await loadFactRows(createServiceClient(), org_id, periodStart, periodEnd, now);
  return buildPackage(rawFramework, deriveFacts(rows), rows, now.toISOString());
}
