/**
 * Tenant-isolation exceptions -- every server-side query on a customer-data table (one with org_id) that
 * does NOT filter by org_id itself, each reviewed by hand and tagged with why it is still limited to one
 * organisation. tenantIsolation.test.ts runs scripts/tenantScopeAudit.cjs over src/app/api and src/lib and
 * fails on any unscoped query missing from this list, and on any entry here that no longer matches a query.
 *
 * Adding a query: prefer `.eq("org_id", org_id)` (or org_id in the insert payload) -- it is cheap and makes
 * the query safe on its own. Add an entry here only when the query genuinely cannot or need not carry it.
 * A record id or scan id taken from the request body is NOT safe on its own: either filter by org_id too,
 * or first load that record with an org_id filter and use only the id from the loaded row.
 */

export type TenantScopeReason =
  /** Filtered by a scan/record id that this code path already loaded with an org_id filter (or took from
   *  an org-scoped query's results) -- the id itself proves the org. */
  | "parent-verified"
  /** The caller's own org_members row, looked up by their authenticated user id / confirmed email --
   *  this is how the caller's org is found in the first place. */
  | "own-membership"
  /** An API key looked up by its hash to find which org it belongs to. */
  | "credential-lookup"
  /** api/admin: cross-org platform metrics by design, gated on role platform_admin (which org admins
   *  cannot grant -- see lib/memberRoles.ts). */
  | "platform-admin"
  /** Cron / scan worker / GitHub webhook / SLA monitor: no caller org; acts on records whose org it reads
   *  from the record itself or from the signed job. */
  | "system-job"
  /** Insert/upsert whose payload is a variable that sets org_id. */
  | "payload-has-org"
  /** Found through the SSO provider id in the caller's verified session: the provider IS the org's (ssoMembership.ts). */
  | "sso-identity"
  /** Asks only whether ANOTHER org already holds something globally unique (a verified SSO domain). */
  | "uniqueness-check";

export interface TenantScopeException {
  file: string;
  table: string;
  op: string;
  /** Filter columns, in chain order (as tenantScopeAudit.cjs reports them). */
  keys: string[];
  /** How many identical queries the file has (default 1). */
  count?: number;
  why: TenantScopeReason;
}

export const TENANT_SCOPE_EXCEPTIONS: TenantScopeException[] = [
  { file: "src/app/api/admin/route.ts", table: "org_members", op: "select", keys: ["user_id","role"], why: "own-membership" },
  { file: "src/app/api/admin/route.ts", table: "scans", op: "select", keys: ["created_at"], count: 4, why: "platform-admin" },
  { file: "src/app/api/admin/route.ts", table: "attestations", op: "select", keys: ["created_at"], why: "platform-admin" },
  { file: "src/app/api/admin/route.ts", table: "violations", op: "select", keys: ["status"], why: "platform-admin" },
  { file: "src/app/api/admin/route.ts", table: "org_members", op: "select", keys: [], why: "platform-admin" },
  { file: "src/app/api/api-security/route.ts", table: "scan_files", op: "select", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/auth/2fa/login/route.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/auth/2fa/login/route.ts", table: "org_members", op: "update", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/auth/bootstrap/route.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/auth/bootstrap/route.ts", table: "org_members", op: "update", keys: ["email","user_id"], why: "own-membership" },
  { file: "src/app/api/auth/bootstrap/route.ts", table: "org_members", op: "update", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/auth/callback/route.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/cron/pipeline-health/route.ts", table: "ops_events", op: "delete", keys: ["created_at"], why: "system-job" },
  { file: "src/app/api/cron/webhook-retry/route.ts", table: "webhook_configs", op: "select", keys: ["enabled","last_delivery_status","last_delivery_at"], why: "system-job" },
  { file: "src/app/api/cron/webhook-retry/route.ts", table: "webhook_configs", op: "update", keys: ["id"], why: "system-job" },
  { file: "src/app/api/dashboard/route.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/dependencies/route.ts", table: "scan_files", op: "select", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/export/sarif/route.ts", table: "scan_files", op: "select", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/github-app/comment/route.ts", table: "scan_files", op: "select", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/github-app/comment/route.ts", table: "attestations", op: "select", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/me/route.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/orgs/create/route.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/orgs/reset/route.ts", table: "violations", op: "delete", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/orgs/reset/route.ts", table: "attestations", op: "delete", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/orgs/reset/route.ts", table: "secret_findings", op: "delete", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/orgs/reset/route.ts", table: "scan_files", op: "delete", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/orgs/route.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/scan-worker/route.ts", table: "webhook_deliveries", op: "update", keys: ["id"], why: "system-job" },
  { file: "src/app/api/scan-worker/route.ts", table: "violations", op: "select", keys: ["scan_id","status","risk_score"], count: 2, why: "system-job" },
  { file: "src/app/api/scan-worker/route.ts", table: "scan_files", op: "select", keys: ["scan_id"], count: 2, why: "system-job" },
  { file: "src/app/api/scan-worker/route.ts", table: "scans", op: "update", keys: ["id"], why: "system-job" },
  { file: "src/app/api/scan-worker/route.ts", table: "attestations", op: "select", keys: ["scan_id"], count: 2, why: "system-job" },
  { file: "src/app/api/scan-worker/route.ts", table: "attestations", op: "select", keys: ["scan_id","file_path"], why: "system-job" },
  { file: "src/app/api/scan-worker/route.ts", table: "violations", op: "update", keys: ["scan_id","file_path"], why: "system-job" },
  { file: "src/app/api/scan-worker/route.ts", table: "developer_baselines", op: "upsert", keys: [], why: "payload-has-org" },
  { file: "src/app/api/scans/bulk/route.ts", table: "attestations", op: "select", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/scans/bulk/route.ts", table: "violations", op: "update", keys: ["scan_id","file_path"], why: "parent-verified" },
  { file: "src/app/api/scans/compare/route.ts", table: "scan_files", op: "select", keys: ["scan_id"], count: 2, why: "parent-verified" },
  { file: "src/app/api/scans/route.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/scans/route.ts", table: "attestations", op: "select", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/scans/route.ts", table: "scan_files", op: "select", keys: ["scan_id","risk_score"], why: "parent-verified" },
  { file: "src/app/api/scans/[id]/route.ts", table: "scan_files", op: "select", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/scans/[id]/route.ts", table: "scans", op: "select", keys: ["id"], why: "parent-verified" },
  { file: "src/app/api/scans/[id]/route.ts", table: "attestations", op: "select", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/scans/[id]/trust-record/route.ts", table: "attestations", op: "select", keys: ["scan_id"], why: "parent-verified" },
  { file: "src/app/api/scans/[id]/trust-record/route.ts", table: "violations", op: "select", keys: ["scan_id","status","risk_score"], why: "parent-verified" },
  { file: "src/app/api/scans/[id]/trust-record/route.ts", table: "scans", op: "select", keys: ["id"], why: "parent-verified" },
  { file: "src/app/api/secrets/route.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/sync-check-run/route.ts", table: "scan_files", op: "select", keys: ["scan_id","risk_score"], why: "parent-verified" },
  { file: "src/app/api/sync-check-run/route.ts", table: "attestations", op: "select", keys: ["scan_id","risk_score"], why: "parent-verified" },
  { file: "src/app/api/sync-check-run/route.ts", table: "violations", op: "update", keys: ["scan_id","status","risk_score"], why: "parent-verified" },
  { file: "src/app/api/sync-check-run/route.ts", table: "scans", op: "update", keys: ["id"], why: "parent-verified" },
  { file: "src/app/api/violations/route.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/webhook/github/route.ts", table: "scans", op: "select", keys: ["check_run_id","repo_full_name"], why: "system-job" },
  { file: "src/app/api/_middleware.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/_middleware.ts", table: "org_members", op: "select", keys: ["email","or(`user_id.is.null,user_id.neq.${user.id}`)"], why: "own-membership" },
  { file: "src/app/api/_middleware.ts", table: "org_members", op: "update", keys: ["id"], why: "own-membership" },
  { file: "src/lib/ssoMembership.ts", table: "sso_connections", op: "select", keys: ["provider_id"], why: "sso-identity" },
  { file: "src/lib/ssoMembership.ts", table: "org_members", op: "select", keys: ["user_id"], why: "own-membership" },
  { file: "src/app/api/sso/domains/route.ts", table: "sso_domains", op: "select", keys: ["domain"], why: "uniqueness-check" },
  { file: "src/app/api/_middleware.ts", table: "api_keys", op: "select", keys: ["key_hash"], why: "credential-lookup" },
  { file: "src/app/api/_middleware.ts", table: "api_keys", op: "update", keys: ["key_hash"], why: "credential-lookup" },
  { file: "src/lib/attestation.ts", table: "scans", op: "update", keys: ["id"], why: "parent-verified" },
  { file: "src/lib/attestation.ts", table: "scan_files", op: "select", keys: ["scan_id","file_path"], why: "parent-verified" },
  { file: "src/lib/attestation.ts", table: "attestations", op: "select", keys: ["scan_id","file_path"], why: "parent-verified" },
  { file: "src/lib/attestation.ts", table: "scan_files", op: "update", keys: ["scan_id","file_path"], why: "parent-verified" },
  { file: "src/lib/attestation.ts", table: "violations", op: "select", keys: ["scan_id","status","risk_score"], why: "parent-verified" },
  { file: "src/lib/dashboardAggregate.ts", table: "attestations", op: "select", keys: ["scan_id","risk_score"], count: 2, why: "parent-verified" },
  { file: "src/lib/dashboardAggregate.ts", table: "violations", op: "select", keys: ["scan_id","risk_score"], count: 2, why: "parent-verified" },
  { file: "src/lib/dashboardAggregate.ts", table: "scan_files", op: "select", keys: ["scan_id","risk_score"], why: "parent-verified" },
  { file: "src/lib/opsEvents.ts", table: "ops_events", op: "insert", keys: [], why: "payload-has-org" },
  { file: "src/lib/slaMonitor.ts", table: "violations", op: "select", keys: ["status","sla_deadline"], why: "system-job" },
];
