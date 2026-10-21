/**
 * How each audit log entry reads on the Audit Trail page: its own label (no more folding "incident created" into
 * "merge blocked" or "signed in" into "user added"), a category, a severity, a one-line title, the facts from its
 * payload, and where to go to see the thing it's about. Pure, client-safe. Unknown event types still render, from
 * their name and payload.
 */

export type AuditCategory = "scans" | "reviews" | "findings" | "incidents" | "access" | "settings" | "integrations" | "evidence";
export type AuditSeverity = "info" | "warning" | "critical";

export interface AuditRow {
  id: number;
  event_type: string;
  actor_email: string | null;
  resource_type?: string | null;
  resource_id?: string | null;
  payload: Record<string, unknown> | null;
  prev_hash?: string | null;
  entry_hash?: string | null;
  created_at: string;
}

export interface AuditView {
  id: number;
  type: string;
  label: string;
  category: AuditCategory;
  severity: AuditSeverity;
  title: string;
  facts: Array<[string, string]>;
  actor: string | null;
  repo: string | null;
  link: { href: string; label: string } | null;
  at: string;
  entry_hash: string | null;
  prev_hash: string | null;
}

export const CATEGORY_LABEL: Record<AuditCategory, string> = {
  scans: "Scans", reviews: "Reviews & sign-offs", findings: "Findings", incidents: "Incidents & alerts",
  access: "People & access", settings: "Settings & policy", integrations: "Repositories & integrations", evidence: "Evidence & reports",
};

/** SOC 2 criteria an event is evidence for. */
export const CATEGORY_SOC2: Record<AuditCategory, string[]> = {
  scans: ["CC7.1"], reviews: ["CC8.1"], findings: ["CC7.1", "CC7.4"], incidents: ["CC7.3", "CC7.4"],
  access: ["CC6.1", "CC6.2", "CC6.3"], settings: ["CC8.1", "CC5.2"], integrations: ["CC6.1", "CC8.1"], evidence: ["CC2.1", "CC4.1"],
};

const META: Record<string, { label: string; category: AuditCategory; severity?: AuditSeverity }> = {
  scan_complete:          { label: "Scan completed", category: "scans" },
  scan_rescan_requested:  { label: "Rescan requested", category: "scans" },
  attestation:            { label: "File signed off", category: "reviews" },
  merge_allowed:          { label: "Merge allowed", category: "reviews" },
  merge_blocked:          { label: "Merge blocked", category: "reviews", severity: "critical" },
  violation_resolved:     { label: "Finding status changed", category: "findings" },
  violation_escalated:    { label: "Finding escalated", category: "findings", severity: "warning" },
  violation_assigned:     { label: "Reviewer assigned", category: "findings" },
  finding_triaged:        { label: "Finding triaged", category: "findings" },
  finding_reopened:       { label: "Finding reopened", category: "findings", severity: "warning" },
  findings_baselined:     { label: "Findings baselined", category: "findings", severity: "warning" },
  policy_violation:       { label: "Policy violation", category: "findings", severity: "critical" },
  secret_detected:        { label: "Secret detected", category: "findings", severity: "critical" },
  secret_resolved:        { label: "Secret resolved", category: "findings" },
  sla_breach:             { label: "Fix deadline missed", category: "findings", severity: "critical" },
  exception_created:      { label: "Exception granted", category: "findings", severity: "warning" },
  exception_resolved:     { label: "Exception closed", category: "findings" },
  incident_created:       { label: "Incident opened", category: "incidents", severity: "critical" },
  incident_resolved:      { label: "Incident resolved", category: "incidents" },
  alert_fired:            { label: "Alert fired", category: "incidents", severity: "warning" },
  alert_resolved:         { label: "Alert resolved", category: "incidents" },
  risk_updated:           { label: "Risk register updated", category: "incidents" },
  user_login:             { label: "Signed in", category: "access" },
  user_added:             { label: "User added", category: "access", severity: "warning" },
  user_removed:           { label: "User removed", category: "access", severity: "warning" },
  member_invited:         { label: "Member invited", category: "access" },
  member_role_changed:    { label: "Role changed", category: "access", severity: "warning" },
  member_removed:         { label: "Member removed", category: "access", severity: "warning" },
  api_key_created:        { label: "API key created", category: "access", severity: "warning" },
  api_key_revoked:        { label: "API key revoked", category: "access" },
  policy_change:          { label: "Policy changed", category: "settings", severity: "warning" },
  org_settings_changed:   { label: "Settings changed", category: "settings", severity: "warning" },
  ai_tool_policy_changed: { label: "Approved AI tools changed", category: "settings", severity: "warning" },
  shadow_ai_triaged:      { label: "Shadow AI detection triaged", category: "settings" },
  integration_connected:  { label: "Integration connected", category: "integrations" },
  repo_connected:         { label: "Repository connected", category: "integrations" },
  repo_enabled:           { label: "Repository switched on", category: "integrations" },
  repo_disabled:          { label: "Repository switched off", category: "integrations", severity: "warning" },
  report_generated:       { label: "Report generated", category: "evidence" },
  evidence_collected:     { label: "Evidence collected", category: "evidence" },
  evidence_uploaded:      { label: "Evidence uploaded", category: "evidence" },
  evidence_deleted:       { label: "Evidence deleted", category: "evidence", severity: "warning" },
  data_exported:          { label: "Data exported", category: "evidence", severity: "warning" },
};

const titleCase = (s: string) => s.replace(/_/g, " ").replace(/^\w/, c => c.toUpperCase());
const str = (v: unknown) => (typeof v === "string" && v.trim() ? v : null);
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
const short = (path: string) => path.split("/").pop() || path;

export function auditMeta(type: string): { label: string; category: AuditCategory; severity: AuditSeverity } {
  const m = META[type];
  return m ? { label: m.label, category: m.category, severity: m.severity ?? "info" } : { label: titleCase(type), category: "settings", severity: "info" };
}

export function describeAuditRow(row: AuditRow): AuditView {
  const p = row.payload ?? {};
  const meta = auditMeta(row.event_type);
  const repo = str(p.repo);
  const scanId = str(p.scan_id) ?? (row.resource_type === "scan" ? str(row.resource_id) : null);
  const file = str(p.file_path) ?? str(p.file);
  const pr = num(p.pr_number);
  const facts: Array<[string, string]> = [];
  const add = (k: string, v: unknown) => { if (v != null && v !== "") facts.push([k, String(v)]); };
  let title = meta.label;
  let severity = meta.severity;
  let link: AuditView["link"] = null;

  switch (row.event_type) {
    case "scan_complete": {
      const risk = str(p.overall_risk);
      title = `Scan completed${pr ? ` for PR #${pr}` : ""}${risk ? ` — ${risk} risk` : ""}`;
      severity = risk === "CRITICAL" ? "critical" : risk === "HIGH" ? "warning" : "info";
      add("Repository", repo); add("Pull request", pr ? `#${pr}` : null); add("Commit", str(p.commit_sha)?.slice(0, 9)); add("Files", num(p.file_count)); add("Risk", risk);
      if (scanId) link = { href: `/pr/${scanId}`, label: "Open scan" };
      break;
    }
    case "attestation":
      title = `${file ? short(file) : "A file"} signed off${row.actor_email ? ` by ${row.actor_email}` : ""}`;
      add("File", file); add("Repository", repo); add("Pull request", pr ? `#${pr}` : null); add("Risk", str(p.risk_score)); add("Record hash", str(p.payload_hash)?.slice(0, 16));
      if (scanId) link = { href: `/pr/${scanId}`, label: "Open scan" };
      break;
    case "violation_resolved": {
      const status = str(p.status) ?? "resolved";
      title = `Finding marked ${status.replace(/_/g, " ")}${file ? ` — ${short(file)}` : ""}`;
      add("File", file); add("Status", status); add("Risk", str(p.risk_score)); add("Note", str(p.note));
      link = { href: "/violations", label: "Open violations" };
      break;
    }
    case "violation_assigned": {
      const to = str(p.assigned_email);
      title = to ? `${short(file ?? "Finding")} assigned to ${to}` : `Reviewer removed${file ? ` — ${short(file)}` : ""}`;
      add("File", file); add("Assigned to", to); add("Assigned by", row.actor_email ?? null);
      if (scanId) link = { href: `/pr/${scanId}`, label: "Open scan" };
      break;
    }
    case "violation_escalated":
      title = `Finding ${p.escalated === false ? "de-escalated" : "escalated"}${file ? ` — ${short(file)}` : ""}`;
      add("File", file);
      link = { href: "/violations", label: "Open violations" };
      break;
    case "incident_created": case "incident_resolved":
      title = `${meta.label}${str(p.title) ? `: ${p.title}` : ""}`;
      add("Severity", str(p.severity)); add("Opened automatically", p.auto_generated === true ? "yes" : null);
      link = { href: "/incidents", label: "Open incidents" };
      break;
    case "user_login":
      title = `${row.actor_email ?? "Someone"} signed in`;
      add("Method", str(p.method)); add("Two-factor", p.mfa === true ? "yes" : p.mfa === false ? "no" : null);
      break;
    case "member_role_changed":
      title = `Role changed${str(p.email) ? ` for ${p.email}` : ""}`;
      add("From", str(p.from) ?? str(p.old_role)); add("To", str(p.to) ?? str(p.new_role) ?? str(p.role));
      break;
    case "member_invited": case "member_removed": case "user_added": case "user_removed":
      title = `${meta.label}${str(p.email) ? `: ${p.email}` : ""}`;
      add("Role", str(p.role));
      break;
    case "api_key_created": case "api_key_revoked":
      title = `${meta.label}${str(p.name) ? ` — ${p.name}` : ""}`;
      add("Scopes", Array.isArray(p.scopes) ? (p.scopes as unknown[]).join(", ") : null);
      break;
    case "repo_connected": {
      const n = num(p.count) ?? 1;
      title = n > 1 ? `${n} repositories connected` : `Repository connected${repo ? `: ${repo}` : ""}`;
      add("Source", str(p.source)?.replace(/_/g, " "));
      if (Array.isArray(p.repos)) add("Repositories", (p.repos as unknown[]).slice(0, 5).join(", ") + ((p.repos as unknown[]).length > 5 ? ` +${(p.repos as unknown[]).length - 5} more` : ""));
      break;
    }
    case "repo_enabled": case "repo_disabled":
      title = `${meta.label}${repo ? `: ${repo}` : ""}`;
      if (repo) link = { href: `/repo/${repo}`, label: "Open repository" };
      break;
    case "report_generated":
      title = `${str(p.framework) ?? "Compliance"} report generated`;
      add("Period", str(p.period_start) && str(p.period_end) ? `${String(p.period_start).slice(0, 10)} → ${String(p.period_end).slice(0, 10)}` : null);
      add("Signature", str(p.signature)?.slice(0, 16));
      link = { href: "/reports", label: "Open reports" };
      break;
    case "data_exported":
      title = `Data exported${str(p.export_type) ? ` — ${String(p.export_type).replace(/_/g, " ")}` : ""}`;
      add("Format", str(p.format)?.toUpperCase()); add("Rows", num(p.rows) ?? num(p.findings));
      break;
    case "evidence_uploaded": case "evidence_deleted":
      title = `${meta.label}${str(p.filename) ? `: ${p.filename}` : str(p.path) ? `: ${short(String(p.path))}` : ""}`;
      link = { href: "/compliance", label: "Open compliance" };
      break;
    case "ai_tool_policy_changed": {
      const allowed = Array.isArray(p.allowed) ? (p.allowed as unknown[]).map(String) : [];
      title = "Approved AI tools changed";
      add("Now approved", allowed.length ? allowed.join(", ") : "none");
      link = { href: "/shadow-ai", label: "Open Shadow AI" };
      break;
    }
    case "risk_updated":
      title = `Risk register ${str(p.action)?.replace(/_/g, " ") ?? "updated"}${str(p.title) ? `: ${p.title}` : ""}`;
      add("Closed", num(p.closed)); add("Reopened", num(p.reopened)); add("Count", num(p.count));
      link = { href: "/risk-register", label: "Open risk register" };
      break;
    default:
      // Generic: whatever simple facts the payload carries.
      for (const [k, v] of Object.entries(p).slice(0, 6)) if (["string", "number", "boolean"].includes(typeof v)) add(titleCase(k), v);
  }
  if (row.resource_type && !facts.some(([k]) => k === "Resource")) add("Resource", `${row.resource_type}${row.resource_id ? ` ${row.resource_id}` : ""}`);

  return {
    id: row.id, type: row.event_type, label: meta.label, category: meta.category, severity, title, facts,
    actor: row.actor_email && row.actor_email !== "system" ? row.actor_email : null,
    repo, link, at: row.created_at, entry_hash: row.entry_hash ?? null, prev_hash: row.prev_hash ?? null,
  };
}

/** First day (YYYY-MM-DD, UTC) of a "last N days" period, or null for all time. */
export function sinceFor(period: string, now = Date.now()): string | null {
  const days = Number(period);
  return period === "all" || !Number.isFinite(days) || days <= 0 ? null : new Date(now - days * 86400_000).toISOString().slice(0, 10);
}

/** Event types grouped by category, for the filter menu. */
export function typesByCategory(): Array<[AuditCategory, Array<[string, string]>]> {
  const out = new Map<AuditCategory, Array<[string, string]>>();
  for (const [type, m] of Object.entries(META)) out.set(m.category, [...(out.get(m.category) ?? []), [type, m.label]]);
  return (Object.keys(CATEGORY_LABEL) as AuditCategory[]).filter(c => out.has(c)).map(c => [c, out.get(c)!]);
}
