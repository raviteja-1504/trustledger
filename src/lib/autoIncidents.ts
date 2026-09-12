/**
 * Server-side auto-generation of incidents from unattested-risk data.
 *
 * This used to run entirely in the browser (src/app/incidents/page.tsx,
 * incidentsFromDashboard()) and was stored ONLY in localStorage["tl_incidents"]
 * -- never written to the real `incidents` table. That's why the page could
 * show "4 active incidents" while the Sidebar badge (reading the real table)
 * correctly showed nothing: the 4 were browser-local fabrications that never
 * existed in the database. This module does the same derivation server-side
 * and writes real rows, so the count is identical everywhere and persists
 * across devices.
 *
 * Auto-generated incidents are marked by created_by IS NULL (manual incidents
 * created via the UI always have a signed-in user, so this reliably tells
 * them apart) and are auto-resolved here too once their trigger clears.
 *
 * Call this after anything that can change which files are unattested:
 * a new scan landing, or a file being attested.
 */

import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types/supabase";
import { fetchDashboard } from "@/lib/dashboardAggregate";
import { PLAYBOOK_TEMPLATES, type IncidentType } from "./incidentPlaybooks";
import { writeAuditLog } from "./audit";

type IncidentRow = Database["public"]["Tables"]["incidents"]["Row"];

export async function syncAutoIncidents(db: SupabaseClient<Database>, orgId: string): Promise<void> {
  try {
    const data = await fetchDashboard(orgId, 90, null);
    const now  = new Date().toISOString();

    const stillOpenFiles = new Set(
      data.top_risk_files
        .filter(f => f.risk_score === "CRITICAL" && !f.attested)
        .map(f => f.file_path),
    );

    const { data: existingAuto } = await db
      .from("incidents")
      .select("id, status, affected_file, incident_type, timeline")
      .eq("org_id", orgId)
      .is("created_by", null);

    const autoRows = (existingAuto ?? []) as Pick<IncidentRow, "id" | "status" | "affected_file" | "incident_type" | "timeline">[];
    const activeFileRows = autoRows.filter(r => r.status === "active" && r.affected_file);
    const activeBacklog  = autoRows.find(r => r.status === "active" && !r.affected_file && r.incident_type === "policy-violation");
    const trackedFiles   = new Set(activeFileRows.map(r => r.affected_file as string));

    // 1. Auto-resolve file-tied incidents whose file is no longer open.
    for (const row of activeFileRows) {
      if (row.affected_file && stillOpenFiles.has(row.affected_file)) continue;
      const timeline = Array.isArray(row.timeline) ? row.timeline : [];
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (db.from("incidents") as any).update({
        status: "resolved",
        resolved_at: now,
        timeline: [...timeline, { time: now, action: "Auto-resolved: file has been reviewed and attested", actor: "TrustLedger" }],
      }).eq("id", row.id);
    }

    // 2. Auto-resolve the deploy-backlog incident once the count clears.
    if (activeBacklog && data.unattested_deploy_count <= 3) {
      const timeline = Array.isArray(activeBacklog.timeline) ? activeBacklog.timeline : [];
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (db.from("incidents") as any).update({
        status: "resolved",
        resolved_at: now,
        timeline: [...timeline, { time: now, action: `Auto-resolved: unattested deploy count is now ${data.unattested_deploy_count}`, actor: "TrustLedger" }],
      }).eq("id", activeBacklog.id);
    }

    // 3. Create P1 incidents for newly-seen CRITICAL unattested files (max 3
    //    at a time, matching the original client-side behavior, to avoid noise).
    const untracked = data.top_risk_files
      .filter(f => f.risk_score === "CRITICAL" && !f.attested && !trackedFiles.has(f.file_path))
      .slice(0, 3);

    for (const f of untracked) {
      const incType: IncidentType = /auth|login|oauth|session/i.test(f.file_path) ? "auth-bypass"
        : /secret|key|token|pass/i.test(f.file_path) ? "secret-exposed"
        : "rce-pattern";
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { data: incident } = await (db.from("incidents") as any).insert({
        org_id: orgId,
        title: `CRITICAL unattested file: ${f.file_path.split("/").pop()}`,
        description: `TrustLedger detected a CRITICAL-risk AI-generated file that has not been attested. File ${f.file_path} in ${f.repo} has AI percentage of ${(f.ai_pct * 100).toFixed(0)}% and risk score CRITICAL. This file was deployed without security review.`,
        severity: "P1",
        status: "active",
        incident_type: incType,
        affected_repo: f.repo,
        affected_file: f.file_path,
        impact: `Unreviewed AI-generated code in production. AI percentage: ${(f.ai_pct * 100).toFixed(0)}%. Deploy #${f.pr_number} blocked from full attestation.`,
        timeline: [
          { time: now, action: "CRITICAL file detected by TrustLedger scan", actor: "TrustLedger" },
          { time: now, action: "P1 incident auto-created", actor: "TrustLedger" },
        ],
        playbook: PLAYBOOK_TEMPLATES[incType].steps.map(s => ({ ...s, completed: false })),
        stakeholders: [],
        detected_at: now,
        created_by: null,
      }).select("id").single() as { data: { id: string } | null };

      if (incident) {
        await writeAuditLog(db, {
          org_id: orgId, event_type: "incident_created", actor_email: "system",
          resource_type: "incident", resource_id: incident.id,
          payload: { title: `CRITICAL unattested file: ${f.file_path.split("/").pop()}`, severity: "P1", auto_generated: true },
        });
      }
    }

    // 4. Create a P2 backlog incident once the unattested deploy count is high.
    if (data.unattested_deploy_count > 3 && !activeBacklog) {
      const repos = data.repos;
      const worstRepo = repos.length > 0
        ? [...repos].sort((a, b) => a.attestation_rate - b.attestation_rate)[0].repo
        : "unknown";
      const attPct = Math.round(data.attestation_rate * 100);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { data: incident } = await (db.from("incidents") as any).insert({
        org_id: orgId,
        title: `${data.unattested_deploy_count} files unattested across ${repos.length} repo${repos.length !== 1 ? "s" : ""}`,
        description: `${data.unattested_deploy_count} CRITICAL/HIGH files require attestation. Organisation-wide attestation rate: ${attPct}%. Policy requires all CRITICAL and HIGH files to be reviewed before merge.`,
        severity: "P2",
        status: "active",
        incident_type: "policy-violation",
        affected_repo: worstRepo,
        impact: `${data.unattested_deploy_count} file${data.unattested_deploy_count !== 1 ? "s" : ""} unreviewed across ${repos.length} repo${repos.length !== 1 ? "s" : ""}. Compliance posture: ${attPct < 50 ? "critical" : attPct < 80 ? "degraded" : "at risk"}.`,
        timeline: [
          { time: now, action: `${data.unattested_deploy_count} unattested CRITICAL/HIGH files detected`, actor: "TrustLedger" },
          { time: now, action: "P2 policy-violation incident created", actor: "TrustLedger" },
        ],
        playbook: PLAYBOOK_TEMPLATES["policy-violation"].steps.map(s => ({ ...s, completed: false })),
        stakeholders: [],
        detected_at: now,
        created_by: null,
      }).select("id").single() as { data: { id: string } | null };

      if (incident) {
        await writeAuditLog(db, {
          org_id: orgId, event_type: "incident_created", actor_email: "system",
          resource_type: "incident", resource_id: incident.id,
          payload: { title: "Unattested deploy backlog", severity: "P2", auto_generated: true },
        });
      }
    }
  } catch (err) {
    // Best-effort — never let incident auto-generation break the scan/attest
    // request that triggered it.
    console.error("[autoIncidents] sync failed:", err);
  }
}
