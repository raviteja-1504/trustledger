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
import { fetchUnattestedRiskState } from "@/lib/dashboardAggregate";
import { cached, cacheKeys } from "@/lib/cache";
import { PLAYBOOK_TEMPLATES, type IncidentType } from "./incidentPlaybooks";
import { writeAuditLog } from "./audit";

type IncidentRow = Database["public"]["Tables"]["incidents"]["Row"];

/** Bounded so an incident that flaps open/closed for months can't grow its timeline without limit. */
const MAX_TIMELINE_ENTRIES = 50;

/** Change an auto-incident's status and append one timeline entry (reading only that row's timeline). */
async function transitionIncident(
  db: SupabaseClient<Database>, orgId: string, id: string, now: string,
  fields: { status: string; resolved_at: string | null }, action: string,
): Promise<void> {
  const { data } = await db.from("incidents").select("timeline").eq("id", id).eq("org_id", orgId).single() as { data: { timeline: unknown } | null };
  const timeline = Array.isArray(data?.timeline) ? data.timeline : [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await (db.from("incidents") as any).update({
    ...fields,
    timeline: [...timeline, { time: now, action, actor: "TrustLedger" }].slice(-MAX_TIMELINE_ENTRIES),
  }).eq("id", id).eq("org_id", orgId);
}

export async function syncAutoIncidents(db: SupabaseClient<Database>, orgId: string): Promise<void> {
  try {
    // fetchUnattestedRiskState() is a full org-wide aggregation (every scan,
    // repo, attestation, violation and up to 1000 scan_files rows, joined and
    // grouped in JS) -- expensive enough that running it unconditionally on
    // every single call here (this function fires on every attest, plus every
    // new scan landing) was the dominant CPU cost on those hot paths. A short
    // per-org cache collapses bursts (e.g. "attest all" firing this once per
    // file in a few seconds) into one real aggregation; a normal, non-bursty
    // call is unaffected since nothing is cached yet. Incident sync is
    // already best-effort (see the catch below), so a few seconds of
    // staleness here is an acceptable trade for the CPU savings.
    const data = await cached(cacheKeys.autoIncidentState(orgId), 12, () => fetchUnattestedRiskState(orgId));
    const now  = new Date().toISOString();

    // Identity of a file-tied incident: repo AND path (the same path in two repos is two problems).
    const fileKey = (repo: string | null | undefined, file: string | null | undefined) => `${repo ?? ""}::${file ?? ""}`;
    const openFiles = data.top_risk_files.filter(f => f.risk_score === "CRITICAL" && !f.attested);
    const stillOpenKeys = new Set(openFiles.map(f => fileKey(f.repo, f.file_path)));

    // No timeline here: it's the bulk of each row, and only the few rows actually updated need it.
    const { data: existingAuto } = await db
      .from("incidents")
      .select("id, status, affected_repo, affected_file, incident_type, detected_at")
      .eq("org_id", orgId)
      .is("created_by", null)
      .order("detected_at", { ascending: false });

    const autoRows = (existingAuto ?? []) as Pick<IncidentRow, "id" | "status" | "affected_repo" | "affected_file" | "incident_type" | "detected_at">[];
    // One row per repo+file, reused for its whole life. Scans of different PRs in the same repo take turns
    // being "the latest scan", so a file can leave and re-enter the open set many times; inserting a fresh
    // incident on every re-entry is what grew this table to thousands of rows.
    const rowByKey = new Map<string, (typeof autoRows)[number]>();
    for (const r of autoRows) if (r.affected_file && !rowByKey.has(fileKey(r.affected_repo, r.affected_file))) rowByKey.set(fileKey(r.affected_repo, r.affected_file), r);
    const backlogRow = autoRows.find(r => !r.affected_file && r.incident_type === "policy-violation");

    // 1. Auto-resolve file-tied incidents whose file is no longer an unattested CRITICAL file in its repo's
    //    latest scan (attested, fixed, or that scan is now of another PR -- not necessarily "reviewed").
    for (const row of rowByKey.values()) {
      if (row.status !== "active" || stillOpenKeys.has(fileKey(row.affected_repo, row.affected_file))) continue;
      await transitionIncident(db, orgId, row.id, now, { status: "resolved", resolved_at: now },
        "Auto-resolved: no longer an unattested CRITICAL file in the repository's latest scan");
    }

    // 2. Auto-resolve the deploy-backlog incident once the count clears.
    if (backlogRow?.status === "active" && data.unattested_deploy_count <= 3) {
      await transitionIncident(db, orgId, backlogRow.id, now, { status: "resolved", resolved_at: now },
        `Auto-resolved: unattested deploy count is now ${data.unattested_deploy_count}`);
    }

    // 3. Reopen the existing incident for a file that is open again, rather than creating another one.
    for (const f of openFiles) {
      const row = rowByKey.get(fileKey(f.repo, f.file_path));
      if (!row || row.status !== "resolved") continue;
      await transitionIncident(db, orgId, row.id, now, { status: "active", resolved_at: null },
        "Re-opened: CRITICAL file is unattested again in the latest scan");
    }

    // 4. Create P1 incidents for CRITICAL unattested files that have never had one (max 3 at a time,
    //    matching the original client-side behavior, to avoid noise).
    const untracked = openFiles.filter(f => !rowByKey.has(fileKey(f.repo, f.file_path))).slice(0, 3);

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
    if (data.unattested_deploy_count > 3 && backlogRow?.status === "resolved") {
      await transitionIncident(db, orgId, backlogRow.id, now, { status: "active", resolved_at: null },
        `Re-opened: ${data.unattested_deploy_count} CRITICAL/HIGH files unattested`);
    } else if (data.unattested_deploy_count > 3 && !backlogRow) {
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
