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
import { orgDataVersion, versionedKey } from "./orgDataVersion";

type IncidentRow = Database["public"]["Tables"]["incidents"]["Row"];

/** Bounded so an incident that flaps open/closed for months can't grow its timeline without limit. */
const MAX_TIMELINE_ENTRIES = 50;

export const backlogTitle = (files: number, repos: number) =>
  `${files} CRITICAL/HIGH file${files !== 1 ? "s" : ""} unattested across ${repos} repo${repos !== 1 ? "s" : ""}`;

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
    // The cache key carries the org's data version, so a sync right after an attestation never reuses state computed
    // before it (that left the file's incident active until some later scan or attestation happened to re-sync).
    const version = await orgDataVersion(db, orgId);
    const data = version == null
      ? await fetchUnattestedRiskState(orgId)
      : await cached(versionedKey(cacheKeys.autoIncidentState(orgId), version), 12, () => fetchUnattestedRiskState(orgId));
    const now  = new Date().toISOString();

    // Identity of a file-tied incident: repo AND path (the same path in two repos is two problems).
    const fileKey = (repo: string | null | undefined, file: string | null | undefined) => `${repo ?? ""}::${file ?? ""}`;
    // Open: a CRITICAL file in the latest scan, not attested, and whose finding hasn't been closed (resolved or
    // accepted on the violations page also ends the incident).
    const closed = new Set(data.closed_files ?? []);
    // The violations page records status changes as overrides keyed "crit::<scan>::<path>"; resolved ones count too.
    const { data: overrides } = await db.from("violation_overrides").select("violation_id").eq("org_id", orgId).eq("status", "resolved") as
      { data: Array<{ violation_id: string }> | null };
    const resolvedOverride = new Set((overrides ?? []).map(o => { const p = o.violation_id.split("::"); return `${p[1]}::${p.slice(2).join("::")}`; }));
    // Files still needing a sign-off: CRITICAL/HIGH in their repo's latest scan, not attested, not closed or
    // resolved. The same rule the dashboard uses -- the backlog count used to be every open violation row, which
    // stays "open" after an attestation, so it kept counting files that were already signed off (16 vs 9).
    const needsSignoff = data.top_risk_files.filter(f => (f.risk_score === "CRITICAL" || f.risk_score === "HIGH") && !f.attested
      && !closed.has(fileKey(f.repo, f.file_path)) && !resolvedOverride.has(`${f.scan_id}::${f.file_path}`));
    const backlogCount = needsSignoff.length;
    const backlogRepos = new Set(needsSignoff.map(f => f.repo)).size;
    const openFiles = needsSignoff.filter(f => f.risk_score === "CRITICAL");
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
    // "Still open" covers contained too: containing an incident doesn't make its file signed off, and once the file
    // is signed off a contained incident is just as finished as an active one.
    const isOpen = (s: string | null) => s === "active" || s === "contained";

    // 0. Older versions of this sync created several rows for one file (and several backlog rows). Only the newest
    //    is managed below, so any other still-open copy stayed open forever and inflated the incident count.
    //    One bulk update (there can be many); the kept row's timeline is the record for that issue.
    const kept = new Set([...rowByKey.values()].map(r => r.id));
    if (backlogRow) kept.add(backlogRow.id);
    const duplicates = autoRows
      .filter(r => (r.affected_file || r.incident_type === "policy-violation") && !kept.has(r.id) && isOpen(r.status))
      .map(r => r.id);
    for (let i = 0; i < duplicates.length; i += 200) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (db.from("incidents") as any).update({ status: "resolved", resolved_at: now })
        .in("id", duplicates.slice(i, i + 200)).eq("org_id", orgId).is("created_by", null);
    }

    // 1. Auto-resolve file-tied incidents whose file is no longer an unattested CRITICAL file in its repo's
    //    latest scan (attested, fixed, or that scan is now of another PR -- not necessarily "reviewed").
    for (const row of rowByKey.values()) {
      if (!isOpen(row.status) || stillOpenKeys.has(fileKey(row.affected_repo, row.affected_file))) continue;
      await transitionIncident(db, orgId, row.id, now, { status: "resolved", resolved_at: now },
        "Auto-resolved: attested, resolved, or no longer a CRITICAL file in the repository's latest scan");
    }

    // 2. Auto-resolve the sign-off backlog incident once it clears.
    if (isOpen(backlogRow?.status ?? null) && backlogCount <= 3) {
      await transitionIncident(db, orgId, backlogRow!.id, now, { status: "resolved", resolved_at: now },
        `Auto-resolved: ${backlogCount} CRITICAL/HIGH file${backlogCount !== 1 ? "s" : ""} now waiting for sign-off`);
    }

    // 3. Reopen the existing incident for a file that is open again, rather than creating another one.
    //    (Its duplicates, resolved in step 0, stay resolved: only the newest row is reused.)
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

    // 4. Keep an open backlog incident's title current (it used to keep the count from when it was created).
    if (isOpen(backlogRow?.status ?? null) && backlogCount > 3) {
      const title = backlogTitle(backlogCount, backlogRepos);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (db.from("incidents") as any).update({ title }).eq("id", backlogRow!.id).eq("org_id", orgId).neq("title", title);
    }

    // 5. Create a P2 backlog incident once many files are waiting for sign-off.
    if (backlogCount > 3 && backlogRow?.status === "resolved") {
      await transitionIncident(db, orgId, backlogRow.id, now, { status: "active", resolved_at: null },
        `Re-opened: ${backlogCount} CRITICAL/HIGH files unattested`);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (db.from("incidents") as any).update({ title: backlogTitle(backlogCount, backlogRepos) }).eq("id", backlogRow.id).eq("org_id", orgId);
    } else if (backlogCount > 3 && !backlogRow) {
      const repos = data.repos;
      const worstRepo = repos.length > 0
        ? [...repos].sort((a, b) => a.attestation_rate - b.attestation_rate)[0].repo
        : "unknown";
      const attPct = Math.round(data.attestation_rate * 100);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { data: incident } = await (db.from("incidents") as any).insert({
        org_id: orgId,
        title: backlogTitle(backlogCount, backlogRepos),
        description: `${backlogCount} CRITICAL/HIGH files require attestation. Organisation-wide attestation rate: ${attPct}%. Policy requires all CRITICAL and HIGH files to be reviewed before merge.`,
        severity: "P2",
        status: "active",
        incident_type: "policy-violation",
        affected_repo: worstRepo,
        impact: `${backlogCount} file${backlogCount !== 1 ? "s" : ""} unreviewed across ${backlogRepos} repo${backlogRepos !== 1 ? "s" : ""}. Compliance posture: ${attPct < 50 ? "critical" : attPct < 80 ? "degraded" : "at risk"}.`,
        timeline: [
          { time: now, action: `${backlogCount} unattested CRITICAL/HIGH files detected`, actor: "TrustLedger" },
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
