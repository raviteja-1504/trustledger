/**
 * Zapier / Make.com Integration API
 *
 * Provides trigger and action endpoints for no-code workflow automation.
 *
 * Triggers (Zapier polls these):
 *   GET /api/zapier/triggers/scan_completed    → new scans
 *   GET /api/zapier/triggers/violation_opened  → new CRITICAL/HIGH violations
 *   GET /api/zapier/triggers/alert_fired       → new P1/P2 alerts
 *
 * Actions (Zapier calls these):
 *   POST /api/zapier/actions/resolve_violation → resolve a violation
 *   POST /api/zapier/actions/create_incident   → create an incident
 *
 * Authentication: X-TrustLedger-Key header (same as REST API)
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type R = Record<string, any>;

// ── Shared pagination helper ──────────────────────────────────────────────────

function parseSince(req: NextRequest): string {
  const url   = new URL(req.url);
  const since = url.searchParams.get("since");
  if (since) return since;
  // Default to last 24 hours for polling triggers
  return new Date(Date.now() - 24 * 3600_000).toISOString();
}

// ── GET /api/zapier?trigger=scan_completed ────────────────────────────────────

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url     = new URL(req.url);
  const trigger = url.searchParams.get("trigger");
  const since   = parseSince(req);
  const limit   = Math.min(parseInt(url.searchParams.get("limit") ?? "25"), 100);

  const db = createServiceClient();

  switch (trigger) {

    case "scan_completed": {
      const { data } = await db
        .from("scans")
        .select("id, repo_full_name, pr_number, commit_sha, overall_risk, total_ai_percentage, file_count, created_at")
        .eq("org_id", org_id)
        .gte("created_at", since)
        .order("created_at", { ascending: false })
        .limit(limit) as { data: unknown[] | null };

      return NextResponse.json({
        trigger: "scan_completed",
        items:   ((data ?? []) as R[]).map((s) => ({
          id:           s.id,
          repo:         s.repo_full_name,
          pr_number:    s.pr_number,
          commit_sha:   s.commit_sha,
          overall_risk: s.overall_risk,
          ai_percent:   Math.round((s.total_ai_percentage as number) * 100),
          file_count:   s.file_count,
          created_at:   s.created_at,
          review_url:   `${process.env.NEXT_PUBLIC_APP_URL ?? ""}/pr/${s.id}`,
        })),
      });
    }

    case "violation_opened": {
      const { data } = await db
        .from("violations")
        .select("id, scan_id, file_path, risk_score, status, sla_deadline, created_at")
        .eq("org_id", org_id)
        .in("risk_score", ["CRITICAL","HIGH"])
        .in("status", ["open","in_review"])
        .gte("created_at", since)
        .order("created_at", { ascending: false })
        .limit(limit) as { data: unknown[] | null };

      return NextResponse.json({
        trigger: "violation_opened",
        items:   ((data ?? []) as R[]).map((v) => ({
          id:           v.id,
          file:         v.file_path,
          risk:         v.risk_score,
          status:       v.status,
          sla_deadline: v.sla_deadline,
          created_at:   v.created_at,
          review_url:   `${process.env.NEXT_PUBLIC_APP_URL ?? ""}/violations`,
        })),
      });
    }

    case "alert_fired": {
      const { data } = await db
        .from("alerts")
        .select("id, alert_type, severity, title, body, repo, fired_at")
        .eq("org_id", org_id)
        .in("severity", ["P1","P2"])
        .gte("fired_at", since)
        .order("fired_at", { ascending: false })
        .limit(limit) as { data: unknown[] | null };

      return NextResponse.json({
        trigger: "alert_fired",
        items:   ((data ?? []) as R[]).map((a) => ({
          id:         a.id,
          severity:   a.severity,
          title:      a.title,
          body:       a.body,
          repo:       a.repo,
          fired_at:   a.fired_at,
          review_url: `${process.env.NEXT_PUBLIC_APP_URL ?? ""}/alerts`,
        })),
      });
    }

    case "secret_detected": {
      const { data } = await db
        .from("secret_findings")
        .select("id, file_path, label, severity, status, created_at")
        .eq("org_id", org_id)
        .in("severity", ["CRITICAL","HIGH"])
        .gte("created_at", since)
        .order("created_at", { ascending: false })
        .limit(limit) as { data: unknown[] | null };

      return NextResponse.json({
        trigger: "secret_detected",
        items:   ((data ?? []) as R[]).map((s) => ({
          id:         s.id,
          file:       s.file_path,
          label:      s.label,
          severity:   s.severity,
          status:     s.status,
          created_at: s.created_at,
          review_url: `${process.env.NEXT_PUBLIC_APP_URL ?? ""}/secrets`,
        })),
      });
    }

    default:
      // Return available triggers for Zapier discovery
      return NextResponse.json({
        triggers: [
          { key:"scan_completed",  name:"New Scan Completed",    description:"Fires when a PR scan completes"                 },
          { key:"violation_opened",name:"New Violation Opened",  description:"Fires when a CRITICAL/HIGH violation is detected" },
          { key:"alert_fired",     name:"P1/P2 Alert Fired",     description:"Fires when a P1 or P2 alert is triggered"        },
          { key:"secret_detected", name:"Secret Detected",       description:"Fires when a hardcoded secret is found"          },
        ],
        auth_note: "Authenticate with X-TrustLedger-Key header",
      });
  }
}

// ── POST /api/zapier?action=... ───────────────────────────────────────────────

export async function POST(req: NextRequest) {
  const { org_id, user_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url    = new URL(req.url);
  const action = url.searchParams.get("action");
  const body   = await req.json() as Record<string, unknown>;
  const db     = createServiceClient();

  switch (action) {

    case "resolve_violation": {
      const id   = body.violation_id as string;
      const note = body.note as string | undefined;
      if (!id) return NextResponse.json({ error:"missing violation_id" }, { status:400 });

      await db.from("violations")
        .update({ status:"resolved", resolved_at: new Date().toISOString(), resolved_by: user_id ?? null })
        .eq("id", id)
        .eq("org_id", org_id);

      return NextResponse.json({ ok: true, resolved_id: id });
    }

    case "create_incident": {
      const { title, severity, incident_type, affected_repo, description } = body as {
        title: string; severity: string; incident_type: string; affected_repo?: string; description?: string;
      };
      if (!title) return NextResponse.json({ error:"missing title" }, { status:400 });

      const { data: inc } = await db.from("incidents").insert({
        org_id,
        title, severity: severity ?? "P2",
        incident_type:  incident_type ?? "unknown",
        affected_repo:  affected_repo ?? null,
        description:    description ?? null,
        status:         "active",
        detected_at:    new Date().toISOString(),
        timeline:       [{ time: new Date().toISOString(), action:"Created via Zapier", actor:"zapier-integration" }],
        stakeholders:   [],
        playbook:       [],
        created_by:     user_id ?? null,
      }).select("id").single() as { data: { id: string } | null };

      return NextResponse.json({ ok: true, incident_id: inc?.id });
    }

    default:
      return NextResponse.json({
        actions: [
          { key:"resolve_violation", name:"Resolve Violation",  fields:[{ key:"violation_id",required:true },{ key:"note" }] },
          { key:"create_incident",   name:"Create Incident",    fields:[{ key:"title",required:true },{ key:"severity" },{ key:"affected_repo" }] },
        ],
      });
  }
}
