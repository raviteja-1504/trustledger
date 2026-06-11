/**
 * Ticket Integration API
 * Creates JIRA or Linear tickets from TrustLedger violations/incidents.
 * Org config stored in tl_org_integrations Supabase table (or env vars for self-hosted).
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { writeAuditLog } from "@/lib/audit";

interface TicketPayload {
  provider:    "jira" | "linear";
  title:       string;
  description: string;
  priority:    "highest" | "high" | "medium" | "low";
  labels?:     string[];
  // Context
  violation_id?: string;
  incident_id?:  string;
  scan_id?:      string;
  file_path?:    string;
  repo?:         string;
  risk_score?:   string;
}

// ── JIRA ───────────────────────────────────────────────────────────────────────

async function createJiraTicket(config: {
  base_url:  string;
  email:     string;
  api_token: string;
  project_key: string;
}, payload: TicketPayload): Promise<{ id: string; key: string; url: string }> {
  const priorityMap: Record<string, string> = {
    highest: "Highest", high: "High", medium: "Medium", low: "Low",
  };

  const body = {
    fields: {
      project:     { key: config.project_key },
      summary:     payload.title,
      description: {
        type:    "doc",
        version: 1,
        content: [{
          type:    "paragraph",
          content: [{ type: "text", text: payload.description }],
        }],
      },
      issuetype: { name: "Bug" },
      priority:  { name: priorityMap[payload.priority] ?? "High" },
      labels:    ["trustledger", ...(payload.labels ?? [])],
    },
  };

  const res = await fetch(`${config.base_url}/rest/api/3/issue`, {
    method:  "POST",
    headers: {
      Authorization: `Basic ${Buffer.from(`${config.email}:${config.api_token}`).toString("base64")}`,
      "Content-Type": "application/json",
      Accept:         "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({})) as { errors?: unknown };
    throw new Error(`JIRA error: ${JSON.stringify(err)}`);
  }

  const data = await res.json() as { id: string; key: string; self: string };
  return {
    id:  data.id,
    key: data.key,
    url: `${config.base_url}/browse/${data.key}`,
  };
}

// ── Linear ─────────────────────────────────────────────────────────────────────

async function createLinearTicket(config: {
  api_key:  string;
  team_id?: string;
}, payload: TicketPayload): Promise<{ id: string; identifier: string; url: string }> {
  const priorityMap: Record<string, number> = {
    highest: 1, high: 2, medium: 3, low: 4,
  };

  // Get team ID if not provided
  let teamId = config.team_id;
  if (!teamId) {
    const teamsRes = await fetch("https://api.linear.app/graphql", {
      method:  "POST",
      headers: { Authorization: config.api_key, "Content-Type": "application/json" },
      body:    JSON.stringify({ query: "{ teams { nodes { id name } } }" }),
    });
    const teams = await teamsRes.json() as { data: { teams: { nodes: { id: string }[] } } };
    teamId = teams.data?.teams?.nodes?.[0]?.id;
  }

  if (!teamId) throw new Error("Linear: no team found");

  const mutation = `
    mutation CreateIssue($input: IssueCreateInput!) {
      issueCreate(input: $input) {
        success
        issue { id identifier url }
      }
    }
  `;

  const res = await fetch("https://api.linear.app/graphql", {
    method:  "POST",
    headers: { Authorization: config.api_key, "Content-Type": "application/json" },
    body:    JSON.stringify({
      query:     mutation,
      variables: {
        input: {
          teamId,
          title:       payload.title,
          description: payload.description,
          priority:    priorityMap[payload.priority] ?? 2,
          labelNames:  ["TrustLedger", ...(payload.labels ?? [])],
        },
      },
    }),
  });

  const data = await res.json() as {
    data?: { issueCreate?: { success: boolean; issue?: { id: string; identifier: string; url: string } } };
    errors?: unknown[];
  };

  if (!data.data?.issueCreate?.success || !data.data.issueCreate.issue) {
    throw new Error(`Linear error: ${JSON.stringify(data.errors)}`);
  }

  return data.data.issueCreate.issue;
}

// ── Route handler ──────────────────────────────────────────────────────────────

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const payload = await req.json() as TicketPayload;
  if (!payload.provider || !payload.title) {
    return NextResponse.json({ error: "missing_fields" }, { status: 400 });
  }

  const db = createServiceClient();

  // Build rich description with TrustLedger context
  const contextLines: string[] = [
    payload.description,
    "",
    "---",
    "**TrustLedger Context**",
  ];
  if (payload.repo)       contextLines.push(`Repository: ${payload.repo}`);
  if (payload.file_path)  contextLines.push(`File: ${payload.file_path}`);
  if (payload.risk_score) contextLines.push(`Risk: ${payload.risk_score}`);
  if (payload.scan_id) {
    const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";
    contextLines.push(`Review: ${appUrl}/pr/${payload.scan_id}`);
  }
  const description = contextLines.join("\n");

  let ticket: { id: string; url: string; key?: string; identifier?: string };

  try {
    if (payload.provider === "jira") {
      const jiraUrl      = process.env.JIRA_BASE_URL      ?? "";
      const jiraEmail    = process.env.JIRA_EMAIL          ?? "";
      const jiraToken    = process.env.JIRA_API_TOKEN      ?? "";
      const jiraProject  = process.env.JIRA_PROJECT_KEY    ?? "TL";

      if (!jiraUrl || !jiraToken) {
        return NextResponse.json({ error: "jira_not_configured" }, { status: 422 });
      }

      const result = await createJiraTicket(
        { base_url: jiraUrl, email: jiraEmail, api_token: jiraToken, project_key: jiraProject },
        { ...payload, description },
      );
      ticket = result;

    } else if (payload.provider === "linear") {
      const linearKey    = process.env.LINEAR_API_KEY   ?? "";
      const linearTeamId = process.env.LINEAR_TEAM_ID;

      if (!linearKey) {
        return NextResponse.json({ error: "linear_not_configured" }, { status: 422 });
      }

      const result = await createLinearTicket(
        { api_key: linearKey, team_id: linearTeamId },
        { ...payload, description },
      );
      ticket = result;

    } else {
      return NextResponse.json({ error: "unsupported_provider" }, { status: 400 });
    }

    // Update violation record with ticket URL if provided
    if (payload.violation_id) {
      const { data: viol } = await db
        .from("violations")
        .select("notes")
        .eq("id", payload.violation_id)
        .single() as { data: { notes: unknown[] } | null };

      const notes = (Array.isArray(viol?.notes) ? viol.notes : []) as unknown[];
      notes.push({
        text: `${payload.provider.toUpperCase()} ticket created: ${ticket.key ?? ticket.identifier ?? ticket.id} — ${ticket.url}`,
        by:   actor_email ?? "system",
        at:   new Date().toISOString(),
      });
      await db.from("violations").update({ notes }).eq("id", payload.violation_id);
    }

    await writeAuditLog(db, {
      org_id,
      event_type:    "violation_escalated",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "ticket",
      resource_id:   ticket.id,
      payload: { provider: payload.provider, url: ticket.url, title: payload.title },
    });

    return NextResponse.json({
      ok:         true,
      ticket_id:  ticket.id,
      ticket_key: ticket.key ?? ticket.identifier,
      ticket_url: ticket.url,
      provider:   payload.provider,
    });

  } catch (e) {
    console.error("Ticket creation failed:", e);
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
