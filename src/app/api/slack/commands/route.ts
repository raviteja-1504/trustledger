/**
 * Slack Slash Command Handler
 * Handles /trustledger slash commands from Slack.
 *
 * Commands:
 *   /trustledger status [repo]      → show current risk status
 *   /trustledger violations         → list open violations
 *   /trustledger attest <scan_id> <file> → attest a file
 *   /trustledger dashboard          → link to dashboard
 *   /trustledger help               → show available commands
 *
 * Setup in Slack:
 *   Create a Slack App → Slash Commands → /trustledger
 *   Request URL: https://app.trustledger.dev/api/slack/commands
 *   Short Description: TrustLedger AI governance
 *   Signing Secret: set SLACK_SIGNING_SECRET env var
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import crypto from "crypto";

const RISK_EMOJI: Record<string, string> = {
  CRITICAL:"🔴", HIGH:"🟠", MEDIUM:"🟡", LOW:"🟢",
};

function verifySlackSignature(body: string, timestamp: string | null, signature: string | null, secret: string): boolean {
  if (!timestamp || !signature || !secret) return !secret;
  // Reject requests older than 5 minutes
  if (Math.abs(Date.now() / 1000 - parseInt(timestamp)) > 300) return false;
  const sigBase = `v0:${timestamp}:${body}`;
  const expected = `v0=${crypto.createHmac("sha256", secret).update(sigBase).digest("hex")}`;
  try { return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected)); } catch { return false; }
}

async function findOrgBySlackTeam(db: ReturnType<typeof createServiceClient>, teamId: string): Promise<string | null> {
  // Match org by stored Slack team ID (stored in org settings)
  // Simplified: look up by env var or first org
  const orgSlug = process.env.NEXT_PUBLIC_ORG ?? "";
  if (!orgSlug) return null;
  const { data } = await db.from("organizations").select("id").eq("slug", orgSlug).single() as { data: { id: string } | null };
  return data?.id ?? null;
}

// ── Slack Block Kit response builders ─────────────────────────────────────────

function slackText(text: string) {
  return { response_type:"ephemeral", text };
}

function slackBlocks(blocks: unknown[]) {
  return { response_type:"ephemeral", blocks };
}

function slackError(msg: string) {
  return slackText(`❌ ${msg}`);
}

// ── Command handlers ──────────────────────────────────────────────────────────

async function handleStatus(db: ReturnType<typeof createServiceClient>, orgId: string, args: string[], appUrl: string) {
  const repo = args[0] ?? null;
  const since = new Date(Date.now() - 7*86400_000).toISOString();

  let baseQuery = db.from("scans")
    .select("repo_full_name, overall_risk, total_ai_percentage, created_at, id")
    .eq("org_id", orgId)
    .gte("created_at", since)
    .order("created_at", { ascending: false })
    .limit(5);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if (repo) baseQuery = (baseQuery as any).ilike("repo_full_name", `%${repo}%`);

  const { data: scansRaw } = await baseQuery;
  const scans = scansRaw as Array<{ repo_full_name: string; overall_risk: string; total_ai_percentage: number; created_at: string; id: string }> | null;

  if (!scans || scans.length === 0) {
    return slackText(repo ? `No recent scans found for \`${repo}\`.` : "No scans in the last 7 days.");
  }

  const { data: violations } = await db
    .from("violations")
    .select("id", { count:"exact", head:true })
    .eq("org_id", orgId)
    .in("status", ["open","in_review"]) as { data: null; count: number | null };

  return slackBlocks([
    {
      type: "header",
      text: { type:"plain_text", text:"🛡️ TrustLedger Status", emoji:true },
    },
    {
      type: "section",
      fields: [
        { type:"mrkdwn", text:`*Open violations:* ${violations ?? 0}` },
        { type:"mrkdwn", text:`*Recent scans (7d):* ${scans.length}` },
      ],
    },
    { type:"divider" },
    ...scans.slice(0, 3).map(s => ({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `${RISK_EMOJI[s.overall_risk]??""} *${s.repo_full_name.split("/")[1]}* — ${s.overall_risk} · ${(s.total_ai_percentage*100).toFixed(0)}% AI`,
      },
      accessory: {
        type:     "button",
        text:     { type:"plain_text", text:"Review" },
        url:      `${appUrl}/pr/${s.id}`,
        action_id:"view_scan",
      },
    })),
    {
      type: "actions",
      elements: [{
        type:      "button",
        text:      { type:"plain_text", text:"Open Dashboard →" },
        url:       `${appUrl}/dashboard`,
        style:     "primary",
        action_id: "open_dashboard",
      }],
    },
  ]);
}

async function handleViolations(db: ReturnType<typeof createServiceClient>, orgId: string, appUrl: string) {
  const { data: violations } = await db
    .from("violations")
    .select("id, file_path, risk_score, status, sla_deadline")
    .eq("org_id", orgId)
    .in("status", ["open","in_review"])
    .in("risk_score", ["CRITICAL","HIGH"])
    .order("sla_deadline", { ascending: true })
    .limit(8) as { data: Array<{ id: string; file_path: string; risk_score: string; status: string; sla_deadline: string | null }> | null };

  if (!violations || violations.length === 0) {
    return slackText("✅ No open CRITICAL or HIGH violations!");
  }

  return slackBlocks([
    {
      type: "header",
      text: { type:"plain_text", text:`⚠️ ${violations.length} Open Violations`, emoji:true },
    },
    ...violations.map(v => {
      const deadline = v.sla_deadline ? new Date(v.sla_deadline) : null;
      const overdue  = deadline && deadline < new Date();
      return {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `${RISK_EMOJI[v.risk_score]??""} \`${v.file_path.split("/").slice(-2).join("/")}\`${overdue ? " 🚨 *SLA BREACHED*" : ""}`,
        },
      };
    }),
    {
      type: "actions",
      elements: [{
        type:"button", text:{ type:"plain_text", text:"View All Violations →" },
        url:`${appUrl}/violations`, style:"danger", action_id:"view_violations",
      }],
    },
  ]);
}

function handleHelp(appUrl: string) {
  return slackBlocks([
    { type:"header", text:{ type:"plain_text", text:"🛡️ TrustLedger Commands", emoji:true } },
    { type:"section", text:{ type:"mrkdwn", text:[
      "`/trustledger status [repo]` — show recent scan status",
      "`/trustledger violations` — list open CRITICAL/HIGH violations",
      "`/trustledger dashboard` — open the TrustLedger dashboard",
      "`/trustledger help` — show this help",
    ].join("\n") } },
    { type:"actions", elements:[{
      type:"button", text:{ type:"plain_text", text:"Open Dashboard" },
      url:appUrl, style:"primary", action_id:"open_dashboard",
    }] },
  ]);
}

// ── Route handler ─────────────────────────────────────────────────────────────

export async function POST(req: NextRequest) {
  const rawBody  = await req.text();
  const timestamp = req.headers.get("x-slack-request-timestamp");
  const signature = req.headers.get("x-slack-signature");
  const secret    = process.env.SLACK_SIGNING_SECRET ?? "";

  if (!verifySlackSignature(rawBody, timestamp, signature, secret)) {
    return NextResponse.json({ error:"invalid_signature" }, { status:401 });
  }

  // Parse URL-encoded Slack body
  const params   = new URLSearchParams(rawBody);
  const teamId   = params.get("team_id")    ?? "";
  const text     = (params.get("text")      ?? "").trim();
  const [cmd, ...args] = text.split(/\s+/);
  const command  = (cmd || "help").toLowerCase();

  const db     = createServiceClient();
  const orgId  = await findOrgBySlackTeam(db, teamId);
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

  if (!orgId) {
    return NextResponse.json(slackError("TrustLedger not connected to this Slack workspace. Visit your Settings to connect."));
  }

  let response: unknown;

  switch (command) {
    case "status":
      response = await handleStatus(db, orgId, args, appUrl);
      break;
    case "violations":
      response = await handleViolations(db, orgId, appUrl);
      break;
    case "dashboard":
      response = slackText(`📊 Open TrustLedger dashboard: ${appUrl}/dashboard`);
      break;
    default:
      response = handleHelp(appUrl);
  }

  return NextResponse.json(response);
}
