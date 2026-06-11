/**
 * Integration Health Monitoring
 * Checks connectivity and configuration of all configured integrations.
 * GET /api/integrations/health → status of all integrations
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";

interface IntegrationStatus {
  name:        string;
  connected:   boolean;
  healthy:     boolean;
  last_check:  string;
  error?:      string;
  details?:    string;
}

async function checkGitHub(db: ReturnType<typeof createServiceClient>, orgId: string): Promise<IntegrationStatus> {
  const { data } = await db
    .from("github_installations")
    .select("installation_id, github_org")
    .eq("org_id", orgId)
    .limit(1)
    .single() as { data: { installation_id: number; github_org: string } | null };

  if (!data) return { name:"GitHub", connected:false, healthy:false, last_check:new Date().toISOString(), details:"Not installed" };

  try {
    const res = await fetch(`https://api.github.com/app/installations/${data.installation_id}`, {
      headers: { Accept:"application/vnd.github+json" },
    });
    return {
      name:       "GitHub App",
      connected:  true,
      healthy:    res.status !== 404,
      last_check: new Date().toISOString(),
      details:    `Installation #${data.installation_id} · @${data.github_org}`,
    };
  } catch {
    return { name:"GitHub App", connected:true, healthy:false, last_check:new Date().toISOString(), error:"Could not reach GitHub API" };
  }
}

async function checkSlack(webhookUrl: string | undefined): Promise<IntegrationStatus> {
  if (!webhookUrl) return { name:"Slack", connected:false, healthy:false, last_check:new Date().toISOString(), details:"No webhook configured" };
  try {
    // Check if URL format is valid (don't send test — might spam channel)
    const valid = webhookUrl.startsWith("https://hooks.slack.com/");
    return { name:"Slack", connected:true, healthy:valid, last_check:new Date().toISOString(), details:valid ? "Webhook URL configured" : "Invalid webhook URL format" };
  } catch {
    return { name:"Slack", connected:false, healthy:false, last_check:new Date().toISOString(), error:"Connection failed" };
  }
}

async function checkSupabase(): Promise<IntegrationStatus> {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
  if (!url) return { name:"Supabase", connected:false, healthy:false, last_check:new Date().toISOString(), details:"Not configured" };
  try {
    const res = await fetch(`${url}/rest/v1/`, { headers: { apikey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "" } });
    return { name:"Supabase Database", connected:true, healthy:res.status < 500, last_check:new Date().toISOString(), details:`${url.split(".")[0].split("//")[1]}...supabase.co` };
  } catch {
    return { name:"Supabase Database", connected:false, healthy:false, last_check:new Date().toISOString(), error:"Cannot reach Supabase" };
  }
}

async function checkStripe(): Promise<IntegrationStatus> {
  const key = process.env.STRIPE_SECRET_KEY ?? "";
  if (!key) return { name:"Stripe", connected:false, healthy:false, last_check:new Date().toISOString(), details:"Not configured" };
  try {
    const { getStripe } = await import("@/lib/stripe");
    const stripe = await getStripe();
    await stripe.balance.retrieve();
    return { name:"Stripe", connected:true, healthy:true, last_check:new Date().toISOString(), details:"Connected" };
  } catch (e) {
    return { name:"Stripe", connected:!!key, healthy:false, last_check:new Date().toISOString(), error:String(e) };
  }
}

async function checkSendGrid(): Promise<IntegrationStatus> {
  const key = process.env.SENDGRID_API_KEY ?? "";
  if (!key) return { name:"SendGrid (Email)", connected:false, healthy:false, last_check:new Date().toISOString(), details:"Not configured" };
  try {
    const res = await fetch("https://api.sendgrid.com/v3/user/account", {
      headers: { Authorization:`Bearer ${key}` },
    });
    return { name:"SendGrid (Email)", connected:true, healthy:res.ok, last_check:new Date().toISOString(), details:res.ok ? "Connected" : `HTTP ${res.status}` };
  } catch {
    return { name:"SendGrid (Email)", connected:!!key, healthy:false, last_check:new Date().toISOString(), error:"Connection failed" };
  }
}

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();

  // Fetch org settings for integration URLs
  const { data: org } = await db
    .from("organizations")
    .select("id, name")
    .eq("id", org_id)
    .single() as { data: { id: string; name: string } | null };

  const slackWebhook = process.env.SLACK_WEBHOOK_URL;

  // Run all checks in parallel
  const [github, slack, supabase, stripe, sendgrid] = await Promise.all([
    checkGitHub(db, org_id),
    checkSlack(slackWebhook),
    checkSupabase(),
    checkStripe(),
    checkSendGrid(),
  ]);

  const all = [github, slack, supabase, stripe, sendgrid];
  const healthyCount = all.filter(i => i.healthy).length;
  const connectedCount = all.filter(i => i.connected).length;

  return NextResponse.json({
    org:             org?.name ?? org_id,
    overall_healthy: healthyCount === all.length,
    summary: { healthy:healthyCount, connected:connectedCount, total:all.length },
    integrations:    all,
    checked_at:      new Date().toISOString(),
  });
}
