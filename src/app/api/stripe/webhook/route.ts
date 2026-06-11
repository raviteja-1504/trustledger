/**
 * Stripe Webhook Handler
 * Processes subscription lifecycle events to keep org plan in sync.
 *
 * Events handled:
 *   checkout.session.completed      → activate trial / new subscription
 *   customer.subscription.updated   → plan change / renewal
 *   customer.subscription.deleted   → downgrade to trial on cancellation
 *   invoice.payment_failed          → notify admins, flag account
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyStripeWebhook, PLAN_NAMES } from "@/lib/stripe";
import { writeAuditLog } from "@/lib/audit";
import { sendEmailAlert } from "@/lib/alertDelivery";
import type Stripe from "stripe";

// Next.js App Router route handlers receive raw body via req.text() — no config needed

export async function POST(req: NextRequest) {
  const rawBody  = await req.text();
  const sig      = req.headers.get("stripe-signature") ?? "";

  let event: Stripe.Event;
  try {
    event = await verifyStripeWebhook(rawBody, sig);
  } catch (e) {
    console.error("Stripe webhook signature invalid:", e);
    return NextResponse.json({ error: "invalid_signature" }, { status: 400 });
  }

  const db     = createServiceClient();
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

  async function getOrgId(metadata?: Stripe.Metadata | null): Promise<string | null> {
    return metadata?.org_id ?? null;
  }

  async function updateOrgPlan(orgId: string, plan: string) {
    await db.from("organizations").update({ plan }).eq("id", orgId);
  }

  async function notifyAdmins(orgId: string, subject: string, body: string) {
    const { data: admins } = await db
      .from("org_members")
      .select("email")
      .eq("org_id", orgId)
      .eq("role", "admin") as { data: { email: string }[] | null };

    const emails = (admins ?? []).map(a => a.email).filter(Boolean);
    const sendgrid = process.env.SENDGRID_API_KEY ?? "";
    const { data: org } = await db
      .from("organizations")
      .select("name")
      .eq("id", orgId)
      .single() as { data: { name: string } | null };

    if (sendgrid && emails.length > 0) {
      await sendEmailAlert(sendgrid, process.env.ALERT_FROM_EMAIL ?? "billing@trustledger.dev", emails, {
        alert_id: `billing-${Date.now()}`,
        severity: "P3",
        title:    subject,
        body,
        org_name: org?.name ?? orgId,
        app_url:  appUrl,
      });
    }
  }

  try {
    switch (event.type) {

      // ── New subscription / trial activated ────────────────────────────────
      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        const orgId   = await getOrgId(session.metadata);
        if (!orgId) break;

        const plan = session.metadata?.plan ?? "starter";
        await updateOrgPlan(orgId, plan);
        await writeAuditLog(db, {
          org_id:      orgId,
          event_type:  "org_settings_changed",
          actor_email: "stripe-webhook",
          resource_type: "subscription",
          resource_id:   session.subscription as string,
          payload: { event: "checkout_completed", plan, session_id: session.id },
        });
        await notifyAdmins(orgId,
          `🎉 TrustLedger ${plan} plan activated`,
          `Your 14-day free trial for the ${plan} plan is now active. You'll be charged at the end of the trial period.`
        );
        break;
      }

      // ── Subscription updated (plan change / renewal) ──────────────────────
      case "customer.subscription.updated": {
        const sub   = event.data.object as Stripe.Subscription;
        const orgId = await getOrgId(sub.metadata);
        if (!orgId) break;

        // Determine new plan from price ID
        const priceId = sub.items.data[0]?.price.id ?? "";
        const plan    = PLAN_NAMES[priceId] ?? sub.metadata?.plan ?? "starter";
        await updateOrgPlan(orgId, plan);
        await writeAuditLog(db, {
          org_id:      orgId,
          event_type:  "org_settings_changed",
          actor_email: "stripe-webhook",
          resource_type: "subscription",
          resource_id:   sub.id,
          payload: { event: "subscription_updated", plan, status: sub.status },
        });
        break;
      }

      // ── Subscription cancelled → downgrade to trial ───────────────────────
      case "customer.subscription.deleted": {
        const sub   = event.data.object as Stripe.Subscription;
        const orgId = await getOrgId(sub.metadata);
        if (!orgId) break;

        await updateOrgPlan(orgId, "trial");
        await writeAuditLog(db, {
          org_id:      orgId,
          event_type:  "org_settings_changed",
          actor_email: "stripe-webhook",
          resource_type: "subscription",
          resource_id:   sub.id,
          payload: { event: "subscription_cancelled" },
        });
        await notifyAdmins(orgId,
          "TrustLedger subscription cancelled",
          "Your subscription has been cancelled. Your account has been downgraded to the trial plan (100 scans/month). Upgrade at any time to restore full access."
        );
        break;
      }

      // ── Payment failed ────────────────────────────────────────────────────
      case "invoice.payment_failed": {
        const invoice = event.data.object as Stripe.Invoice & { subscription?: string | null };
        const sub     = typeof invoice.subscription === "string" ? invoice.subscription : null;
        if (!sub) break;

        const stripe     = await import("@/lib/stripe").then(m => m.getStripe());
        const subObj     = await (await stripe).subscriptions.retrieve(sub);
        const orgId      = await getOrgId(subObj.metadata);
        if (!orgId) break;

        await notifyAdmins(orgId,
          "⚠️ Payment failed — action required",
          `Your TrustLedger payment of ${((invoice.amount_due ?? 0) / 100).toFixed(2)} ${(invoice.currency ?? "usd").toUpperCase()} failed. Please update your payment method to avoid service interruption.`
        );
        break;
      }
    }
  } catch (err) {
    console.error("Stripe webhook processing error:", err);
    // Return 200 to prevent Stripe from retrying — log the error
    return NextResponse.json({ ok: true, warning: String(err) });
  }

  return NextResponse.json({ ok: true, event: event.type });
}
