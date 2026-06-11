/**
 * Stripe Checkout + Portal API
 * POST /api/stripe         → create checkout session (new subscription)
 * POST /api/stripe?portal  → create customer portal session (manage/cancel)
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { getStripe, STRIPE_PRICES } from "@/lib/stripe";
import { writeAuditLog } from "@/lib/audit";

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url    = new URL(req.url);
  const portal = url.searchParams.get("portal") === "1";

  const db     = createServiceClient();
  const stripe = await getStripe();
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

  // Fetch org + existing Stripe customer ID
  const { data: org } = await db
    .from("organizations")
    .select("id, name, slug, plan")
    .eq("id", org_id)
    .single() as { data: { id: string; name: string; slug: string; plan: string } | null };

  if (!org) return NextResponse.json({ error: "org_not_found" }, { status: 404 });

  // Look up existing Stripe customer in metadata
  const { data: meta } = await db
    .from("org_members")
    .select("email")
    .eq("user_id", user_id ?? "")
    .eq("org_id", org_id)
    .single() as { data: { email: string } | null };

  // Find or create Stripe customer
  let customerId: string | null = null;
  const existing = await stripe.customers.search({
    query: `metadata["org_id"]:"${org_id}"`,
    limit: 1,
  });
  if (existing.data.length > 0) {
    customerId = existing.data[0].id;
  } else {
    const customer = await stripe.customers.create({
      email:    meta?.email ?? actor_email ?? "",
      name:     org.name,
      metadata: { org_id, org_slug: org.slug },
    });
    customerId = customer.id;
  }

  // ── Customer portal (manage existing subscription) ────────────────────────
  if (portal) {
    const session = await stripe.billingPortal.sessions.create({
      customer:   customerId,
      return_url: `${appUrl}/billing`,
    });
    return NextResponse.json({ url: session.url });
  }

  // ── Checkout session (new/upgrade subscription) ───────────────────────────
  const body = await req.json() as {
    plan:    string;   // "starter" | "growth"
    billing: string;   // "monthly" | "annual"
  };

  if (!body.plan || !body.billing) {
    return NextResponse.json({ error: "missing_fields" }, { status: 400 });
  }

  const priceId = STRIPE_PRICES[body.plan]?.[body.billing as "monthly" | "annual"];
  if (!priceId) {
    return NextResponse.json({ error: "price_not_configured", hint: "Set STRIPE_PRICE_* env vars" }, { status: 422 });
  }

  const session = await stripe.checkout.sessions.create({
    customer:             customerId,
    payment_method_types: ["card"],
    mode:                 "subscription",
    line_items:           [{ price: priceId, quantity: 1 }],
    subscription_data: {
      metadata:         { org_id, plan: body.plan },
      trial_period_days: 14,
    },
    success_url: `${appUrl}/billing?upgraded=1&session_id={CHECKOUT_SESSION_ID}`,
    cancel_url:  `${appUrl}/billing?cancelled=1`,
    metadata:    { org_id, plan: body.plan, billing: body.billing },
    allow_promotion_codes: true,
  });

  await writeAuditLog(db, {
    org_id,
    event_type:    "org_settings_changed",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "subscription",
    resource_id:   session.id,
    payload: { action: "checkout_started", plan: body.plan, billing: body.billing },
  });

  return NextResponse.json({ url: session.url, session_id: session.id });
}
