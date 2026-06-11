/**
 * Stripe integration for TrustLedger billing.
 * Handles subscription creation, upgrades, portal sessions, and webhook events.
 */

// ── Plan → Stripe Price ID mapping ────────────────────────────────────────────
// Set these in your .env after creating products in Stripe Dashboard
export const STRIPE_PRICES: Record<string, { monthly: string; annual: string }> = {
  starter: {
    monthly: process.env.STRIPE_PRICE_STARTER_MONTHLY ?? "",
    annual:  process.env.STRIPE_PRICE_STARTER_ANNUAL  ?? "",
  },
  growth: {
    monthly: process.env.STRIPE_PRICE_GROWTH_MONTHLY ?? "",
    annual:  process.env.STRIPE_PRICE_GROWTH_ANNUAL  ?? "",
  },
};

export const PLAN_NAMES: Record<string, string> = {
  [process.env.STRIPE_PRICE_STARTER_MONTHLY ?? "starter_monthly"]: "starter",
  [process.env.STRIPE_PRICE_STARTER_ANNUAL  ?? "starter_annual"]:  "starter",
  [process.env.STRIPE_PRICE_GROWTH_MONTHLY  ?? "growth_monthly"]:  "growth",
  [process.env.STRIPE_PRICE_GROWTH_ANNUAL   ?? "growth_annual"]:   "growth",
};

// ── Stripe client (server-side only) ─────────────────────────────────────────
export function getStripe() {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error("STRIPE_SECRET_KEY not configured");
  // Dynamic import so Stripe SDK is never bundled client-side
  return import("stripe").then(({ default: Stripe }) => new Stripe(key, { apiVersion: "2026-05-27.dahlia" }));
}

// ── Webhook signature verification ───────────────────────────────────────────
export async function verifyStripeWebhook(
  rawBody: string,
  signature: string,
): Promise<import("stripe").Stripe.Event> {
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) throw new Error("STRIPE_WEBHOOK_SECRET not configured");
  const stripe = await getStripe();
  return stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);
}
