/**
 * @jest-environment node
 *
 * The Stripe SDK's default HTTP client requires a global fetch implementation
 * that jsdom (this project's default test environment) doesn't provide.
 * Node's environment has native fetch (stable since Node 18/20).
 */
import { verifyStripeWebhook, getStripe } from "@/lib/stripe";

describe("getStripe", () => {
  const originalKey = process.env.STRIPE_SECRET_KEY;
  afterEach(() => { process.env.STRIPE_SECRET_KEY = originalKey; });

  it("throws when STRIPE_SECRET_KEY is not configured", () => {
    delete process.env.STRIPE_SECRET_KEY;
    // getStripe() throws synchronously before ever returning a promise.
    expect(() => getStripe()).toThrow("STRIPE_SECRET_KEY not configured");
  });
});

describe("verifyStripeWebhook", () => {
  const originalSecret = process.env.STRIPE_WEBHOOK_SECRET;
  const originalKey    = process.env.STRIPE_SECRET_KEY;

  beforeAll(() => {
    // constructEvent() only needs a key to instantiate the Stripe client —
    // it never makes a network call to verify a webhook signature.
    process.env.STRIPE_SECRET_KEY = "sk_test_fake_for_unit_tests";
  });
  afterAll(() => {
    process.env.STRIPE_WEBHOOK_SECRET = originalSecret;
    process.env.STRIPE_SECRET_KEY     = originalKey;
  });

  it("throws when STRIPE_WEBHOOK_SECRET is not configured", async () => {
    delete process.env.STRIPE_WEBHOOK_SECRET;
    await expect(verifyStripeWebhook("{}", "t=1,v1=fake")).rejects.toThrow("STRIPE_WEBHOOK_SECRET not configured");
  });

  it("rejects a payload whose signature does not match the configured secret", async () => {
    // This is the actual security boundary: without this check, anyone could
    // POST a fabricated event (e.g. "checkout.session.completed") to the
    // webhook endpoint and get free access provisioned.
    process.env.STRIPE_WEBHOOK_SECRET = "whsec_test_secret";
    await expect(
      verifyStripeWebhook('{"type":"checkout.session.completed"}', "t=1,v1=not_a_real_signature")
    ).rejects.toThrow(/signature/i);
  });

  it("rejects a validly-signed payload if it's been re-signed under a different secret", async () => {
    // Guards against a signature computed with a leaked/old secret being
    // accepted after the secret has been rotated.
    const StripeModule = (await import("stripe")).default;
    const stripe = new StripeModule("sk_test_fake_for_unit_tests", { apiVersion: "2026-05-27.dahlia" });
    const payload = JSON.stringify({ type: "checkout.session.completed" });
    const header  = stripe.webhooks.generateTestHeaderString({
      payload,
      secret: "whsec_the_wrong_secret",
    });

    process.env.STRIPE_WEBHOOK_SECRET = "whsec_the_correct_secret";
    await expect(verifyStripeWebhook(payload, header)).rejects.toThrow(/signature/i);
  });

  it("accepts a payload correctly signed with the configured secret", async () => {
    const StripeModule = (await import("stripe")).default;
    const stripe = new StripeModule("sk_test_fake_for_unit_tests", { apiVersion: "2026-05-27.dahlia" });
    const payload = JSON.stringify({ type: "checkout.session.completed", id: "evt_test" });
    const secret  = "whsec_matching_secret";
    const header  = stripe.webhooks.generateTestHeaderString({ payload, secret });

    process.env.STRIPE_WEBHOOK_SECRET = secret;
    const event = await verifyStripeWebhook(payload, header);
    expect(event.type).toBe("checkout.session.completed");
  });
});
