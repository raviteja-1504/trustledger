import { test, expect } from "@playwright/test";

test.describe("Landing page", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
  });

  test("renders hero section with correct headline", async ({ page }) => {
    await expect(page.locator("h1").first()).toBeVisible();
    const h1Text = await page.locator("h1").first().textContent();
    expect(h1Text).toMatch(/AI|Code|TrustLedger/i);
  });

  test("shows pricing section with three plans", async ({ page }) => {
    await page.click("text=Pricing");
    const plans = page.locator("text=/Starter|Growth|Enterprise/");
    await expect(plans.first()).toBeVisible();
  });

  test("has working Get started CTA that goes to login", async ({ page }) => {
    const cta = page.locator("a[href='/login']").first();
    await expect(cta).toBeVisible();
  });

  test("nav links render", async ({ page }) => {
    await expect(page.locator("text=Sign in")).toBeVisible();
  });
});
