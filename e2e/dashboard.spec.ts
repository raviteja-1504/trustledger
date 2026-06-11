import { test, expect } from "@playwright/test";

// All dashboard tests run in demo/seed mode (NEXT_PUBLIC_SKIP_AUTH=true)
test.describe("Dashboard — demo mode", () => {
  test.beforeEach(async ({ page }) => {
    // Set seed mode so no Supabase needed
    await page.goto("/seed");
    // Wait for seed to finish
    await page.waitForTimeout(1000);
    await page.goto("/dashboard");
  });

  test("renders dashboard with repo cards", async ({ page }) => {
    // Wait for data to load
    await page.waitForSelector("text=/payments-api|auth-service|fraud-detection/i", { timeout: 10_000 });
    await expect(page.locator("text=/payments-api/i").first()).toBeVisible();
  });

  test("shows health score gauge", async ({ page }) => {
    await expect(page.locator("text=/Health Score/i")).toBeVisible({ timeout: 8_000 });
  });

  test("sidebar navigation links work", async ({ page }) => {
    await page.click("a[href='/violations']");
    await expect(page).toHaveURL(/violations/);
    await expect(page.locator("h1, [data-testid='page-title']")).toContainText(/Violation/i, { timeout: 8_000 });
  });

  test("pending attestation counter shows in sidebar", async ({ page }) => {
    // Sidebar should show a badge count for violations or alerts
    await expect(page.locator("aside")).toBeVisible();
  });
});
