import { test, expect } from "@playwright/test";

test.describe("Compliance pages", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/seed");
    await page.waitForTimeout(500);
  });

  test("compliance page loads with framework tabs", async ({ page }) => {
    await page.goto("/compliance");
    await expect(page.locator("text=/SOC 2|PCI-DSS|EU AI/i").first()).toBeVisible({ timeout: 8_000 });
  });

  test("compliance calendar shows upcoming events", async ({ page }) => {
    await page.goto("/compliance-calendar");
    await expect(page.locator("text=/Audit|Deadline|Review/i").first()).toBeVisible({ timeout: 8_000 });
  });

  test("compliance calendar add event works", async ({ page }) => {
    await page.goto("/compliance-calendar");
    await page.click("button:has-text('+ Add event')");
    await expect(page.locator("text=Add compliance event")).toBeVisible({ timeout: 5_000 });
  });

  test("evidence page loads control objectives", async ({ page }) => {
    await page.goto("/evidence");
    await expect(page.locator("text=/SOC 2|Evidence|Collect/i").first()).toBeVisible({ timeout: 8_000 });
  });

  test("reports page loads with framework selection", async ({ page }) => {
    await page.goto("/reports");
    await expect(page.locator("text=/SOC 2|Report|Attestation/i").first()).toBeVisible({ timeout: 8_000 });
  });
});
