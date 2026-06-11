import { test, expect } from "@playwright/test";

test.describe("Scan → Attest flow", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/seed");
    await page.waitForTimeout(800);
  });

  test("PR review page loads for seed scan", async ({ page }) => {
    await page.goto("/pr/sc_mock_001");
    await expect(page.locator("text=/card_validator|stripe_client/i")).toBeVisible({ timeout: 10_000 });
  });

  test("shows file list with risk badges", async ({ page }) => {
    await page.goto("/pr/sc_mock_001");
    await expect(page.locator("text=/CRITICAL/i").first()).toBeVisible({ timeout: 8_000 });
  });

  test("expand file to see source code", async ({ page }) => {
    await page.goto("/pr/sc_mock_001");
    // Click a file row to expand
    const firstFile = page.locator("tr").nth(1);
    if (await firstFile.isVisible()) {
      await firstFile.click();
      // Should show source code viewer or signals
      await expect(page.locator("text=/AI Content|Source Code|Risk/i").first()).toBeVisible({ timeout: 5_000 });
    }
  });

  test("Attest button is present for unattested files", async ({ page }) => {
    await page.goto("/pr/sc_mock_001");
    await expect(page.locator("button:has-text('Attest')").first()).toBeVisible({ timeout: 8_000 });
  });
});
