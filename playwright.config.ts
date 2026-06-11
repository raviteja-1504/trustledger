import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir:          "./e2e",
  fullyParallel:    true,
  forbidOnly:       !!process.env.CI,
  retries:          process.env.CI ? 2 : 0,
  workers:          process.env.CI ? 1 : undefined,
  reporter:         process.env.CI ? "github" : [["html", { open: "never" }], ["list"]],

  use: {
    baseURL:      process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:3000",
    trace:        "on-first-retry",
    screenshot:   "only-on-failure",
    video:        "retain-on-failure",
    // Demo mode env so tests run without real Supabase
    extraHTTPHeaders: { "X-Test-Mode": "1" },
  },

  projects: [
    {
      name:    "chromium",
      use:     { ...devices["Desktop Chrome"] },
    },
    {
      name:    "firefox",
      use:     { ...devices["Desktop Firefox"] },
    },
    {
      name:    "Mobile Safari",
      use:     { ...devices["iPhone 14"] },
    },
  ],

  // Start the dev server if not already running
  webServer: {
    command:   "npm run dev",
    url:       "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
    timeout:   60_000,
    env: {
      NEXT_PUBLIC_SKIP_AUTH: "true",
      NEXT_PUBLIC_ORG:       "test-org",
    },
  },
});
