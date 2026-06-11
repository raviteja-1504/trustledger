/**
 * Environment variable validation.
 * Validates required env vars at startup and provides typed accessors.
 * Call validateEnv() in instrumentation.ts (Next.js 13 server startup hook).
 */

export interface EnvConfig {
  // Supabase
  supabaseUrl:      string;
  supabaseAnonKey:  string;
  supabaseServiceKey: string;

  // App
  appUrl:           string;
  orgSlug:          string;
  skipAuth:         boolean;

  // GitHub App (optional in dev)
  githubAppId?:     string;
  githubWebhookSecret?: string;

  // Cron
  cronSecret:       string;
}

export type EnvError = { missing: string[]; invalid: string[] };

/** Validate all required environment variables. Returns errors or null if valid. */
export function checkEnv(): EnvError | null {
  const missing: string[]  = [];
  const invalid: string[]  = [];
  const isDemo = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";

  // Always required
  if (!process.env.NEXT_PUBLIC_APP_URL) missing.push("NEXT_PUBLIC_APP_URL");

  // Required in production
  if (!isDemo) {
    if (!process.env.NEXT_PUBLIC_SUPABASE_URL)        missing.push("NEXT_PUBLIC_SUPABASE_URL");
    if (!process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)   missing.push("NEXT_PUBLIC_SUPABASE_ANON_KEY");
    if (!process.env.SUPABASE_SERVICE_ROLE_KEY)        missing.push("SUPABASE_SERVICE_ROLE_KEY");
    if (!process.env.CRON_SECRET)                      missing.push("CRON_SECRET");
  }

  // Validate URL formats
  if (process.env.NEXT_PUBLIC_SUPABASE_URL &&
      !process.env.NEXT_PUBLIC_SUPABASE_URL.startsWith("https://")) {
    invalid.push("NEXT_PUBLIC_SUPABASE_URL must start with https://");
  }
  if (process.env.NEXT_PUBLIC_APP_URL &&
      !process.env.NEXT_PUBLIC_APP_URL.startsWith("http")) {
    invalid.push("NEXT_PUBLIC_APP_URL must start with http:// or https://");
  }

  if (missing.length === 0 && invalid.length === 0) return null;
  return { missing, invalid };
}

/** Print a clear startup error and optionally throw in production. */
export function validateEnv(): void {
  // Hard block: server must not start with auth disabled in production
  if (process.env.NODE_ENV === "production" && process.env.NEXT_PUBLIC_SKIP_AUTH === "true") {
    throw new Error(
      "NEXT_PUBLIC_SKIP_AUTH=true in a production environment. " +
      "This grants admin access to every visitor. Set it to false or remove it."
    );
  }

  const errors = checkEnv();
  if (!errors) return;

  const lines = [
    "═══════════════════════════════════════════════════",
    "  TrustLedger — Missing environment variables",
    "═══════════════════════════════════════════════════",
    "",
    ...errors.missing.map(v => `  ✗ MISSING:  ${v}`),
    ...errors.invalid.map(v => `  ✗ INVALID:  ${v}`),
    "",
    "  Copy .env.example → .env.local and fill in values.",
    "  Docs: https://docs.trustledger.dev/self-hosted",
    "═══════════════════════════════════════════════════",
  ];

  console.error(lines.join("\n"));

  // In production, throw to prevent the app from starting with bad config
  if (process.env.NODE_ENV === "production") {
    const parts = [
      errors.missing.length  ? `Missing: ${errors.missing.join(", ")}`  : "",
      errors.invalid.length  ? `Invalid: ${errors.invalid.join("; ")}`  : "",
    ].filter(Boolean);
    throw new Error(parts.join(" | "));
  }
}

/** Typed accessor — throws if Supabase not configured. */
export function requireSupabaseConfig(): { url: string; anonKey: string; serviceKey: string } {
  const url        = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey    = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !anonKey || !serviceKey) {
    throw new Error("Supabase not configured. Set NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY.");
  }

  return { url, anonKey, serviceKey };
}
