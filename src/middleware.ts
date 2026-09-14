/**
 * Next.js Edge Middleware
 * - Protects all dashboard routes — redirects unauthenticated users to /login
 * - Skips protection when NEXT_PUBLIC_SKIP_AUTH=true (demo / dev mode)
 * - API routes are protected by the _middleware.ts verifyApiKey helper instead
 */

import { NextResponse, type NextRequest } from "next/server";
import { createClient } from "@supabase/supabase-js";
import { checkRateLimit } from "@/lib/rateLimit";

const SKIP_AUTH  = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";
const IS_PROD    = process.env.NODE_ENV === "production";

const PUBLIC_PATHS = new Set(["/login", "/auth/callback", "/api/webhook", "/changelog", "/docs", "/status", "/healthz", "/privacy", "/terms"]);

// Routes blocked in production (dev/seed tools)
const DEV_ONLY_PATHS = new Set(["/seed", "/dev-seed"]);

// Max request body size for API routes (10MB)
const MAX_BODY_BYTES = 10 * 1024 * 1024;

// Blanket per-IP rate limit applied to every API route here in the edge
// middleware, rather than relying on each route to opt in individually.
// Routes that need a tighter, endpoint-specific limit (scans, attest, key
// creation, webhooks, etc.) layer their own checkRateLimit() call on top of
// this -- this is just the floor every route gets for free.
// Webhooks are excluded: they're driven by the source platform's own
// infrastructure (GitHub/GitLab/Bitbucket shared egress IPs), already have
// per-installation/per-repo limits in their handlers, and a global per-IP
// cap here would risk throttling legitimate delivery traffic from a shared IP.
const GLOBAL_API_LIMIT = { limit: 300, windowMs: 60_000, prefix: "global" };

function isRateLimitExempt(pathname: string): boolean {
  return pathname.startsWith("/api/webhook")
    || pathname.startsWith("/api/health")
    || pathname === "/healthz"
    || pathname.startsWith("/api/docs")
    || pathname === "/api/scan-worker"; // internal, called by QStash/self, not user-facing
}

function isPublic(pathname: string): boolean {
  if (PUBLIC_PATHS.has(pathname))              return true;
  if (pathname.startsWith("/api/webhook/"))    return true;
  if (pathname.startsWith("/api/docs"))        return true;
  if (pathname.startsWith("/api/health"))      return true;
  if (pathname.startsWith("/_next/"))          return true;
  if (pathname.startsWith("/static/"))         return true;
  if (pathname === "/favicon.ico")             return true;
  if (pathname === "/")                        return true;
  if (pathname === "/onboarding")              return true;
  if (pathname === "/create-org")              return true;
  return false;
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Block dev-only routes in production
  if (IS_PROD && DEV_ONLY_PATHS.has(pathname)) {
    return NextResponse.json({ error: "not_available_in_production" }, { status: 404 });
  }

  // Block oversized requests to API routes
  if (pathname.startsWith("/api/") && !pathname.startsWith("/api/webhook/")) {
    const contentLength = parseInt(req.headers.get("content-length") ?? "0");
    if (contentLength > MAX_BODY_BYTES) {
      return NextResponse.json({ error: "request_too_large", max_bytes: MAX_BODY_BYTES }, { status: 413 });
    }
  }

  // Demo / dev mode — no auth required
  if (SKIP_AUTH) {
    const res = NextResponse.next();
    addSecurityHeaders(res, pathname);
    return res;
  }

  // Public paths — always allow (but still add security headers)
  if (isPublic(pathname)) {
    const res = NextResponse.next();
    addSecurityHeaders(res, pathname);
    return res;
  }

  // API routes handle their own auth, but get a blanket per-IP rate limit here
  // so no route can accidentally ship without one.
  if (pathname.startsWith("/api/")) {
    if (!isRateLimitExempt(pathname)) {
      const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
        ?? req.headers.get("x-real-ip")
        ?? "unknown";
      const rl = await checkRateLimit(ip, GLOBAL_API_LIMIT);
      if (!rl.success) {
        return NextResponse.json(
          { error: "too_many_requests", detail: "Global rate limit exceeded. Slow down." },
          { status: 429, headers: rl.headers },
        );
      }
    }
    return NextResponse.next();
  }

  // Check Supabase session from cookie
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
  const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "";

  if (!supabaseUrl || !supabaseKey) {
    // Supabase not configured — allow through
    return NextResponse.next();
  }

  // Read auth token from cookies
  const authCookie = req.cookies.get(`sb-${new URL(supabaseUrl).hostname.split(".")[0]}-auth-token`);

  if (!authCookie?.value) {
    // Not authenticated — redirect to login
    const loginUrl = new URL("/login", req.url);
    loginUrl.searchParams.set("next", pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Validate the token
  try {
    const supabase = createClient(supabaseUrl, supabaseKey, {
      auth: { persistSession: false },
    });
    const { data: { user } } = await supabase.auth.getUser(
      JSON.parse(authCookie.value).access_token,
    );
    if (!user) {
      const loginUrl = new URL("/login", req.url);
      loginUrl.searchParams.set("next", pathname);
      return NextResponse.redirect(loginUrl);
    }
  } catch {
    // Token parse error — redirect to login
    const loginUrl = new URL("/login", req.url);
    return NextResponse.redirect(loginUrl);
  }

  const response = NextResponse.next();
  addSecurityHeaders(response, pathname);
  return response;
}

function addSecurityHeaders(res: NextResponse, pathname: string): void {
  // In development, Next.js webpack HMR requires 'unsafe-eval' for hot-reload scripts.
  // Never apply strict CSP in dev — it blocks the entire app from loading.
  if (!IS_PROD) {
    res.headers.set("X-Content-Type-Options", "nosniff");
    return;
  }

  // Content Security Policy (production only)
  // /docs page loads Swagger UI from unpkg — needs unsafe-eval for its bundle
  const isDocsPage = pathname === "/docs" || pathname.startsWith("/api/docs");
  const scriptSrc  = isDocsPage
    ? "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://unpkg.com"
    : "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net";
  const csp = [
    "default-src 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' https://unpkg.com",
    "img-src 'self' data: https: blob:",
    "font-src 'self' data:",
    "connect-src 'self' https://*.supabase.co wss://*.supabase.co https://api.github.com https://api.sendgrid.com https://api.linear.app https://posthog.com https://eu.posthog.com https://*.sentry.io https://registry.npmjs.org",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self' https://github.com https://*.github.com",
  ].join("; ");

  res.headers.set("Content-Security-Policy",          csp);
  res.headers.set("X-Content-Type-Options",           "nosniff");
  res.headers.set("X-Frame-Options",                  "DENY");
  res.headers.set("X-XSS-Protection",                 "1; mode=block");
  res.headers.set("Referrer-Policy",                  "strict-origin-when-cross-origin");
  res.headers.set("Permissions-Policy",               "camera=(), microphone=(), geolocation=(), payment=()");
  res.headers.set("Strict-Transport-Security",        "max-age=63072000; includeSubDomains; preload");
  res.headers.set("Cross-Origin-Opener-Policy",       "same-origin");
  res.headers.set("Cross-Origin-Resource-Policy",     "same-origin");
  res.headers.set("Cross-Origin-Embedder-Policy",     "require-corp");

  // API routes — add CORS for SDK usage
  if (pathname.startsWith("/api/")) {
    res.headers.set("Access-Control-Allow-Origin",      process.env.NEXT_PUBLIC_APP_URL ?? "*");
    res.headers.set("Access-Control-Allow-Methods",     "GET, POST, PATCH, DELETE, OPTIONS");
    res.headers.set("Access-Control-Allow-Headers",     "Content-Type, Authorization, X-TrustLedger-Key, X-Gitlab-Token, X-Hub-Signature-256");
    res.headers.set("Access-Control-Max-Age",           "86400");
  }
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization)
     * - favicon.ico
     */
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
