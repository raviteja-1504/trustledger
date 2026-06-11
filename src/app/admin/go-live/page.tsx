"use client";
/**
 * Production Go-Live Checklist
 * Accessible at /admin/go-live (requires admin role)
 * Runs automated checks against the current environment.
 */

import { useState, useEffect } from "react";
import AuthGuard from "@/components/AuthGuard";
import { useAuth } from "@/lib/auth";

interface CheckResult {
  id:         string;
  category:   string;
  name:       string;
  status:     "pass" | "fail" | "warn" | "pending" | "skip";
  detail?:    string;
  docsUrl?:   string;
}

const IS_PROD = process.env.NODE_ENV === "production";

function useGoLiveChecks() {
  const [checks, setChecks] = useState<CheckResult[]>([]);
  const [running, setRunning] = useState(false);

  async function runChecks() {
    setRunning(true);

    const results: CheckResult[] = [];

    // ── Infrastructure ──────────────────────────────────────────────────────
    results.push({
      id: "supabase_url",
      category: "Infrastructure",
      name: "Supabase URL configured",
      status: process.env.NEXT_PUBLIC_SUPABASE_URL ? "pass" : "fail",
      detail: process.env.NEXT_PUBLIC_SUPABASE_URL
        ? `Connected to ${process.env.NEXT_PUBLIC_SUPABASE_URL?.split(".")[0]?.split("//")[1]}...`
        : "Set NEXT_PUBLIC_SUPABASE_URL",
    });

    results.push({
      id: "skip_auth",
      category: "Infrastructure",
      name: "Auth enabled (SKIP_AUTH=false)",
      status: process.env.NEXT_PUBLIC_SKIP_AUTH === "true" ? "warn" : "pass",
      detail: process.env.NEXT_PUBLIC_SKIP_AUTH === "true"
        ? "⚠️ NEXT_PUBLIC_SKIP_AUTH=true — disable in production"
        : "Real authentication enabled",
    });

    results.push({
      id: "app_url",
      category: "Infrastructure",
      name: "APP_URL set to production domain",
      status: (() => {
        const url = process.env.NEXT_PUBLIC_APP_URL ?? "";
        if (!url) return "fail";
        if (url.includes("localhost")) return "warn";
        if (url.startsWith("https://")) return "pass";
        return "warn";
      })(),
      detail: `NEXT_PUBLIC_APP_URL=${process.env.NEXT_PUBLIC_APP_URL ?? "(not set)"}`,
    });

    // ── API Health ──────────────────────────────────────────────────────────
    try {
      const r = await fetch("/healthz", { cache: "no-store" });
      const body = await r.json() as { status: string; db: string; latency_ms: number };
      results.push({
        id: "healthz",
        category: "API Health",
        name: "/healthz endpoint responds",
        status: r.ok ? "pass" : "fail",
        detail: `Status: ${body.status}, DB: ${body.db}, Latency: ${body.latency_ms}ms`,
      });
      results.push({
        id: "db_connected",
        category: "API Health",
        name: "Database connected",
        status: body.db === "connected" ? "pass" : "fail",
        detail: body.db === "connected" ? "Supabase PostgreSQL connected" : "Database unreachable",
      });
    } catch (e) {
      results.push({ id:"healthz", category:"API Health", name:"/healthz", status:"fail", detail: String(e) });
    }

    // ── Security ─────────────────────────────────────────────────────────────
    results.push({
      id: "https",
      category: "Security",
      name: "HTTPS in production",
      status: (() => {
        const url = process.env.NEXT_PUBLIC_APP_URL ?? "";
        if (!IS_PROD) return "skip";
        return url.startsWith("https://") ? "pass" : "fail";
      })(),
      detail: IS_PROD ? undefined : "Skipped in dev mode",
    });

    results.push({
      id: "cron_secret",
      category: "Security",
      name: "CRON_SECRET set",
      status: process.env.CRON_SECRET && process.env.CRON_SECRET !== "dev-cron-secret" ? "pass" : "warn",
      detail: !process.env.CRON_SECRET
        ? "Set CRON_SECRET to a random string"
        : process.env.CRON_SECRET === "dev-cron-secret"
          ? "⚠️ Using default dev secret — change for production"
          : "Custom cron secret set",
    });

    results.push({
      id: "github_webhook",
      category: "Security",
      name: "GitHub webhook secret set",
      status: process.env.GITHUB_WEBHOOK_SECRET ? "pass" : "warn",
      detail: process.env.GITHUB_WEBHOOK_SECRET ? "Webhook secret configured" : "Set GITHUB_WEBHOOK_SECRET",
    });

    // ── Features ─────────────────────────────────────────────────────────────
    results.push({
      id: "stripe",
      category: "Features",
      name: "Stripe billing configured",
      status: process.env.STRIPE_SECRET_KEY ? "pass" : "warn",
      detail: process.env.STRIPE_SECRET_KEY ? "Stripe connected" : "Set STRIPE_SECRET_KEY for billing",
    });

    results.push({
      id: "sendgrid",
      category: "Features",
      name: "Email (SendGrid) configured",
      status: process.env.SENDGRID_API_KEY ? "pass" : "warn",
      detail: process.env.SENDGRID_API_KEY ? "Email delivery configured" : "Set SENDGRID_API_KEY for alerts",
    });

    results.push({
      id: "redis",
      category: "Features",
      name: "Rate limiting (Upstash Redis)",
      status: process.env.UPSTASH_REDIS_REST_URL ? "pass" : "warn",
      detail: process.env.UPSTASH_REDIS_REST_URL
        ? "Redis rate limiting active"
        : "Using in-memory fallback — set UPSTASH_REDIS_REST_URL for production",
    });

    results.push({
      id: "sentry",
      category: "Observability",
      name: "Sentry error tracking",
      status: process.env.NEXT_PUBLIC_SENTRY_DSN ? "pass" : "warn",
      detail: process.env.NEXT_PUBLIC_SENTRY_DSN ? "Error tracking active" : "Set NEXT_PUBLIC_SENTRY_DSN",
    });

    results.push({
      id: "posthog",
      category: "Observability",
      name: "PostHog analytics",
      status: process.env.NEXT_PUBLIC_POSTHOG_KEY ? "pass" : "warn",
      detail: process.env.NEXT_PUBLIC_POSTHOG_KEY ? "Analytics active" : "Set NEXT_PUBLIC_POSTHOG_KEY",
    });

    setChecks(results);
    setRunning(false);
  }

  return { checks, running, runChecks };
}

const STATUS_STYLE: Record<string, { bg: string; text: string; icon: string }> = {
  pass:    { bg:"#f0fdf4", text:"#15803d", icon:"✓"  },
  fail:    { bg:"#fff1f2", text:"#be123c", icon:"✗"  },
  warn:    { bg:"#fffbeb", text:"#b45309", icon:"⚠"  },
  pending: { bg:"#f8fafc", text:"#64748b", icon:"○"  },
  skip:    { bg:"#f8fafc", text:"#94a3b8", icon:"—"  },
};

export default function GoLivePage() {
  const { profile } = useAuth();
  const { checks, running, runChecks } = useGoLiveChecks();

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { runChecks(); }, []);

  const passCount    = checks.filter(c => c.status === "pass").length;
  const failCount    = checks.filter(c => c.status === "fail").length;
  const warnCount    = checks.filter(c => c.status === "warn").length;
  const categories   = Array.from(new Set(checks.map(c => c.category)));
  const isReadyToLaunch = failCount === 0;

  return (
    <AuthGuard>
      <div className="max-w-3xl mx-auto space-y-5 pb-10">

        <div className="pt-1">
          <h1 className="text-xl font-black text-gray-900">Production Go-Live Checklist</h1>
          <p className="text-sm text-gray-400 mt-0.5">Automated checks against current environment configuration</p>
        </div>

        {/* Summary */}
        <div className={`rounded-2xl p-5 border-2 ${isReadyToLaunch ? "bg-emerald-50 border-emerald-200" : "bg-rose-50 border-rose-200"}`}>
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div>
              <p className={`text-lg font-black ${isReadyToLaunch ? "text-emerald-800" : "text-rose-800"}`}>
                {running ? "Running checks…" : isReadyToLaunch ? "✅ Ready to launch" : "❌ Issues found — fix before launching"}
              </p>
              <p className="text-sm text-gray-600 mt-0.5">
                {passCount} passed · {failCount} failed · {warnCount} warnings
              </p>
            </div>
            <button onClick={runChecks} disabled={running}
              className="px-5 py-2 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-60 transition-colors">
              {running ? "Checking…" : "Re-run checks"}
            </button>
          </div>
        </div>

        {/* Checks by category */}
        {categories.map(cat => (
          <div key={cat} className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-100 bg-gray-50">
              <p className="text-xs font-black text-gray-700 uppercase tracking-wider">{cat}</p>
            </div>
            <div className="divide-y divide-gray-50">
              {checks.filter(c => c.category === cat).map(c => {
                const s = STATUS_STYLE[c.status] ?? STATUS_STYLE.pending;
                return (
                  <div key={c.id} className="flex items-start gap-4 px-5 py-3.5">
                    <span className="text-base shrink-0 mt-0.5 font-black"
                      style={{ color: s.text }}>{s.icon}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-semibold text-gray-900">{c.name}</p>
                      {c.detail && <p className="text-xs text-gray-500 mt-0.5">{c.detail}</p>}
                    </div>
                    <span className="text-[10px] font-bold px-2.5 py-1 rounded-full shrink-0"
                      style={{ background: s.bg, color: s.text }}>
                      {c.status.toUpperCase()}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        ))}

        {checks.length === 0 && !running && (
          <div className="text-center py-12 text-gray-400">
            <p className="text-sm">Click "Re-run checks" to start</p>
          </div>
        )}

      </div>
    </AuthGuard>
  );
}
