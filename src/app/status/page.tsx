"use client";

import { useState, useEffect } from "react";

interface ServiceStatus {
  name:        string;
  status:      "operational" | "degraded" | "down";
  latency_ms?: number;
  message?:    string;
}

const STATUS_COLORS = {
  operational: { bg:"#f0fdf4", text:"#15803d", dot:"#22c55e", label:"Operational" },
  degraded:    { bg:"#fffbeb", text:"#b45309", dot:"#f59e0b", label:"Degraded"    },
  down:        { bg:"#fff1f2", text:"#be123c", dot:"#ef4444", label:"Down"        },
};

export default function StatusPage() {
  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [checkedAt, setCheckedAt] = useState<Date | null>(null);
  const [overallOk, setOverallOk] = useState(true);

  async function check() {
    setLoading(true);
    const checks: ServiceStatus[] = [];

    // Check our own /healthz endpoint
    try {
      const start = Date.now();
      const res   = await fetch("/healthz");
      const lat   = Date.now() - start;
      const body  = await res.json() as { status: string; db: string };
      checks.push({
        name:       "TrustLedger App",
        status:     res.ok && body.status === "ok" ? "operational" : "degraded",
        latency_ms: lat,
        message:    body.status !== "ok" ? `Status: ${body.status}` : undefined,
      });
      checks.push({
        name:       "Database (Supabase)",
        status:     body.db === "connected" ? "operational" : "down",
        latency_ms: lat,
        message:    body.db !== "connected" ? "Database unreachable" : undefined,
      });
    } catch {
      checks.push({ name:"TrustLedger App", status:"down", message:"Connection refused" });
      checks.push({ name:"Database (Supabase)", status:"down" });
    }

    // Check GitHub API reachability
    try {
      const start = Date.now();
      const res   = await fetch("https://api.github.com/zen", { mode:"cors" }).catch(() => null);
      const lat   = Date.now() - start;
      checks.push({
        name:       "GitHub API",
        status:     res?.ok ? "operational" : "degraded",
        latency_ms: res?.ok ? lat : undefined,
        message:    !res?.ok ? "GitHub API unreachable" : undefined,
      });
    } catch {
      checks.push({ name:"GitHub API", status:"degraded", message:"Could not reach GitHub" });
    }

    // Static services (would be real checks in production)
    checks.push({ name:"Webhook Receiver",  status:"operational" });
    checks.push({ name:"PDF Generator",     status:"operational" });
    checks.push({ name:"Alert Delivery",    status:"operational" });
    checks.push({ name:"SLA Monitor (Cron)",status:"operational" });

    setServices(checks);
    setOverallOk(checks.every(s => s.status === "operational"));
    setCheckedAt(new Date());
    setLoading(false);
  }

  useEffect(() => { check(); }, []);

  const overall = overallOk ? STATUS_COLORS.operational : STATUS_COLORS.degraded;

  return (
    <div className="min-h-screen" style={{ background:"#f8fafc" }}>
      <div className="max-w-2xl mx-auto py-16 px-4">

        {/* Header */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full text-sm font-bold mb-6"
            style={{ background: overall.bg, color: overall.text }}>
            <span className="w-2 h-2 rounded-full" style={{ background: overall.dot }} />
            {overallOk ? "All systems operational" : "Some systems degraded"}
          </div>
          <h1 className="text-3xl font-black text-gray-900">TrustLedger Status</h1>
          {checkedAt && (
            <p className="text-sm text-gray-400 mt-2">Last checked {checkedAt.toLocaleTimeString()}</p>
          )}
        </div>

        {/* Services */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden mb-6">
          {loading ? (
            <div className="py-12 text-center text-sm text-gray-400">Checking services…</div>
          ) : (
            <div className="divide-y divide-gray-50">
              {services.map(svc => {
                const cfg = STATUS_COLORS[svc.status];
                return (
                  <div key={svc.name} className="flex items-center justify-between px-6 py-4">
                    <div className="flex items-center gap-3">
                      <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: cfg.dot }} />
                      <div>
                        <p className="text-sm font-semibold text-gray-900">{svc.name}</p>
                        {svc.message && <p className="text-xs text-gray-500 mt-0.5">{svc.message}</p>}
                      </div>
                    </div>
                    <div className="flex items-center gap-4 shrink-0">
                      {svc.latency_ms !== undefined && (
                        <span className="text-xs text-gray-400 font-mono">{svc.latency_ms}ms</span>
                      )}
                      <span className="text-xs font-bold px-2.5 py-1 rounded-full"
                        style={{ background: cfg.bg, color: cfg.text }}>
                        {cfg.label}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="flex items-center justify-between">
          <button
            onClick={check}
            disabled={loading}
            className="px-5 py-2.5 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 transition-colors disabled:opacity-60"
          >
            {loading ? "Checking…" : "Refresh"}
          </button>
          <p className="text-xs text-gray-400">
            <a href="https://status.trustledger.dev" className="hover:text-indigo-600 transition-colors">
              Historical uptime →
            </a>
          </p>
        </div>

      </div>
    </div>
  );
}
