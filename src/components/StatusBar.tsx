"use client";

import { useState, useEffect } from "react";
import { usePathname } from "next/navigation";
import { useSidebar } from "@/lib/sidebar";

const VERSION  = "v1.0.0";

type APIStatus = "online" | "offline" | "checking";

export default function StatusBar() {
  const pathname = usePathname() ?? "/";
  const { collapsed } = useSidebar();
  const [apiStatus,   setApiStatus]   = useState<APIStatus>("checking");
  const [lastCheck,   setLastCheck]   = useState<Date | null>(null);
  const [refreshAgo,  setRefreshAgo]  = useState("");
  const [now,         setNow]         = useState<Date | null>(null); // null until after hydration

  // Check API health every 30s (use our own /healthz instead of old Python backend)
  useEffect(() => {
    async function check() {
      try {
        const res = await fetch("/healthz", { signal: AbortSignal.timeout(3000) });
        setApiStatus(res.ok ? "online" : "offline");
      } catch {
        setApiStatus("offline");
      }
      setLastCheck(new Date());
    }
    check();
    const id = setInterval(check, 30_000);
    return () => clearInterval(id);
  }, []);

  // Set clock after mount (avoids server/client hydration mismatch)
  useEffect(() => { setNow(new Date()); }, []);

  // Tick the clock and refresh-ago
  useEffect(() => {
    const id = setInterval(() => {
      setNow(new Date());
      if (lastCheck) {
        const s = Math.floor((Date.now() - lastCheck.getTime()) / 1000);
        setRefreshAgo(s < 10 ? "just now" : s < 60 ? `${s}s ago` : `${Math.floor(s/60)}m ago`);
      }
    }, 5000);
    return () => clearInterval(id);
  }, [lastCheck]);

  const timeStr = now
    ? `${String(now.getHours()).padStart(2,"0")}:${String(now.getMinutes()).padStart(2,"0")}`
    : "";

  return (
    <div
      className="shrink-0 flex items-center justify-between px-4 h-7 text-[10px] font-medium select-none"
      style={{
        background: "rgba(10,15,30,0.98)",
        borderTop: "1px solid rgba(255,255,255,0.05)",
        color: "rgba(255,255,255,0.35)",
      }}
    >
      {/* Left — API status + current page */}
      <div className="flex items-center gap-3">
        <span className="flex items-center gap-1.5">
          <span className={`w-1.5 h-1.5 rounded-full ${
            apiStatus === "online"   ? "bg-emerald-400" :
            apiStatus === "offline"  ? "bg-rose-400" :
                                       "bg-amber-400 animate-pulse"
          }`} />
          <span style={{ color: apiStatus==="online" ? "rgba(52,211,153,0.7)" : apiStatus==="offline" ? "rgba(248,113,113,0.7)" : "rgba(251,191,36,0.7)" }}>
            {apiStatus === "checking" ? "Connecting…" : `API ${apiStatus}`}
          </span>
          {lastCheck && refreshAgo && (
            <span className="opacity-50">· checked {refreshAgo}</span>
          )}
        </span>

        <span className="opacity-30">|</span>

        {/* Breadcrumb path */}
        <span className="font-mono opacity-50">
          {pathname.split("/").filter(Boolean).join(" › ") || "dashboard"}
        </span>
      </div>

      {/* Right — version, time */}
      <div className="flex items-center gap-3">
        <span className="opacity-40">TrustLedger {VERSION}</span>
        <span className="opacity-30">|</span>
        <span className="font-mono tabular-nums opacity-50">{timeStr}</span>
        <a
          href="https://github.com/anthropics/claude-code/issues"
          target="_blank"
          rel="noopener noreferrer"
          className="opacity-30 hover:opacity-60 transition-opacity"
          title="Report an issue">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
        </a>
      </div>
    </div>
  );
}
