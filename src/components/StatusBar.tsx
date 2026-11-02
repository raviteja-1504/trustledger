"use client";

import { useState, useEffect } from "react";
import { usePathname } from "next/navigation";
import { useSidebar } from "@/lib/sidebar";
import { probeApi, recheckAfter, RECHECK_OFFLINE_MS, type ApiStatus } from "@/lib/apiHealth";

const VERSION  = "v1.0.0";

type APIStatus = ApiStatus | "checking";
const LABEL: Record<APIStatus, string> = { online: "API online", offline: "API offline", "no-network": "You're offline", checking: "Connecting…" };

export default function StatusBar() {
  const pathname = usePathname() ?? "/";
  const { collapsed } = useSidebar();
  const [apiStatus,   setApiStatus]   = useState<APIStatus>("checking");
  const [lastCheck,   setLastCheck]   = useState<Date | null>(null);
  const [refreshAgo,  setRefreshAgo]  = useState("");
  const [now,         setNow]         = useState<Date | null>(null); // null until after hydration

  // Check API health (lib/apiHealth.ts): every 5 min while healthy, every 30 s while not, skipped while the tab is
  // hidden. This component is mounted globally on every page for every user, so its poll cost multiplies across the
  // whole session base -- a healthy indicator doesn't need sub-minute freshness. The browser's own online/offline
  // events re-check at once.
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let alive = true;
    async function check() {
      if (timer) clearTimeout(timer);
      const status = await probeApi();
      if (!alive) return;
      setApiStatus(status);
      setLastCheck(new Date());
      next(recheckAfter(status));
    }
    // a hidden tab doesn't check: it looks again a little later
    function next(ms: number) {
      timer = setTimeout(() => { if (document.hidden) next(RECHECK_OFFLINE_MS); else void check(); }, ms);
    }
    const recheck = () => { void check(); };
    void check();
    window.addEventListener("online", recheck);
    window.addEventListener("offline", recheck);
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
      window.removeEventListener("online", recheck);
      window.removeEventListener("offline", recheck);
    };
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
          <span role="status" style={{ color: apiStatus==="online" ? "rgba(52,211,153,0.7)" : apiStatus==="offline" ? "rgba(248,113,113,0.7)" : "rgba(251,191,36,0.7)" }}>
            {LABEL[apiStatus]}
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
          href="/security"
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
