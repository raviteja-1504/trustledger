"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { applySeed, clearSeed } from "@/lib/seed";

export default function SeedPage() {
  const router = useRouter();
  const [done,      setDone]      = useState<"applied" | "cleared" | null>(null);
  const [isApplied, setIsApplied] = useState(false); // always false on server, updated after mount

  // Read localStorage only after hydration to avoid server/client mismatch
  useEffect(() => {
    setIsApplied(localStorage.getItem("tl_force_seed") === "1");
  }, []);

  // Auto-apply on first load so navigating to /seed is enough
  useEffect(() => {
    applySeed();
    setDone("applied");
    setIsApplied(true);
    const t = setTimeout(() => router.push("/dashboard"), 1200);
    return () => clearTimeout(t);
  }, [router]);

  function handleClear() {
    clearSeed();
    setDone("cleared");
    setIsApplied(false);
    setTimeout(() => router.push("/dashboard"), 1200);
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-8 w-80 text-center space-y-5">

        {/* Icon */}
        <div className="w-12 h-12 rounded-2xl mx-auto flex items-center justify-center"
          style={{ background: done === "cleared" ? "#fef2f2" : "#f5f3ff" }}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
            stroke={done === "cleared" ? "#be123c" : "#7c3aed"} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            {done === "cleared"
              ? <><path d="M3 6h18"/><path d="M19 6l-1 14H6L5 6"/><path d="M9 6V4h6v2"/></>
              : <><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></>
            }
          </svg>
        </div>

        {/* Status */}
        {done === "applied" && (
          <>
            <div>
              <p className="font-black text-gray-900 text-lg">Seed applied</p>
              <p className="text-sm text-gray-400 mt-1">7 repos · 147 scans · all features populated</p>
            </div>
            <p className="text-xs text-indigo-600 font-semibold animate-pulse">Redirecting to dashboard…</p>
          </>
        )}
        {done === "cleared" && (
          <>
            <div>
              <p className="font-black text-gray-900 text-lg">Seed cleared</p>
              <p className="text-sm text-gray-400 mt-1">Live API restored</p>
            </div>
            <p className="text-xs text-gray-500 font-semibold animate-pulse">Redirecting to dashboard…</p>
          </>
        )}
        {!done && (
          <>
            <div>
              <p className="font-black text-gray-900 text-lg">Local Test Seed</p>
              <p className="text-sm text-gray-400 mt-1">
                {isApplied ? "Seed is currently active — API bypassed" : "No seed active — live API in use"}
              </p>
            </div>
          </>
        )}

        {/* Actions */}
        {!done && (
          <div className="space-y-2">
            <button
              onClick={() => { applySeed(); setDone("applied"); setTimeout(() => router.push("/dashboard"), 1200); }}
              className="w-full py-2.5 rounded-xl text-sm font-bold text-white transition-all hover:opacity-90"
              style={{ background: "linear-gradient(135deg,#7c3aed,#6366f1)" }}>
              Apply Seed
            </button>
            {isApplied && (
              <button onClick={handleClear}
                className="w-full py-2.5 rounded-xl text-sm font-semibold text-rose-600 bg-rose-50 border border-rose-100 hover:bg-rose-100 transition-all">
                Clear Seed &amp; Restore API
              </button>
            )}
          </div>
        )}

        <p className="text-[10px] text-gray-300">
          Navigate to <code className="font-mono">/seed</code> to apply · <code className="font-mono">/seed</code> again to manage
        </p>
      </div>
    </div>
  );
}
