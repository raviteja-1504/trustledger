"use client";

import { ReactNode, useEffect, useRef } from "react";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { authedFetch } from "@/lib/useRealData";

const SKIP_AUTH = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";

function ShieldIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  );
}

function GitHubIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

export default function AuthGuard({ children }: { children: ReactNode }) {
  const { user, profile, loading, signInWithGitHub } = useAuth();
  const pathname  = usePathname() ?? "";
  const checked   = useRef(false);

  // Check onboarding status once after the user + profile loads.
  // Admins who haven't completed setup are redirected to /onboarding.
  useEffect(() => {
    if (SKIP_AUTH || loading || !user || !profile || checked.current) return;
    if (pathname === "/onboarding") return;
    if (profile.role !== "admin") return;
    checked.current = true;
    authedFetch<{ complete: boolean }>("/api/onboarding")
      .then(data => { if (!data.complete) window.location.replace("/onboarding"); })
      .catch(() => {}); // if check fails, allow access
  }, [loading, user, profile, pathname]);

  if (SKIP_AUTH) return <>{children}</>;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex flex-col items-center gap-3">
          <svg className="animate-spin w-6 h-6 text-indigo-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          <p className="text-sm text-gray-400 font-medium">Loading…</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center h-full px-4">
        <div className="w-full max-w-sm">
          {/* Card */}
          <div className="bg-white rounded-2xl border border-gray-200 shadow-xl shadow-gray-100 overflow-hidden">
            {/* Header */}
            <div className="px-8 pt-8 pb-6 text-center"
              style={{ background: "linear-gradient(135deg,#0f172a 0%,#1e1b4b 100%)" }}>
              <div className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4 text-indigo-300"
                style={{ background: "rgba(99,102,241,0.2)", border: "1px solid rgba(99,102,241,0.35)" }}>
                <ShieldIcon />
              </div>
              <h1 className="text-lg font-black text-white tracking-tight">TrustLedger</h1>
              <p className="text-sm text-white/45 mt-1">AI Code Provenance Platform</p>
            </div>

            {/* Body */}
            <div className="px-8 py-7 space-y-5">
              <div className="text-center">
                <p className="text-base font-bold text-gray-900">Sign in to continue</p>
                <p className="text-sm text-gray-400 mt-1">
                  Use your GitHub account to access your organisation's dashboard.
                </p>
              </div>

              <button
                onClick={() => signInWithGitHub()}
                className="w-full flex items-center justify-center gap-2.5 py-3 rounded-xl font-bold text-sm text-white transition-all active:scale-[0.98]"
                style={{ background: "#24292f", boxShadow: "0 2px 10px rgba(0,0,0,0.2)" }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "#1a1f24"; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = "#24292f"; }}
              >
                <GitHubIcon />
                Continue with GitHub
              </button>

              <p className="text-center text-[11px] text-gray-400 leading-relaxed">
                By signing in you agree to our{" "}
                <a href="#" className="text-indigo-500 hover:text-indigo-600 underline underline-offset-2">Terms of Service</a>
                {" "}and{" "}
                <a href="#" className="text-indigo-500 hover:text-indigo-600 underline underline-offset-2">Privacy Policy</a>.
              </p>
            </div>
          </div>

          <p className="text-center text-xs text-gray-400 mt-5">
            Need access?{" "}
            <a href="mailto:hello@trustledger.dev" className="text-indigo-500 hover:text-indigo-600 font-medium">
              Contact your admin
            </a>
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
