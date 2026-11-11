"use client";

import { ReactNode, useEffect, useRef } from "react";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { authedFetch, handleSessionError } from "@/lib/useRealData";
import { fullPageReplace } from "@/lib/authFlow";

import { BrandLogo } from "./BrandLogo";
import { contactEmail } from "@/lib/contacts";
import { onboardingAction, ONBOARDING_PROMPTED_KEY, type OnboardingStatus } from "@/lib/onboardingGate";

const SKIP_AUTH = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";

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

  // GitHub sends a person back to the app's Setup URL after installing it, with ?installation_id=...&setup_action=...
  // If that is some page other than the wizard (the dashboard, say), carry on to the wizard with the same details.
  useEffect(() => {
    if (SKIP_AUTH || loading || !user || pathname === "/onboarding") return;
    const q = new URLSearchParams(window.location.search);
    // setup_action=request: a member installed it on an organisation whose owner has not approved it yet (no installation_id)
    const action = q.get("setup_action");
    if (action && (q.get("installation_id") || action === "request")) fullPageReplace(`/onboarding?${q.toString()}`);
  }, [loading, user, pathname]);

  // Check onboarding status once after the user + profile loads.
  // Only a brand-new organisation's creator is sent to /onboarding (lib/onboardingGate.ts); an admin joining an
  // organisation that already has members or scans is marked complete and never sees the flow.
  useEffect(() => {
    if (SKIP_AUTH || loading || !user || !profile || checked.current) return;
    if (pathname === "/onboarding") return;
    if (profile.role !== "admin") return;
    checked.current = true;
    authedFetch<OnboardingStatus>("/api/onboarding")
      .then(data => {
        let prompted = false;
        try { prompted = sessionStorage.getItem(ONBOARDING_PROMPTED_KEY) === "1"; } catch { /* storage unavailable */ }
        const action = onboardingAction(data, prompted);
        if (action === "none") return;
        if (action === "complete") {
          // an admin who joined an organisation that is already running: nothing to set up
          authedFetch("/api/onboarding", {
            method: "POST",
            body: JSON.stringify({ action: "complete" }),
          }).catch(() => {});
          return;
        }
        // a brand-new organisation: offer setup once per session; after that it is resumed from the dashboard
        try { sessionStorage.setItem(ONBOARDING_PROMPTED_KEY, "1"); } catch { /* storage unavailable */ }
        fullPageReplace("/onboarding");
      })
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

  // Authenticated but no org membership — try /api/me once more before
  // giving up. This handles the case where loadProfile() finished before
  // the session token was fully available (rare race) or /api/me transiently
  // failed. Only redirect to create-org if /api/me explicitly returns 404.
  if (!loading && user && !profile && pathname !== "/create-org") {
    if (typeof window !== "undefined") {
      import("@/lib/supabase").then(({ supabase }) =>
        supabase.auth.getSession().then(({ data: { session } }) => {
          if (!session?.access_token) { fullPageReplace("/login"); return; }
          fetch("/api/me", { headers: { Authorization: `Bearer ${session.access_token}` } })
            .then(async res => {
              if (res.ok) {
                // Profile found — reload so auth context can pick it up
                window.location.reload();
              } else {
                const body = await res.json().catch(() => ({}));
                // Only redirect to create-org if truly no membership
                // /api/me answers "no org" both as 404 and (via verifyApiKey) as 401 — key on the code.
                if (body.error === "no_org_membership") {
                  fullPageReplace("/create-org");
                } else if (body.error === "mfa_required" || body.error === "session_revoked") {
                  // Needs the 2FA code / signed in elsewhere — retrying would loop forever.
                  handleSessionError(body.error);
                } else {
                  // Auth/server error — retry in 2s
                  setTimeout(() => window.location.reload(), 2000);
                }
              }
            })
            .catch(() => fullPageReplace("/create-org"));
        })
      );
    }
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex flex-col items-center gap-3">
          <svg className="animate-spin w-6 h-6 text-indigo-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
          </svg>
          <p className="text-sm text-gray-400 font-medium">Loading your profile…</p>
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
              <h1 className="flex justify-center"><BrandLogo height={66} /></h1>
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
            <a href={`mailto:${contactEmail("hello")}`} className="text-indigo-500 hover:text-indigo-600 font-medium">
              Contact your admin
            </a>
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
