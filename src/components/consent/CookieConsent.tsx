"use client";
/**
 * GDPR Cookie Consent Banner
 * Required for EU users. Stores consent in localStorage.
 * Blocks analytics (PostHog) until consent is given.
 *
 * Consent types:
 *   - necessary:   Always on (auth session, CSRF, preferences)
 *   - analytics:   PostHog usage analytics
 *   - marketing:   Currently unused — placeholder for future use
 */

import { useState, useEffect } from "react";
import Link from "next/link";

type ConsentChoice = "all" | "necessary" | null;

const CONSENT_KEY     = "tl_cookie_consent";
const CONSENT_DATE_KEY= "tl_cookie_consent_date";

export function getConsent(): ConsentChoice {
  if (typeof window === "undefined") return null;
  return (localStorage.getItem(CONSENT_KEY) as ConsentChoice) ?? null;
}

export function hasAnalyticsConsent(): boolean {
  return getConsent() === "all";
}

function saveConsent(choice: "all" | "necessary") {
  localStorage.setItem(CONSENT_KEY, choice);
  localStorage.setItem(CONSENT_DATE_KEY, new Date().toISOString());
}

export default function CookieConsent() {
  const [visible,   setVisible]   = useState(false);
  const [expanded,  setExpanded]  = useState(false);

  useEffect(() => {
    const existing = getConsent();
    if (!existing) {
      const t = setTimeout(() => setVisible(true), 1000);
      return () => clearTimeout(t);
    }
    return undefined;
  }, []);

  function accept(choice: "all" | "necessary") {
    saveConsent(choice);
    setVisible(false);

    if (choice === "all") {
      // Enable analytics
      import("@/lib/analytics").then(({ track }) => {
        track("cookie_consent_accepted", { choice });
      }).catch(() => {});
    }
  }

  if (!visible) return null;

  return (
    <div
      role="dialog"
      aria-label="Cookie consent"
      aria-modal="false"
      className="fixed bottom-0 left-0 right-0 z-50 md:bottom-4 md:left-4 md:right-auto md:max-w-md"
      style={{ animation: "slideUp 0.3s ease-out" }}
    >
      <style>{`
        @keyframes slideUp {
          from { transform: translateY(100%); opacity: 0; }
          to   { transform: translateY(0);    opacity: 1; }
        }
      `}</style>

      <div className="bg-white rounded-none md:rounded-2xl border border-gray-200 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-5 py-4 border-b border-gray-100 flex items-start gap-3">
          <span className="text-xl shrink-0">🍪</span>
          <div>
            <p className="text-sm font-black text-gray-900">Cookie Preferences</p>
            <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">
              We use cookies to keep you signed in and improve our service.{" "}
              <Link href="/privacy" className="text-indigo-600 hover:underline">Privacy Policy</Link>
            </p>
          </div>
        </div>

        {/* Cookie types */}
        {expanded && (
          <div className="px-5 py-3 space-y-3 border-b border-gray-100">
            {[
              {
                name:     "Strictly Necessary",
                desc:     "Authentication session, security tokens, preferences. Cannot be disabled.",
                always:   true,
              },
              {
                name:     "Analytics",
                desc:     "Anonymous usage data to improve the product (PostHog). No personal data shared.",
                always:   false,
              },
            ].map(cookie => (
              <div key={cookie.name} className="flex items-start justify-between gap-3">
                <div className="flex-1">
                  <p className="text-xs font-bold text-gray-800">{cookie.name}</p>
                  <p className="text-[10px] text-gray-500 mt-0.5 leading-relaxed">{cookie.desc}</p>
                </div>
                <div className={`w-9 h-5 rounded-full shrink-0 flex items-center ${cookie.always ? "bg-emerald-500" : "bg-gray-200"}`}>
                  <div className={`w-4 h-4 rounded-full bg-white shadow mx-0.5 ${cookie.always ? "" : "ml-auto mr-0.5"}`} />
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Actions */}
        <div className="px-5 py-3.5 flex items-center gap-2 flex-wrap">
          <button
            onClick={() => accept("all")}
            className="flex-1 py-2 text-sm font-bold rounded-xl text-white transition-all"
            style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}
          >
            Accept all
          </button>
          <button
            onClick={() => accept("necessary")}
            className="flex-1 py-2 text-sm font-semibold rounded-xl border border-gray-200 text-gray-600 hover:border-gray-300 transition-all"
          >
            Necessary only
          </button>
          <button
            onClick={() => setExpanded(v => !v)}
            className="text-[11px] text-gray-400 hover:text-gray-600 w-full text-center mt-1 transition-colors"
          >
            {expanded ? "Hide details ↑" : "Cookie details ↓"}
          </button>
        </div>
      </div>
    </div>
  );
}

/** Floating button to re-open cookie settings after they've been set. */
export function CookieSettingsButton() {
  function reset() {
    localStorage.removeItem(CONSENT_KEY);
    localStorage.removeItem(CONSENT_DATE_KEY);
    window.location.reload();
  }

  return (
    <button
      onClick={reset}
      className="text-xs text-gray-400 hover:text-gray-600 transition-colors underline underline-offset-2"
    >
      Cookie settings
    </button>
  );
}
