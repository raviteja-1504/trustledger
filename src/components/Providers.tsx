"use client";

import { useEffect } from "react";
import { AuthProvider, useAuth } from "@/lib/auth";
import { ToastProvider } from "@/lib/toast";
import Toaster from "@/components/Toaster";
import { loadBranding, applyBranding } from "@/lib/branding";
import dynamic from "next/dynamic";

const CookieConsent = dynamic(() => import("@/components/consent/CookieConsent"), { ssr: false });
const WebVitals     = dynamic(() => import("@/components/WebVitals").then(m => ({ default: m.WebVitals })), { ssr: false });

function BrandingInit() {
  useEffect(() => {
    // Apply saved branding on mount
    applyBranding(loadBranding());
  }, []);
  return null;
}

function AnalyticsInit() {
  const { user, profile } = useAuth();
  useEffect(() => {
    if (!user || !profile) return;
    // Set Sentry user context
    import("@/lib/observability").then(({ setUserContext }) => {
      setUserContext(user.id, profile.email, profile.org_id);
    }).catch(() => {});
    // Set PostHog identity
    import("@/lib/analytics").then(({ identify }) => {
      identify(user.id, { email: profile.email, org: profile.org_slug, role: profile.role });
    }).catch(() => {});
  }, [user?.id, profile?.org_id]); // eslint-disable-line react-hooks/exhaustive-deps
  return null;
}

function GlobalErrorHandler() {
  useEffect(() => {
    function onError(event: ErrorEvent) {
      import("@/lib/observability").then(({ captureError }) => {
        captureError(event.error ?? new Error(event.message), {
          type: "uncaught_error",
          filename: event.filename,
          lineno: event.lineno,
        });
      }).catch(() => {});
    }
    function onUnhandledRejection(event: PromiseRejectionEvent) {
      import("@/lib/observability").then(({ captureError }) => {
        captureError(event.reason instanceof Error ? event.reason : new Error(String(event.reason)), {
          type: "unhandled_promise_rejection",
        });
      }).catch(() => {});
    }
    window.addEventListener("error", onError);
    window.addEventListener("unhandledrejection", onUnhandledRejection);
    return () => {
      window.removeEventListener("error", onError);
      window.removeEventListener("unhandledrejection", onUnhandledRejection);
    };
  }, []);
  return null;
}

export default function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <ToastProvider>
        <BrandingInit />
        <AnalyticsInit />
        <GlobalErrorHandler />
        {children}
        <Toaster />
        <CookieConsent />
        <WebVitals />
      </ToastProvider>
    </AuthProvider>
  );
}
