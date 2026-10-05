"use client";

import { Suspense, useEffect, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { syncSessionCookie, type BootstrapResult } from "@/lib/auth";
import { authedFetch } from "@/lib/useRealData";
import { fullPageNavigate, safeNextPath } from "@/lib/authFlow";

// GitHub OAuth lands here with ?code=... (PKCE flow).
//
// The Supabase client exchanges that code by itself as soon as it loads (detectSessionInUrl), so the
// session is normally already there — getSession() waits for that. Exchanging the same code again here
// used to fail every time ("code verifier not found") and bounce through /login?error=pkce_lost; only
// when the client did NOT pick it up do we exchange it ourselves.
//
// Then: no org → /create-org; 2FA on → the code step on /login; otherwise `next` (same-site paths only).
// useSearchParams() needs a Suspense boundary (a build error since Next 15).
export default function AuthCallbackPage() {
  return <Suspense fallback={<SigningIn />}><AuthCallback /></Suspense>;
}

function SigningIn() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <p className="text-sm text-gray-500">Signing you in…</p>
    </div>
  );
}

function AuthCallback() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;

    const code  = searchParams?.get("code") ?? null;
    const error = searchParams?.get("error") ?? null;
    const next  = safeNextPath(searchParams?.get("next"));

    if (error) {
      router.replace(`/login?error=${error === "access_denied" ? "access_denied" : "auth_failed"}`);
      return;
    }

    (async () => {
      let { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        if (!code) { router.replace("/login?error=missing_code"); return; }
        const { data, error: exchErr } = await supabase.auth.exchangeCodeForSession(code);
        if (exchErr || !data.session) {
          const reason = (exchErr?.message ?? "").toLowerCase();
          router.replace(`/login?error=${reason.includes("verifier") || reason.includes("pkce") ? "pkce_lost" : "auth_failed"}`);
          return;
        }
        session = data.session;
      }

      // Write the auth cookie ourselves right away — onAuthStateChange's listener may not have run yet,
      // and middleware needs this cookie on the very next request to avoid bouncing back to /login.
      syncSessionCookie(session);

      let destination = next;
      try {
        const result = await authedFetch<BootstrapResult>("/api/auth/bootstrap", { method: "POST" });
        if (result.sso_status) {
          // An SSO sign-in its organisation didn't accept: don't leave that session behind.
          await supabase.auth.signOut();
          fullPageNavigate(`/login?error=${encodeURIComponent(result.sso_status)}`);
          return;
        }
        if (!result.has_org) destination = "/create-org";
        else if (result.mfa_required) destination = `/login?step=2fa&next=${encodeURIComponent(next)}`;
      } catch { /* fall back to `next`; AuthGuard sorts out a missing org */ }

      // Full navigation (not router.replace) so middleware re-evaluates with the cookie we just set.
      fullPageNavigate(destination);
    })();
  }, [router, searchParams]);

  return <SigningIn />;
}
