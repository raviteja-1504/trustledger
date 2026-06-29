"use client";

import { useEffect, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { syncSessionCookie } from "@/lib/auth";
import { authedFetch } from "@/lib/useRealData";

// GitHub OAuth lands here with ?code=... (PKCE flow). We exchange it for a
// session using the same browser client that initiated signInWithOAuth (it
// holds the PKCE code verifier), then bootstrap org membership server-side.
export default function AuthCallbackPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;

    const code  = searchParams?.get("code") ?? null;
    const error = searchParams?.get("error") ?? null;
    const next  = searchParams?.get("next") ?? "/dashboard";

    if (error) {
      router.replace(`/login?error=${encodeURIComponent(error)}`);
      return;
    }
    if (!code) {
      router.replace("/login?error=missing_code");
      return;
    }

    (async () => {
      const { data, error: exchErr } = await supabase.auth.exchangeCodeForSession(code);
      if (exchErr || !data.session) {
        // Encode the actual Supabase error message so the login page can show it
        const reason = exchErr?.message ?? "no_session";
        // pkce_verifier_mismatch / bad_code_verifier → browser lost the PKCE state
        const isPKCE = reason.toLowerCase().includes("code_verifier") ||
                       reason.toLowerCase().includes("pkce") ||
                       reason.toLowerCase().includes("verifier");
        const errParam = isPKCE ? "pkce_lost" : encodeURIComponent(reason);
        router.replace(`/login?error=${errParam}`);
        return;
      }

      // Write the auth cookie ourselves right away — onAuthStateChange's
      // listener may not have run yet, and middleware needs this cookie on
      // the very next request to avoid bouncing back to /login.
      syncSessionCookie(data.session);

      let destination = next;
      try {
        const { is_new_user } = await authedFetch<{ is_new_user: boolean }>("/api/auth/bootstrap", {
          method: "POST",
        });
        destination = is_new_user && next === "/dashboard" ? "/onboarding" : next;
      } catch { /* fall back to `next` */ }

      // Full navigation (not router.replace) so middleware re-evaluates
      // with the cookie we just set.
      window.location.assign(destination);
    })();
  }, [router, searchParams]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <p className="text-sm text-gray-500">Signing you in…</p>
    </div>
  );
}
