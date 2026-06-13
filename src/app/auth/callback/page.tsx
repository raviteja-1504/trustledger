"use client";

import { useEffect, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { supabase } from "@/lib/supabase";
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
        router.replace("/login?error=auth_failed");
        return;
      }

      try {
        const { is_new_user } = await authedFetch<{ is_new_user: boolean }>("/api/auth/bootstrap", {
          method: "POST",
        });
        router.replace(is_new_user && next === "/dashboard" ? "/onboarding" : next);
      } catch {
        router.replace(next);
      }
    })();
  }, [router, searchParams]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <p className="text-sm text-gray-500">Signing you in…</p>
    </div>
  );
}
