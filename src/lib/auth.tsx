"use client";

import {
  createContext, useContext, useEffect, useState, type ReactNode,
} from "react";
import type { User, Session } from "@supabase/supabase-js";
import { supabase } from "./supabase";
import { authedFetch } from "./useRealData";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface OrgProfile {
  org_id:              string;
  org_slug:            string;
  org_name:            string;
  role:                string;
  email:               string;
  name:                string | null;
  github_login:         string | null;
  avatar_url:           string | null;
  onboarding_complete?: boolean;
}

interface AuthContextValue {
  user:       User | null;
  session:    Session | null;
  profile:    OrgProfile | null;
  loading:    boolean;
  signInWithGitHub:   () => Promise<void>;
  signInWithEmail:    (email: string, password: string) => Promise<{ error: string | null }>;
  signUpWithEmail:    (email: string, password: string, name: string) => Promise<{ error: string | null }>;
  resetPassword:      (email: string) => Promise<{ error: string | null }>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// ── Session cookie sync ──────────────────────────────────────────────────────
// The Supabase JS client persists sessions in localStorage, but
// src/middleware.ts (Edge runtime) checks a `sb-<project-ref>-auth-token`
// cookie to gate protected routes. Mirror the session into that cookie so
// server-side route protection works for email/password and OAuth sign-ins.
function authCookieName(): string {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
  const ref = url ? new URL(url).hostname.split(".")[0] : "";
  return `sb-${ref}-auth-token`;
}

export function syncSessionCookie(session: Session | null) {
  if (typeof document === "undefined") return;
  const name = authCookieName();
  if (!session) {
    document.cookie = `${name}=; path=/; max-age=0; SameSite=Lax`;
    return;
  }
  const value = encodeURIComponent(JSON.stringify({
    access_token:  session.access_token,
    refresh_token: session.refresh_token,
  }));
  const maxAge = Math.max(60, session.expires_in ?? 3600);
  const secure = window.location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `${name}=${value}; path=/; max-age=${maxAge}; SameSite=Lax${secure}`;
}

// ── Idle timeout ─────────────────────────────────────────────────────────────
// Auto sign-out after this much inactivity (no mouse/keyboard/touch events).
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;

// ── Demo / skip-auth mode ──────────────────────────────────────────────────────
const SKIP_AUTH = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";

// Read the demo role chosen on the login page (stored in localStorage)
function getDemoRole(): string {
  if (typeof window === "undefined") return "admin";
  return localStorage.getItem("tl_demo_role") ?? "admin";
}

function getDemoProfile(role: string): OrgProfile {
  const NAMES: Record<string, string> = {
    admin:             "Alex Admin",
    security_reviewer: "Sam Security",
    developer:         "Dev User",
    auditor:           "Alice Auditor",
  };
  const EMAILS: Record<string, string> = {
    admin:             "admin@trustledger.dev",
    security_reviewer: "security@trustledger.dev",
    developer:         "dev@trustledger.dev",
    auditor:           "auditor@trustledger.dev",
  };
  return {
    org_id:       "demo-org",
    org_slug:     process.env.NEXT_PUBLIC_ORG ?? "novapay",
    org_name:     process.env.NEXT_PUBLIC_ORG ?? "novapay",
    role,
    email:        EMAILS[role] ?? "demo@trustledger.dev",
    name:         NAMES[role]  ?? "Demo User",
    github_login: null,
    avatar_url:   null,
  };
}

function makeDemoAuth(): AuthContextValue {
  const role = getDemoRole();
  return {
    user:    { id: `demo-${role}`, email: `${role}@trustledger.dev` } as User,
    session: null,
    profile: getDemoProfile(role),
    loading: false,
    signInWithGitHub: async () => {},
    signInWithEmail:  async () => ({ error: null }),
    signUpWithEmail:  async () => ({ error: null }),
    resetPassword:    async () => ({ error: null }),
    signOut:          async () => {
      if (typeof window !== "undefined") localStorage.removeItem("tl_demo_role");
      window.location.href = "/login";
    },
  };
}

const _demoAuth = makeDemoAuth();

// ── Provider ───────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }) {
  if (SKIP_AUTH) {
    return <AuthContext.Provider value={_demoAuth}>{children}</AuthContext.Provider>;
  }
  return <SupabaseAuthProvider>{children}</SupabaseAuthProvider>;
}

function SupabaseAuthProvider({ children }: { children: ReactNode }) {
  const [user,    setUser]    = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [profile, setProfile] = useState<OrgProfile | null>(null);
  const [loading, setLoading] = useState(true);

  // Load org profile after user is known.
  async function loadProfile(userId: string) {
    // Look up by user_id first (returning members)
    let { data } = await supabase
      .from("org_members")
      .select("org_id, role, email, name, github_login, avatar_url, organizations(slug, name)")
      .eq("user_id", userId)
      .single();

    // Invited users have user_id = null until first login. The direct
    // Supabase client UPDATE (anon key) is blocked by RLS for new users
    // who don't own the row yet. Fall back to /api/me which uses the
    // service role client in the middleware — it handles the linking
    // automatically and returns the profile once linked.
    if (!data) {
      try {
        const { data: { session } } = await supabase.auth.getSession();
        if (session?.access_token) {
          const res = await fetch("/api/me", {
            headers: { Authorization: `Bearer ${session.access_token}` },
          });
          if (res.ok) {
            const me = await res.json();
            setProfile(me);
            return;
          }
        }
      } catch {}
    }

    if (data) {
      const org = (Array.isArray(data.organizations) ? data.organizations[0] : data.organizations) as { slug: string; name: string } | null;
      setProfile({
        org_id:   data.org_id,
        org_slug: org?.slug ?? "",
        org_name: org?.name ?? "",
        role:     data.role,
        email:    data.email,
        name:     data.name,
        github_login: data.github_login,
        avatar_url:   data.avatar_url,
      });
    }
  }

  useEffect(() => {
    // Get initial session
    supabase.auth.getSession().then(({ data: { session } }) => {
      syncSessionCookie(session);
      setSession(session);
      setUser(session?.user ?? null);
      if (session?.user) loadProfile(session.user.id).finally(() => setLoading(false));
      else setLoading(false);
    });

    // Listen for auth state changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      syncSessionCookie(session);
      setSession(session);
      setUser(session?.user ?? null);
      if (session?.user) {
        loadProfile(session.user.id);
        // Register session on every sign-in (GitHub OAuth or email) so
        // active_session_id in org_members always matches the current JWT.
        // Without this, a GitHub OAuth login after a password login would
        // produce a new JWT session ID that doesn't match the stored ID,
        // triggering the "session_revoked" false-positive.
        if (event === "SIGNED_IN") registerSession();
      } else {
        setProfile(null);
      }
    });

    return () => subscription.unsubscribe();
  }, []);

  async function signInWithGitHub() {
    await supabase.auth.signInWithOAuth({
      provider: "github",
      options: {
        redirectTo: `${window.location.origin}/auth/callback`,
        scopes: "read:user user:email read:org",
      },
    });
  }

  async function signInWithEmail(email: string, password: string) {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (!error && data.session) {
      syncSessionCookie(data.session);
      await registerSession();
    }
    return { error: error?.message ?? null };
  }

  async function signUpWithEmail(email: string, password: string, name: string) {
    const { data, error } = await supabase.auth.signUp({
      email, password,
      options: { data: { name } },
    });
    if (!error && data.session) {
      syncSessionCookie(data.session);
      await registerSession();
    }
    return { error: error?.message ?? null };
  }

  async function resetPassword(email: string) {
    const base = (process.env.NEXT_PUBLIC_APP_URL || (typeof window !== "undefined" ? window.location.origin : "")).replace(/\/$/, "");
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${base}/login`,
    });
    return { error: error?.message ?? null };
  }

  // Record this session as the user's sole active session (kicks out any
  // previously issued token — see verifyApiKey's session_revoked check).
  async function registerSession() {
    try {
      await authedFetch("/api/auth/bootstrap", { method: "POST" });
    } catch { /* best-effort */ }
  }

  async function signOut() {
    await supabase.auth.signOut();
    syncSessionCookie(null);
    setProfile(null);
  }

  // Auto sign-out after IDLE_TIMEOUT_MS with no user activity.
  useEffect(() => {
    if (!user) return;

    let lastActivity = Date.now();
    const onActivity = () => { lastActivity = Date.now(); };
    const events: (keyof WindowEventMap)[] = ["mousemove", "keydown", "click", "scroll", "touchstart"];
    events.forEach(e => window.addEventListener(e, onActivity, { passive: true }));

    const interval = setInterval(() => {
      if (Date.now() - lastActivity >= IDLE_TIMEOUT_MS) {
        clearInterval(interval);
        signOut().then(() => { window.location.href = "/login?error=session_timeout"; });
      }
    }, 30_000);

    return () => {
      events.forEach(e => window.removeEventListener(e, onActivity));
      clearInterval(interval);
    };
  }, [user]);

  return (
    <AuthContext.Provider value={{ user, session, profile, loading, signInWithGitHub, signInWithEmail, signUpWithEmail, resetPassword, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

// ── Hook ───────────────────────────────────────────────────────────────────────

const _noopAuth: AuthContextValue = {
  user: null, session: null, profile: null, loading: false,
  signInWithGitHub:  async () => {},
  signInWithEmail:   async () => ({ error: null }),
  signUpWithEmail:   async () => ({ error: null }),
  resetPassword:     async () => ({ error: null }),
  signOut: async () => {},
};

export function useAuth(): AuthContextValue {
  return useContext(AuthContext) ?? _noopAuth;
}
