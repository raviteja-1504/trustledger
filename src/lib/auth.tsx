"use client";

import {
  createContext, useContext, useEffect, useState, type ReactNode,
} from "react";
import type { User, Session } from "@supabase/supabase-js";
import { supabase } from "./supabase";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface OrgProfile {
  org_id:   string;
  org_slug: string;
  org_name: string;
  role:     string;
  email:    string;
  name:     string | null;
  github_login: string | null;
  avatar_url:   string | null;
}

interface AuthContextValue {
  user:       User | null;
  session:    Session | null;
  profile:    OrgProfile | null;
  loading:    boolean;
  signInWithGitHub: () => Promise<void>;
  signInWithEmail:  (email: string, password: string) => Promise<{ error: string | null }>;
  signUpWithEmail:  (email: string, password: string, name: string) => Promise<{ error: string | null }>;
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

function syncSessionCookie(session: Session | null) {
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

  // Load org profile after user is known
  async function loadProfile(userId: string) {
    const { data } = await supabase
      .from("org_members")
      .select("org_id, role, email, name, github_login, avatar_url, organizations(slug, name)")
      .eq("user_id", userId)
      .single();

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
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      syncSessionCookie(session);
      setSession(session);
      setUser(session?.user ?? null);
      if (session?.user) loadProfile(session.user.id);
      else setProfile(null);
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
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    return { error: error?.message ?? null };
  }

  async function signUpWithEmail(email: string, password: string, name: string) {
    const { error } = await supabase.auth.signUp({
      email, password,
      options: { data: { name } },
    });
    return { error: error?.message ?? null };
  }

  async function signOut() {
    await supabase.auth.signOut();
    syncSessionCookie(null);
    setProfile(null);
  }

  return (
    <AuthContext.Provider value={{ user, session, profile, loading, signInWithGitHub, signInWithEmail, signUpWithEmail, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

// ── Hook ───────────────────────────────────────────────────────────────────────

const _noopAuth: AuthContextValue = {
  user: null, session: null, profile: null, loading: false,
  signInWithGitHub: async () => {},
  signInWithEmail:  async () => ({ error: null }),
  signUpWithEmail:  async () => ({ error: null }),
  signOut: async () => {},
};

export function useAuth(): AuthContextValue {
  return useContext(AuthContext) ?? _noopAuth;
}
