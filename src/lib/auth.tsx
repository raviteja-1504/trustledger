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
      setSession(session);
      setUser(session?.user ?? null);
      if (session?.user) loadProfile(session.user.id).finally(() => setLoading(false));
      else setLoading(false);
    });

    // Listen for auth state changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
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
        redirectTo: `${window.location.origin}/api/auth/callback`,
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
