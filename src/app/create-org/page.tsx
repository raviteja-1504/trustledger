"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/lib/auth";
import { authedFetch } from "@/lib/useRealData";

function ShieldIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <polyline points="9 12 11 14 15 10"/>
    </svg>
  );
}

function GitHubIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
    </svg>
  );
}

export default function CreateOrgPage() {
  const { user, loading, signInWithGitHub } = useAuth();

  const [name,      setName]      = useState("");
  const [slug,      setSlug]      = useState("");
  const [githubOrg, setGithubOrg] = useState("");
  const [creating,  setCreating]  = useState(false);
  const [error,     setError]     = useState<string | null>(null);

  // Auto-generate slug from name
  useEffect(() => {
    setSlug(name.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""));
  }, [name]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim() || !slug.trim()) return;
    setCreating(true);
    setError(null);
    try {
      await authedFetch("/api/orgs/create", {
        method: "POST",
        body: JSON.stringify({ name: name.trim(), slug: slug.trim(), github_org: githubOrg.trim() || undefined }),
      });
      window.location.href = "/onboarding";
    } catch (err: unknown) {
      const e = err as { error?: string };
      if (e?.error === "already_in_org") {
        window.location.href = "/dashboard";
        return;
      }
      setError(e?.error === "slug_taken"
        ? "That URL slug is already taken. Try a different one."
        : "Failed to create organisation. Please try again.");
      setCreating(false);
    }
  }

  const pageStyle: React.CSSProperties = {
    minHeight: "100vh",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "48px 16px",
    background: "linear-gradient(135deg,#0f172a 0%,#1e1040 50%,#0f172a 100%)",
  };

  // ── Loading ────────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={pageStyle}>
        <svg className="animate-spin w-6 h-6 text-indigo-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
        </svg>
      </div>
    );
  }

  // ── Step 1: Not signed in → show sign-in prompt ───────────────────────────
  if (!user) {
    return (
      <div style={pageStyle}>
        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <div className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4 text-white"
              style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 8px 32px rgba(99,102,241,0.4)" }}>
              <ShieldIcon />
            </div>
            <h1 className="text-2xl font-black text-white">Create your organisation</h1>
            <p className="text-sm mt-2" style={{ color: "rgba(165,180,252,0.7)" }}>
              Sign in first, then set up your TrustLedger organisation.
            </p>
          </div>

          <div className="rounded-2xl p-8 space-y-4" style={{
            background: "rgba(255,255,255,0.04)",
            border: "1px solid rgba(255,255,255,0.08)",
          }}>
            <button
              onClick={signInWithGitHub}
              className="w-full flex items-center justify-center gap-3 py-3 rounded-xl font-semibold text-sm text-white transition-all"
              style={{ background: "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.15)" }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.13)"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.08)"; }}
            >
              <GitHubIcon />
              Continue with GitHub
            </button>
            <p className="text-center text-xs" style={{ color: "rgba(255,255,255,0.3)" }}>
              Already have an account?{" "}
              <a href="/login" className="text-indigo-400 hover:text-indigo-300 underline underline-offset-2">
                Sign in →
              </a>
            </p>
          </div>
        </div>
      </div>
    );
  }

  // ── Step 2: Signed in → show org creation form ────────────────────────────
  return (
    <div style={{ ...pageStyle, background: "linear-gradient(135deg,#f8fafc 0%,#eff6ff 50%,#f8fafc 100%)" }}>
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4 text-white"
            style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 8px 32px rgba(99,102,241,0.4)" }}>
            <ShieldIcon />
          </div>
          <h1 className="text-2xl font-black text-gray-900">Create your organisation</h1>
          <p className="text-sm text-gray-500 mt-2">
            You&apos;ll be the admin. Invite your team once setup is complete.
          </p>
        </div>

        <form onSubmit={handleCreate} className="bg-white rounded-3xl shadow-xl border border-gray-100 p-8 space-y-5">

          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-1.5">
              Organisation name <span className="text-rose-500">*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Acme Corp"
              required
              autoFocus
              className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-400"
            />
          </div>

          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-1.5">
              URL slug <span className="text-rose-500">*</span>
            </label>
            <div className="flex items-center gap-2 border border-gray-200 rounded-xl px-4 py-3 focus-within:ring-2 focus-within:ring-indigo-400">
              <span className="text-sm text-gray-400 shrink-0">trustledger.dev/</span>
              <input
                type="text"
                value={slug}
                onChange={e => setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
                placeholder="acme-corp"
                required
                className="flex-1 text-sm font-mono focus:outline-none min-w-0"
              />
            </div>
            <p className="text-xs text-gray-400 mt-1">Auto-generated from your name. Lowercase, numbers, hyphens only.</p>
          </div>

          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-1.5">
              GitHub organisation handle <span className="text-gray-400 font-normal">(optional)</span>
            </label>
            <div className="flex items-center gap-2 border border-gray-200 rounded-xl px-4 py-3 focus-within:ring-2 focus-within:ring-indigo-400">
              <span className="text-sm text-gray-400 shrink-0">github.com/</span>
              <input
                type="text"
                value={githubOrg}
                onChange={e => setGithubOrg(e.target.value)}
                placeholder="acme-corp"
                className="flex-1 text-sm font-mono focus:outline-none min-w-0"
              />
            </div>
          </div>

          {error && (
            <p className="text-sm text-rose-600 bg-rose-50 border border-rose-200 rounded-xl px-4 py-3">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={creating || !name.trim() || !slug.trim()}
            className="w-full py-3 rounded-2xl font-bold text-white text-sm transition-all disabled:opacity-50 hover:opacity-90"
            style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)" }}
          >
            {creating ? "Creating…" : "Create organisation →"}
          </button>

          <p className="text-center text-xs text-gray-400">
            Signed in as <span className="font-semibold text-gray-600">{user.email}</span>
          </p>
        </form>
      </div>
    </div>
  );
}
