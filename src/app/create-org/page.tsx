"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
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

export default function CreateOrgPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [name,      setName]      = useState("");
  const [slug,      setSlug]      = useState("");
  const [githubOrg, setGithubOrg] = useState("");
  const [creating,  setCreating]  = useState(false);
  const [error,     setError]     = useState<string | null>(null);

  // Auto-generate slug from name
  useEffect(() => {
    setSlug(name.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""));
  }, [name]);

  // If not authenticated, redirect to login
  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [loading, user, router]);

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
      // Reload to re-fetch profile with new org membership
      window.location.href = "/onboarding";
    } catch (err: unknown) {
      const e = err as { error?: string };
      if (e?.error === "already_in_org") {
        window.location.href = "/dashboard";
        return;
      }
      if (e?.error === "slug_taken") {
        setError("That URL slug is already taken. Try a different one.");
      } else {
        setError("Failed to create organisation. Please try again.");
      }
      setCreating(false);
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <svg className="animate-spin w-6 h-6 text-indigo-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
        </svg>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12"
      style={{ background: "linear-gradient(135deg,#f8fafc 0%,#eff6ff 50%,#f8fafc 100%)" }}>
      <div className="w-full max-w-md">

        {/* Logo */}
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

        {/* Form */}
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
            <p className="text-xs text-gray-400 mt-1">Lowercase letters, numbers and hyphens only.</p>
          </div>

          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-1.5">
              GitHub organisation handle <span className="text-gray-400 font-normal">(optional — set later in Settings)</span>
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
            Signed in as <span className="font-semibold">{user?.email}</span>.{" "}
            <button type="button" onClick={() => window.location.href = "/login"}
              className="text-indigo-500 hover:text-indigo-700 underline underline-offset-2">
              Sign out
            </button>
          </p>
        </form>
      </div>
    </div>
  );
}
