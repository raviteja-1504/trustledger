"use client";

import { useState } from "react";

/**
 * One-click GitHub App creation via the manifest flow.
 * Submits the manifest from /api/github-app/manifest to GitHub, which creates
 * the app and redirects back to that same endpoint with ?code=... to finish setup.
 */
export default function GithubAppSetupPage() {
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState<string | null>(null);

  async function createApp(target: "user" | "novapay") {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/github-app/manifest");
      if (!res.ok) throw new Error(`Failed to load manifest (${res.status})`);
      const manifest = await res.json();

      const form = document.createElement("form");
      form.method = "post";
      form.action = target === "novapay"
        ? "https://github.com/organizations/novapay/settings/apps/new"
        : "https://github.com/settings/apps/new";

      const input = document.createElement("input");
      input.type  = "hidden";
      input.name  = "manifest";
      input.value = JSON.stringify(manifest);
      form.appendChild(input);

      document.body.appendChild(form);
      form.submit();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setLoading(false);
    }
  }

  return (
    <div className="max-w-lg mx-auto py-16 px-6 space-y-6">
      <div>
        <h1 className="text-xl font-black text-gray-900">Create the TrustLedger GitHub App</h1>
        <p className="text-sm text-gray-500 mt-2">
          This creates a new GitHub App pre-configured with the correct webhook URL,
          permissions, and event subscriptions (pull requests, pushes, check runs).
          After creation, GitHub will show you the App ID, webhook secret, and private key —
          copy those into the project&apos;s environment variables.
        </p>
      </div>

      <div className="space-y-3">
        <button
          onClick={() => createApp("novapay")}
          disabled={loading}
          className="w-full py-3 rounded-2xl font-bold text-white text-sm transition-all disabled:opacity-50"
          style={{ background: "#24292f" }}
        >
          {loading ? "Redirecting to GitHub…" : "Create app under novapay org →"}
        </button>
        <button
          onClick={() => createApp("user")}
          disabled={loading}
          className="w-full py-3 rounded-2xl font-bold text-gray-700 text-sm border border-gray-200 transition-all disabled:opacity-50"
        >
          Create under my personal account instead
        </button>
      </div>

      {error && <p className="text-sm text-rose-600">{error}</p>}

      <p className="text-xs text-gray-400">
        You&apos;ll be redirected to github.com to review and confirm the app's permissions.
      </p>
    </div>
  );
}
