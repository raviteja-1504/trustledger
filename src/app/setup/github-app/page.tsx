"use client";

import { useEffect, useState } from "react";
import { authedFetch } from "@/lib/useRealData";

/**
 * One-click GitHub App creation via the manifest flow.
 * Submits the manifest from /api/github-app/manifest to GitHub, which creates
 * the app and redirects back to that same endpoint with ?code=... to finish setup.
 */
export default function GithubAppSetupPage() {
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState<string | null>(null);
  // Creating another app does not replace the one in use: only changing the GITHUB_APP_* environment variables does.
  const [alreadySet, setAlreadySet] = useState(false);
  useEffect(() => {
    authedFetch<{ configured: boolean }>("/api/github-app/info").then(i => setAlreadySet(!!i.configured)).catch(() => {});
  }, []);

  async function createApp() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/github-app/manifest");
      if (!res.ok) throw new Error(`Failed to load manifest (${res.status})`);
      const manifest = await res.json();

      const form = document.createElement("form");
      form.method = "post";
      form.action = "https://github.com/settings/apps/new";

      const input = document.createElement("input");
      input.type  = "hidden";
      input.name  = "manifest";
      input.value = JSON.stringify(manifest);
      form.appendChild(input);

      document.body.appendChild(form);
      form.submit();
    } catch (e) {
      setError(e instanceof Error ? e.message : "We couldn't start GitHub App creation. Please try again.");
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

      {alreadySet && (
        <div role="note" className="bg-amber-50 border border-amber-200 rounded-2xl p-4 space-y-1">
          <p className="text-sm font-bold text-amber-900">This deployment already has a GitHub App</p>
          <p className="text-xs text-amber-800 leading-relaxed">
            You only need this page to replace it. Creating a new app changes nothing by itself; TrustLedger switches to it only if you put its credentials into the
            <code className="font-mono"> GITHUB_APP_*</code> environment variables, and installations of the current app would then stop working. Customers never need this page: they click Install on GitHub.
          </p>
        </div>
      )}

      <div className="space-y-3">
        <button
          onClick={() => createApp()}
          disabled={loading}
          className="w-full py-3 rounded-2xl font-bold text-white text-sm transition-all disabled:opacity-50"
          style={{ background: "#24292f" }}
        >
          {loading ? "Redirecting to GitHub…" : "Create the GitHub App →"}
        </button>
      </div>

      {error && <p className="text-sm text-rose-600">{error}</p>}

      <p className="text-xs text-gray-400">
        You&apos;ll be redirected to github.com to review and confirm the app's permissions.
      </p>
    </div>
  );
}
