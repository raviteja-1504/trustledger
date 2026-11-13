"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { authedFetch } from "@/lib/useRealData";
import { useTimezone, formatDateOnly } from "@/lib/timezone";

/**
 * Settings → API Access: create and revoke the API keys a CI job or script uses to submit scans (POST /api/scans with an X-TrustLedger-Key
 * header). What a key may do is fixed by the server (lib/permissions.ts, API_KEY_PERMISSIONS), so this screen says exactly that instead of
 * offering permission switches that would not be enforced. A key is only ever created by the server: if that fails the reason is shown,
 * never a locally invented key that would not work.
 */

interface ApiKeyRow { id: string; name: string; key_prefix: string; created_at: string; last_used: string | null; expires_at: string | null; revoked?: boolean }

export const KEY_CAN = [
  "Submit scans and read their results",
  "Resolve violations and manage incidents",
  "Create reports",
];
export const KEY_CANNOT = [
  "Attest (sign off) files: that is always a named person",
  "Create, list or revoke API keys",
  "Change settings, the team or billing",
];
const EXPIRY: Array<{ label: string; days: number }> = [
  { label: "Never expires", days: 0 }, { label: "30 days", days: 30 }, { label: "90 days", days: 90 }, { label: "1 year", days: 365 },
];

/** The reason to show for a failed key call, in words. */
export function apiKeyErrorText(e: unknown): string {
  const code = (e as { code?: string })?.code ?? (e instanceof Error ? e.message : "");
  if (code === "insufficient_permissions") return "Only an administrator can create or revoke API keys.";
  if (code === "rate_limited") return "Too many keys were created recently. Try again in an hour.";
  if (code === "missing_name") return "Give the key a name.";
  return "We couldn't do that. Please try again.";
}

export function ApiAccessTab() {
  const { profile } = useAuth();
  const tz = useTimezone();
  const [keys, setKeys] = useState<ApiKeyRow[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [days, setDays] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [generated, setGenerated] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!profile?.org_id) return;
    authedFetch<{ keys: ApiKeyRow[] }>("/api/keys")
      .then(r => setKeys((r.keys ?? []).filter(k => !k.revoked)))
      .catch(e => { setKeys([]); setLoadError(apiKeyErrorText(e)); });
  }, [profile?.org_id]);

  async function makeKey() {
    if (!name.trim() || busy) return;
    setBusy(true); setError(null);
    try {
      const res = await authedFetch<{ raw_key: string; id: string; key_prefix: string; created_at: string }>("/api/keys", {
        method: "POST",
        body: JSON.stringify({ name: name.trim(), ...(days > 0 ? { expires_days: days } : {}) }),
      });
      setGenerated(res.raw_key);
      setKeys(prev => [{
        id: res.id, name: name.trim(), key_prefix: res.key_prefix, created_at: res.created_at, last_used: null,
        expires_at: days > 0 ? new Date(Date.now() + days * 86400_000).toISOString() : null,
      }, ...(prev ?? [])]);
      setName(""); setDays(0);
    } catch (e) { setError(apiKeyErrorText(e)); }
    setBusy(false);
  }

  async function revoke(id: string) {
    setError(null);
    try {
      await authedFetch("/api/keys", { method: "DELETE", body: JSON.stringify({ id }) });
      setKeys(prev => (prev ?? []).filter(k => k.id !== id));
    } catch (e) { setError(apiKeyErrorText(e)); }
  }

  function copyKey() {
    if (!generated) return;
    navigator.clipboard?.writeText(generated).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const fmt = (iso: string) => formatDateOnly(new Date(iso), tz);
  const origin = typeof window !== "undefined" ? window.location.origin : "https://<your-deployment>";

  return (
    <div className="space-y-5">
      <div className="section-card animate-fade-up p-5 space-y-3">
        <p className="text-sm font-bold text-gray-900">What an API key is for</p>
        <p className="text-xs text-gray-600 leading-relaxed">
          A CI job or script uses a key to submit scans and read their results for this organisation, without a person signing in.
          Scans sent with a key count against your plan like any other scan.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div>
            <p className="font-bold text-emerald-700 mb-1">A key can</p>
            <ul className="space-y-0.5 text-gray-600 list-disc pl-4">{KEY_CAN.map(t => <li key={t}>{t}</li>)}</ul>
          </div>
          <div>
            <p className="font-bold text-rose-700 mb-1">A key can never</p>
            <ul className="space-y-0.5 text-gray-600 list-disc pl-4">{KEY_CANNOT.map(t => <li key={t}>{t}</li>)}</ul>
          </div>
        </div>
        <p className="text-[11px] font-semibold text-gray-500 pt-1">Use it like this</p>
        <pre className="text-[11px] leading-relaxed bg-gray-900 text-gray-100 rounded-xl p-3 overflow-x-auto"><code>{`curl -X POST ${origin}/api/scans \\
  -H "X-TrustLedger-Key: <your key>" \\
  -H "Content-Type: application/json" \\
  -d '{"repo":"acme/api","pr_number":482,"commit_sha":"<sha>","files":[{"path":"src/app.ts","content":"..."}]}'`}</code></pre>
        <p className="text-[11px] text-gray-500">Up to 50 files per request. Treat a key like a password: anyone who has it can submit scans for this organisation.</p>
      </div>

      {generated && (
        <div role="alert" className="bg-amber-50 border-2 border-amber-300 rounded-2xl p-5 space-y-3">
          <p className="text-xs font-bold text-amber-800">Copy this key now. It will not be shown again.</p>
          <div className="flex items-center gap-2 bg-white border border-amber-200 rounded-xl px-4 py-3">
            <code className="font-mono text-xs text-gray-800 flex-1 break-all select-all">{generated}</code>
            <button type="button" onClick={copyKey} className="shrink-0 px-3 py-1.5 text-xs font-bold rounded-lg" style={{ background: copied ? "#d1fae5" : "#f1f5f9", color: copied ? "#065f46" : "#374151" }}>
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          <button type="button" onClick={() => setGenerated(null)} className="text-xs text-amber-700 hover:text-amber-900 font-semibold">I&apos;ve copied it: dismiss</button>
        </div>
      )}

      <div className="section-card animate-fade-up p-5 space-y-4">
        <p className="text-sm font-bold text-gray-900">Create an API key</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label htmlFor="api-key-name" className="block text-[10px] font-semibold text-gray-500 mb-1.5">Name</label>
            <input id="api-key-name" value={name} onChange={e => setName(e.target.value)} placeholder="e.g. GitHub Actions"
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
          </div>
          <div>
            <label htmlFor="api-key-expiry" className="block text-[10px] font-semibold text-gray-500 mb-1.5">Expires</label>
            <select id="api-key-expiry" value={days} onChange={e => setDays(Number(e.target.value))}
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-400">
              {EXPIRY.map(o => <option key={o.days} value={o.days}>{o.label}</option>)}
            </select>
          </div>
        </div>
        {error && <p role="alert" className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-lg px-3 py-2">{error}</p>}
        <button type="button" onClick={makeKey} disabled={!name.trim() || busy}
          className="px-4 py-2 text-sm font-bold text-white rounded-xl disabled:opacity-40" style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)" }}>
          {busy ? "Creating…" : "Create key"}
        </button>
      </div>

      <div className="section-card animate-fade-up overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <p className="text-sm font-bold text-gray-900">Active keys</p>
          <span className="text-xs text-gray-400">{keys?.length ?? 0} key{(keys?.length ?? 0) === 1 ? "" : "s"}</span>
        </div>
        {loadError ? (
          <p role="alert" className="px-5 py-6 text-sm text-rose-700">{loadError}</p>
        ) : keys === null ? (
          <p className="px-5 py-6 text-sm text-gray-400">Loading…</p>
        ) : keys.length === 0 ? (
          <div className="py-10 text-center">
            <p className="text-sm text-gray-400">No API keys yet</p>
            <p className="text-xs text-gray-400 mt-1">Create one above to submit scans from a script or CI job.</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-50">
            {keys.map(k => {
              const expired = !!k.expires_at && new Date(k.expires_at) < new Date();
              return (
                <div key={k.id} className="flex items-center gap-4 px-5 py-3.5">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-sm font-bold text-gray-800">{k.name}</p>
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${expired ? "text-rose-700 bg-rose-50 border-rose-100" : "text-emerald-700 bg-emerald-50 border-emerald-100"}`}>{expired ? "expired" : "active"}</span>
                    </div>
                    <p className="text-[10px] text-gray-400 mt-0.5 font-mono break-all">
                      {k.key_prefix} · Created {fmt(k.created_at)}
                      {k.expires_at ? ` · ${expired ? "Expired" : "Expires"} ${fmt(k.expires_at)}` : " · Never expires"}
                      {k.last_used ? ` · Last used ${fmt(k.last_used)}` : " · Never used"}
                    </p>
                  </div>
                  <button type="button" onClick={() => revoke(k.id)} aria-label={`Revoke ${k.name}`}
                    className="shrink-0 text-xs font-semibold text-rose-600 bg-rose-50 border border-rose-200 px-3 py-1.5 rounded-lg hover:bg-rose-100 transition-colors">
                    Revoke
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
