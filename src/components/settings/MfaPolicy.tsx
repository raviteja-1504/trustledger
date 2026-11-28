"use client";

/**
 * Require two-factor authentication for everyone in the organisation (app/api/security-policy). Shows how many members would be
 * stopped until they enrol, and only lets an admin switch it on once they have two-factor themselves.
 */
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { authedFetch } from "@/lib/useRealData";

interface Policy { require_mfa: boolean; set_up: boolean; you_have_mfa: boolean; members_total: number; members_without_mfa: number }

export default function MfaPolicy() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    try { setPolicy(await authedFetch<Policy>("/api/security-policy")); setFailed(false); } catch { setFailed(true); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function set(next: boolean) {
    setBusy(true); setMessage(null);
    try {
      await authedFetch("/api/security-policy", { method: "PATCH", body: JSON.stringify({ require_mfa: next }) });
      setMessage({ ok: true, text: next ? "Two-factor is now required. Members without it must enrol before they can continue." : "Two-factor is no longer required." });
      await load();
    } catch (e) { setMessage({ ok: false, text: e instanceof Error && e.message ? e.message : "Couldn't save that. Please try again." }); }
    finally { setBusy(false); }
  }

  if (failed) return <p className="text-xs text-rose-600">Couldn&apos;t load the two-factor policy. Please refresh.</p>;
  if (!policy) return <p className="text-xs text-gray-400">Loading…</p>;

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-600">
        {policy.require_mfa
          ? <>Two-factor is <strong>required</strong>: a member without it is stopped until they turn it on.</>
          : <>Two-factor is optional. {policy.members_without_mfa} of {policy.members_total} member{policy.members_total === 1 ? "" : "s"} {policy.members_without_mfa === 1 ? "has" : "have"} not turned it on.</>}
      </p>
      {!policy.set_up && <p className="text-xs text-amber-700">This needs a database update first (migration 20261129_require_mfa).</p>}
      {!policy.require_mfa && !policy.you_have_mfa && policy.set_up && (
        <p className="text-xs text-amber-700">Turn on two-factor for your own account first, so this cannot lock you out. <Link href="/profile" className="font-semibold underline">Open your profile</Link></p>
      )}
      <button onClick={() => set(!policy.require_mfa)} disabled={busy || !policy.set_up || (!policy.require_mfa && !policy.you_have_mfa)}
        className={`px-5 py-2 text-sm font-bold rounded-xl transition-colors disabled:opacity-40 ${policy.require_mfa ? "border border-gray-300 text-gray-700 hover:bg-gray-50" : "bg-indigo-600 text-white hover:bg-indigo-700"}`}>
        {busy ? "Saving…" : policy.require_mfa ? "Stop requiring two-factor" : "Require two-factor for everyone"}
      </button>
      {message && <p role="status" className={`text-xs ${message.ok ? "text-emerald-700" : "text-rose-600"}`}>{message.text}</p>}
    </div>
  );
}
