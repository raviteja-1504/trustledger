"use client";

/**
 * Deleting the organisation: see what goes and what stays, take a copy, request the deletion, wait out the period (cancel any
 * time), then confirm again to run it. Talks to /api/orgs/delete (app/api/orgs/delete/route.ts); the server enforces every step.
 */
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { authedFetch } from "@/lib/useRealData";

interface Count { key: string; label: string; count: number | null }
interface Open { id: string; status: "pending" | "executing" | "failed"; execute_after: string; error: string | null; requested_by_email: string | null }
interface State {
  organization: { name: string; slug: string } | null;
  preview: { deleted: Count[]; retained: Count[]; exports: Array<{ label: string; href: string }> };
  request: Open | null;
  delay_hours: number;
  step_up: "totp" | "recent_signin";
}

const fmt = (iso: string) => new Date(iso).toLocaleString();
const reason = (e: unknown) => (e instanceof Error && e.message ? e.message : "Something went wrong. Please try again.");

export default function DeleteOrganisation() {
  const [state, setState] = useState<State | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState<null | "request" | "cancel" | "execute">(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    try { setState(await authedFetch<State>("/api/orgs/delete")); setLoadError(false); }
    catch { setLoadError(true); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function act(action: "request" | "cancel" | "execute") {
    setBusy(action); setMessage(null);
    try {
      await authedFetch("/api/orgs/delete", { method: "POST", body: JSON.stringify({ action, confirm, code: code || undefined }) });
      if (action === "execute") { window.location.href = "/create-org"; return; }
      setConfirm(""); setCode("");
      setMessage({ ok: true, text: action === "request" ? "Deletion requested. Nothing is deleted until the waiting period is over and you confirm again." : "Deletion cancelled." });
      await load();
    } catch (e) { setMessage({ ok: false, text: reason(e) }); }
    finally { setBusy(null); }
  }

  if (loadError) return <p className="text-xs text-rose-600">Couldn&apos;t load the deletion details. Please refresh.</p>;
  if (!state) return <p className="text-xs text-gray-400">Loading…</p>;

  const slug = state.organization?.slug ?? "";
  const open = state.request;
  const ready = !!open && open.status !== "executing" && Date.now() >= Date.parse(open.execute_after);
  const inputs = (
    <div className="grid sm:grid-cols-2 gap-3">
      <label className="block text-xs font-semibold text-gray-700">
        Type <code className="font-mono bg-gray-100 px-1 rounded">{slug}</code> to confirm
        <input value={confirm} onChange={e => setConfirm(e.target.value)} autoComplete="off" className="mt-1 w-full px-3 py-2 text-sm border border-gray-200 rounded-xl" />
      </label>
      {state.step_up === "totp" ? (
        <label className="block text-xs font-semibold text-gray-700">
          Authenticator code
          <input value={code} onChange={e => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={8} className="mt-1 w-full px-3 py-2 text-sm border border-gray-200 rounded-xl" />
        </label>
      ) : (
        <p className="text-[11px] text-gray-500 self-end">You must have signed in within the last 10 minutes. If not, sign out and back in first.</p>
      )}
    </div>
  );

  return (
    <div className="space-y-4">
      <div className="grid sm:grid-cols-2 gap-3">
        <div className="bg-rose-50 rounded-xl p-4 border border-rose-200">
          <p className="text-xs font-bold text-rose-800 mb-2">Deleted</p>
          <ul className="text-xs text-rose-700 space-y-0.5">
            {state.preview.deleted.map(d => <li key={d.key}>{d.label}: <strong>{d.count ?? "?"}</strong></li>)}
          </ul>
        </div>
        <div className="bg-gray-50 rounded-xl p-4 border border-gray-200">
          <p className="text-xs font-bold text-gray-800 mb-2">Kept, as evidence</p>
          <ul className="text-xs text-gray-700 space-y-0.5">
            {state.preview.retained.map(d => <li key={d.key}>{d.label}: <strong>{d.count ?? "?"}</strong></li>)}
          </ul>
          <p className="text-[11px] text-gray-500 mt-2">These records are immutable by design. They stay against an anonymised organisation record.</p>
        </div>
      </div>

      <p className="text-xs text-gray-600">
        Take a copy first:{" "}
        {state.preview.exports.map((x, i) => <span key={x.href}>{i > 0 && " · "}<Link href={x.href} className="text-indigo-600 font-semibold hover:underline">{x.label}</Link></span>)}
      </p>

      {!open && (
        <div className="space-y-3">
          {inputs}
          <p className="text-xs text-gray-500">After you request it there is a <strong>{state.delay_hours}-hour</strong> waiting period. You can cancel at any time before you confirm the final step.</p>
          <button onClick={() => act("request")} disabled={busy !== null || confirm !== slug}
            className="px-5 py-2 text-sm font-bold rounded-xl border-2 border-rose-600 text-rose-600 hover:bg-rose-600 hover:text-white disabled:opacity-40 transition-colors">
            {busy === "request" ? "Requesting…" : "Request deletion"}
          </button>
        </div>
      )}

      {open && (
        <div className="space-y-3">
          <div className={`rounded-xl p-4 border text-xs ${open.status === "failed" ? "bg-amber-50 border-amber-200 text-amber-900" : "bg-rose-50 border-rose-200 text-rose-800"}`}>
            {open.status === "pending" && <p><strong>Deletion requested</strong>{open.requested_by_email ? ` by ${open.requested_by_email}` : ""}. {ready ? "The waiting period is over: you can confirm the deletion now." : `It cannot run before ${fmt(open.execute_after)}.`}</p>}
            {open.status === "executing" && <p><strong>Deletion is running.</strong> It cannot be cancelled now.</p>}
            {open.status === "failed" && <p><strong>The last attempt did not complete, and nothing was deleted.</strong> {open.error ? `(${open.error}) ` : ""}You can run it again or cancel.</p>}
          </div>
          {ready && inputs}
          <div className="flex flex-wrap gap-3">
            {ready && (
              <button onClick={() => act("execute")} disabled={busy !== null || confirm !== slug}
                className="px-5 py-2 text-sm font-bold rounded-xl bg-rose-600 text-white hover:bg-rose-700 disabled:opacity-40 transition-colors">
                {busy === "execute" ? "Deleting…" : "Delete the organisation permanently"}
              </button>
            )}
            {open.status !== "executing" && (
              <button onClick={() => act("cancel")} disabled={busy !== null}
                className="px-5 py-2 text-sm font-bold rounded-xl border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-40 transition-colors">
                {busy === "cancel" ? "Cancelling…" : "Cancel deletion"}
              </button>
            )}
          </div>
        </div>
      )}

      {message && <p role="status" className={`text-xs ${message.ok ? "text-emerald-700" : "text-rose-600"}`}>{message.text}</p>}
    </div>
  );
}
