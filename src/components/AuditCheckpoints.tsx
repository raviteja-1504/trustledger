"use client";

/**
 * Audit checkpoints panel (Audit Trail page): checks the stored log against signed checkpoints, records a new one, and
 * downloads the bundle for the independent verifier (scripts/verify-audit-bundle.cjs).
 *
 * It says plainly what a checkpoint is and is not: checkpoints kept only in TrustLedger's database cannot prove the
 * database itself was not rewritten. A copy kept somewhere else can.
 */
import { useState } from "react";
import { authedFetch, getAuthHeader } from "@/lib/useRealData";
import type { CheckpointVerification, CheckpointStatus, SignedCheckpoint } from "@/lib/auditCheckpoint";

interface CheckpointsResponse { verification: CheckpointVerification; checkpoints: SignedCheckpoint[] }
type CreateResponse =
  | { created: true; checkpoint: SignedCheckpoint; external: "delivered" | "failed" | "not_configured" }
  | { created: false; reason: string; status?: CheckpointStatus };

const STATUS: Record<CheckpointStatus, { tone: "ok" | "warn" | "bad" | "idle"; title: string; body: (v: CheckpointVerification) => string }> = {
  VALID: { tone: "ok", title: "Matches every checkpoint", body: v => `The log still contains what ${v.checkpoints} signed checkpoint${v.checkpoints === 1 ? "" : "s"} recorded.` },
  NO_CHECKPOINTS: { tone: "idle", title: "No checkpoints yet", body: () => "There is nothing signed to compare the log against. Record a checkpoint to start." },
  TRUNCATED: { tone: "bad", title: "Entries are missing", body: () => "The log holds fewer entries than a signed checkpoint recorded. Recent entries may have been deleted." },
  HISTORY_MODIFIED: { tone: "bad", title: "History has changed", body: () => "An entry a checkpoint committed to no longer matches, or the log's own chain no longer verifies." },
  CHAIN_FORKED: { tone: "bad", title: "The log has forked", body: () => "Two entries share the same previous entry, so the history has two branches. It is not a clean history, and no new checkpoint will be signed over it until this is investigated." },
  CHECKPOINT_INVALID: { tone: "bad", title: "A checkpoint does not verify", body: () => "A signature, link or sequence number is wrong, or a checkpoint is missing from the middle." },
  KEY_UNTRUSTED: { tone: "warn", title: "Signed by an untrusted key", body: () => "A checkpoint was signed with a revoked key, or the key is not available to verify it." },
};
const TONE: Record<"ok" | "warn" | "bad" | "idle", string> = {
  ok: "bg-emerald-50 text-emerald-800", warn: "bg-amber-50 text-amber-900", bad: "bg-rose-50 text-rose-800", idle: "bg-gray-50 text-gray-700",
};

const CREATE_MESSAGE: Record<string, string> = {
  unchanged: "Nothing new since the last checkpoint.",
  no_entries: "There are no audit entries to checkpoint yet.",
  no_signing_key: "This deployment has no signing key configured, so checkpoints can't be signed.",
  audit_unreadable: "The audit log couldn't be read, so no checkpoint was recorded. Please try again.",
  conflict: "Another checkpoint was recorded at the same moment. Check again.",
};
const EXTERNAL: Record<string, string> = {
  delivered: "A copy was sent to your external store.",
  failed: "Sending a copy to your external store failed; the checkpoint is still recorded here.",
  not_configured: "No external store is configured, so the only copy is in TrustLedger's database.",
};

const short = (h: string) => `${h.slice(0, 10)}…`;
const when = (iso: string) => new Date(iso).toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC";

export default function AuditCheckpoints() {
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [data, setData] = useState<CheckpointsResponse | null>(null);
  const [note, setNote] = useState<{ tone: "ok" | "bad" | "idle"; text: string } | null>(null);
  const [busy, setBusy] = useState<null | "create" | "download">(null);

  async function check() {
    setState("loading");
    try {
      const r = await authedFetch<CheckpointsResponse>("/api/audit/checkpoints");
      if (!r?.verification) throw new Error("unexpected response");
      setData(r); setState("done");
    } catch { setState("error"); }
  }

  async function create() {
    setBusy("create"); setNote(null);
    try {
      const r = await authedFetch<CreateResponse>("/api/audit/checkpoints", { method: "POST" });
      if (r.created) {
        setNote({ tone: "ok", text: `Checkpoint #${r.checkpoint.payload.sequence} recorded, covering ${r.checkpoint.payload.entry_count.toLocaleString()} entries. ${EXTERNAL[r.external] ?? ""}` });
      } else if (r.reason === "verification_failed") {
        setNote({ tone: "bad", text: `No checkpoint was recorded: the log already fails verification (${STATUS[r.status as CheckpointStatus]?.title ?? r.status}). A new signature must not vouch for a log that has been altered.` });
      } else {
        setNote({ tone: "idle", text: CREATE_MESSAGE[r.reason] ?? `No checkpoint was recorded (${r.reason}).` });
      }
      await check();
    } catch (e) {
      setNote({ tone: "bad", text: e instanceof Error ? e.message : "The checkpoint couldn't be recorded. Please try again." });
    }
    setBusy(null);
  }

  async function download() {
    setBusy("download"); setNote(null);
    try {
      const res = await fetch("/api/audit/checkpoints?bundle=1", { headers: await getAuthHeader() });
      if (!res.ok) throw new Error();
      const url = URL.createObjectURL(await res.blob());
      Object.assign(document.createElement("a"), { href: url, download: "audit-bundle.json" }).click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch { setNote({ tone: "bad", text: "The bundle couldn't be downloaded. Please try again." }); }
    setBusy(null);
  }

  const v = data?.verification;
  const s = v ? STATUS[v.status] : null;
  const latest = data?.checkpoints[data.checkpoints.length - 1];

  return (
    <section aria-label="Checkpoints" className="section-card px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="max-w-xl">
          <p className="text-sm font-bold text-gray-900">Could the newest entries have been deleted?</p>
          <p className="text-xs text-gray-500 mt-0.5">
            The hash chain can&apos;t show that: a log with its latest entries removed still links together. Signed checkpoints can — each one records
            how many entries the log held and the hash of the last.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={check} disabled={state === "loading"} className="px-3 py-2 text-xs font-bold text-white bg-indigo-600 rounded-xl hover:bg-indigo-700 disabled:opacity-50">
            {state === "loading" ? "Checking…" : "Check against checkpoints"}
          </button>
          <button onClick={create} disabled={busy !== null} className="px-3 py-2 text-xs font-semibold text-indigo-700 bg-indigo-50 border border-indigo-100 rounded-xl hover:bg-indigo-100 disabled:opacity-50">
            {busy === "create" ? "Recording…" : "Record a checkpoint"}
          </button>
          <button onClick={download} disabled={busy !== null} className="px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-50">
            {busy === "download" ? "Preparing…" : "Download bundle"}
          </button>
        </div>
      </div>

      {state === "error" && <p role="alert" className="mt-3 text-xs text-rose-600">The check couldn&apos;t run. Please try again.</p>}
      {note && <p role="status" className={`mt-3 rounded-xl px-4 py-2.5 text-xs ${note.tone === "ok" ? "bg-emerald-50 text-emerald-800" : note.tone === "bad" ? "bg-rose-50 text-rose-800" : "bg-gray-50 text-gray-700"}`}>{note.text}</p>}

      {state === "done" && v && s && (
        <div className="mt-3 space-y-3">
          <div role="status" className={`rounded-xl px-4 py-3 text-xs ${TONE[s.tone]}`}>
            <p><strong>{s.title}.</strong> {s.body(v)}</p>
            {v.unanchored_entries > 0 && v.checkpoints > 0 && (
              <p className="mt-1 opacity-80">{v.unanchored_entries.toLocaleString()} newer {v.unanchored_entries === 1 ? "entry is" : "entries are"} not covered by a checkpoint yet.</p>
            )}
            {v.problems.length > 0 && (
              <ul className="mt-2 list-disc pl-4 space-y-0.5">
                {v.problems.map((p, i) => <li key={i}>{p.sequence != null ? `Checkpoint #${p.sequence}: ` : ""}{p.detail}</li>)}
              </ul>
            )}
          </div>

          {data!.checkpoints.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead><tr className="text-left text-[10px] font-black uppercase tracking-widest text-gray-400">
                  <th className="pr-4 py-1">#</th><th className="pr-4 py-1">Recorded</th><th className="pr-4 py-1">Entries covered</th><th className="pr-4 py-1">Checkpoint hash</th><th className="py-1">Key</th>
                </tr></thead>
                <tbody>
                  {[...data!.checkpoints].reverse().slice(0, 5).map(c => (
                    <tr key={c.payload.sequence} className="border-t border-gray-100 text-gray-700">
                      <td className="pr-4 py-1.5 font-bold tabular-nums">{c.payload.sequence}</td>
                      <td className="pr-4 py-1.5 whitespace-nowrap">{when(c.payload.created_at)}</td>
                      <td className="pr-4 py-1.5 tabular-nums">{c.payload.entry_count.toLocaleString()}</td>
                      <td className="pr-4 py-1.5 font-mono" title={c.payload_hash}>{short(c.payload_hash)}</td>
                      <td className="py-1.5 font-mono" title={c.payload.key_id}>{short(c.payload.key_id)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {latest && data!.checkpoints.length > 5 && <p className="text-[11px] text-gray-400 mt-1">Showing the latest 5 of {data!.checkpoints.length}.</p>}
            </div>
          )}

          <p className="text-[11px] text-gray-500">
            Checkpoints held only in TrustLedger&apos;s database can&apos;t prove the database itself wasn&apos;t rewritten, because whoever controls it could remove checkpoints
            together with log entries. Download the bundle and keep it somewhere else, or set an external store, then check it with
            <span className="font-mono"> scripts/verify-audit-bundle.cjs</span> — it needs nothing from TrustLedger.
          </p>
        </div>
      )}
    </section>
  );
}
