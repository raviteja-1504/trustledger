"use client";

/**
 * The scan queue: how many scans are waiting, running, done and failed over the last week, the jobs that need attention with the
 * reason, and a replay for a failed one. Reads /api/scan-jobs; a replay queues the ORIGINAL job again.
 */
import { useCallback, useEffect, useState } from "react";
import { authedFetch } from "@/lib/useRealData";

interface Job { id: string; repo_full_name: string; pr_number: number | null; head_sha: string | null; status: "queued" | "running" | "succeeded" | "failed" | "dead"; attempts: number; max_attempts: number; last_error: string | null; result: string | null; updated_at: string }
interface Overview { set_up: boolean; counts: Record<"queued" | "running" | "succeeded" | "failed" | "dead", number>; attention: Job[]; recent: Job[] }

const LABEL: Record<Job["status"], string> = { queued: "Waiting", running: "Running", succeeded: "Done", failed: "Failed, will retry", dead: "Failed" };
const TONE: Record<Job["status"], string> = { queued: "text-gray-600", running: "text-indigo-600", succeeded: "text-emerald-700", failed: "text-amber-700", dead: "text-rose-700" };

export default function ScanQueue() {
  const [data, setData] = useState<Overview | null>(null);
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    try { setData(await authedFetch<Overview>("/api/scan-jobs")); setFailed(false); } catch { setFailed(true); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function replay(job: Job) {
    setBusy(job.id); setMessage(null);
    try {
      await authedFetch("/api/scan-jobs", { method: "POST", body: JSON.stringify({ id: job.id }) });
      setMessage({ ok: true, text: `Queued ${job.repo_full_name}${job.pr_number ? ` #${job.pr_number}` : ""} again.` });
      await load();
    } catch (e) { setMessage({ ok: false, text: e instanceof Error && e.message ? e.message : "Couldn't queue that again. Please try again." }); }
    finally { setBusy(null); }
  }

  if (failed) return <p className="text-xs text-rose-600">Couldn&apos;t load the scan queue. Please refresh.</p>;
  if (!data) return <p className="text-xs text-gray-400">Loading…</p>;
  if (!data.set_up) return <p className="text-xs text-amber-700">The scan queue needs a database update first (migration 20261129_scan_jobs).</p>;

  const c = data.counts;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-gray-600" aria-label="Scan queue, last 7 days">
        <span>Waiting <strong>{c.queued}</strong></span>
        <span>Running <strong>{c.running}</strong></span>
        <span>Done <strong>{c.succeeded}</strong></span>
        <span className={c.failed ? "text-amber-700" : ""}>Retrying <strong>{c.failed}</strong></span>
        <span className={c.dead ? "text-rose-700" : ""}>Failed <strong>{c.dead}</strong></span>
        <button onClick={() => void load()} className="ml-auto font-semibold text-indigo-600 hover:underline">Refresh</button>
      </div>

      {data.attention.length === 0 ? (
        <p className="text-xs text-emerald-700">Nothing needs attention: no failed or stuck scans in the last 7 days.</p>
      ) : (
        <ul className="divide-y divide-gray-100 border border-gray-100 rounded-xl">
          {data.attention.map(j => (
            <li key={j.id} className="px-4 py-3 flex flex-wrap items-start gap-3">
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold text-gray-800 break-all">{j.repo_full_name}{j.pr_number ? ` · PR #${j.pr_number}` : ""} <span className="font-mono text-gray-400">{j.head_sha?.slice(0, 7)}</span></p>
                <p className={`text-[11px] ${TONE[j.status]}`}>{LABEL[j.status]} · attempt {j.attempts} of {j.max_attempts}</p>
                {j.last_error && <p className="text-[11px] text-gray-500 mt-0.5 break-words">{j.last_error}</p>}
              </div>
              {(j.status === "failed" || j.status === "dead") && (
                <button onClick={() => replay(j)} disabled={busy !== null}
                  className="shrink-0 px-3 py-1.5 text-xs font-bold rounded-lg border border-indigo-200 text-indigo-700 hover:bg-indigo-50 disabled:opacity-40">
                  {busy === j.id ? "Queuing…" : "Replay"}
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {message && <p role="status" className={`text-xs ${message.ok ? "text-emerald-700" : "text-rose-600"}`}>{message.text}</p>}
    </div>
  );
}
