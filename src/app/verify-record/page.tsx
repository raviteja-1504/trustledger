"use client";

import { useState } from "react";
import AuthGuard from "@/components/AuthGuard";
import { authedFetch } from "@/lib/useRealData";

type Status = "valid" | "tampered" | "unknown_key" | "unsigned" | "malformed" | "not_configured";

interface VerifyResult {
  status: Status;
  message: string;
  summary: null | {
    organization: string | null;
    change: { repository: string; pull_request: number; commit: string };
    scanned_at?: string; generated_at?: string; engine_version?: string | null;
    verdict?: { overall_risk: string; merge_gate: string; ai_share_percent: number; open_blocking_violations: number };
    summary?: { findings: number; critical: number; high: number; introduced_by_pr: number; accepted_or_false_positive: number; files: number; files_attested: number };
  };
}

const STATUS_STYLE: Record<Status, { label: string; bg: string; text: string; border: string; icon: string }> = {
  valid:          { label: "Valid",       bg: "#f0fdf4", text: "#15803d", border: "#bbf7d0", icon: "✓" },
  tampered:       { label: "Tampered",    bg: "#fef2f2", text: "#be123c", border: "#fecdd3", icon: "✕" },
  unknown_key:    { label: "Unknown key", bg: "#fffbeb", text: "#a16207", border: "#fde68a", icon: "?" },
  unsigned:       { label: "Unsigned",    bg: "#f8fafc", text: "#475569", border: "#e2e8f0", icon: "–" },
  malformed:      { label: "Not a Trust Record", bg: "#f8fafc", text: "#475569", border: "#e2e8f0", icon: "!" },
  not_configured: { label: "Can't verify", bg: "#f8fafc", text: "#475569", border: "#e2e8f0", icon: "!" },
};

const fmt = (iso?: string) => (iso ? new Date(iso).toLocaleString() : "—");

export default function VerifyRecordPage() {
  const [text, setText] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function verify(raw: string) {
    setBusy(true); setErr(null); setResult(null);
    let document: unknown;
    try { document = JSON.parse(raw); } catch {
      setResult({ status: "malformed", message: "That isn't valid JSON, so it can't be a Trust Record.", summary: null });
      setBusy(false);
      return;
    }
    try {
      setResult(await authedFetch<VerifyResult>("/api/trust-record/verify", { method: "POST", body: JSON.stringify({ document }) }));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Verification failed. Please try again.");
    } finally { setBusy(false); }
  }

  async function onFile(f: File | undefined) {
    if (!f) return;
    setFileName(f.name);
    const raw = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result ?? ""));
      reader.onerror = () => reject(reader.error);
      reader.readAsText(f);
    }).catch(() => "");
    setText(raw);
    void verify(raw);
  }

  const s = result ? STATUS_STYLE[result.status] : null;
  const sum = result?.summary;

  return (
    <AuthGuard>
      <div className="max-w-3xl mx-auto space-y-5 pb-10">
        <div>
          <h1 className="text-xl font-black text-gray-900 tracking-tight">Verify a Trust Record</h1>
          <p className="text-sm text-gray-500 mt-1 max-w-2xl">
            Check that a Trust Record downloaded from a PR page is genuine and unchanged. The file is checked against this
            server&apos;s signing key and isn&apos;t stored.
          </p>
        </div>

        <div
          className="rounded-2xl border-2 border-dashed border-gray-200 bg-white px-5 py-6 text-center"
          onDragOver={e => e.preventDefault()}
          onDrop={e => { e.preventDefault(); void onFile(e.dataTransfer.files?.[0]); }}
        >
          <p className="text-sm font-semibold text-gray-700">Drop a Trust Record here</p>
          <p className="text-xs text-gray-400 mt-1">or</p>
          <label htmlFor="record-file" className="inline-block mt-2 text-xs font-bold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 rounded-lg px-3 py-1.5 cursor-pointer">
            Choose a file
          </label>
          <input id="record-file" type="file" accept="application/json,.json" className="sr-only" onChange={e => void onFile(e.target.files?.[0])} />
          {fileName && <p className="text-[11px] text-gray-500 mt-2 font-mono">{fileName}</p>}
        </div>

        <details className="group">
          <summary className="text-xs font-semibold text-indigo-600 cursor-pointer select-none">Or paste its JSON</summary>
          <div className="mt-2 space-y-2">
            <label htmlFor="record-json" className="sr-only">Trust Record JSON</label>
            <textarea id="record-json" value={text} onChange={e => setText(e.target.value)} rows={8}
              className="w-full rounded-xl border border-gray-200 bg-white px-3 py-2 font-mono text-[11px] text-gray-800 focus:outline-none focus:ring-2 focus:ring-indigo-200"
              placeholder='{ "record": { "schema": "trustledger.trust-record/v1", … }, "signature": { … } }' />
            <button onClick={() => void verify(text)} disabled={busy || !text.trim()}
              className="text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg px-3.5 py-2 disabled:opacity-50">
              {busy ? "Checking…" : "Verify"}
            </button>
          </div>
        </details>

        {busy && <p className="text-sm text-gray-500">Checking…</p>}
        {err && <p className="text-sm text-rose-600">{err}</p>}

        {result && s && (
          <div className="rounded-2xl border px-5 py-4 space-y-3" style={{ background: s.bg, borderColor: s.border }}>
            <div className="flex items-center gap-2.5">
              <span className="w-8 h-8 rounded-full flex items-center justify-center text-base font-black" style={{ color: s.text, background: "white", border: `1px solid ${s.border}` }}>{s.icon}</span>
              <p className="text-lg font-black" style={{ color: s.text }}>{s.label}</p>
            </div>
            <p className="text-sm text-gray-700">{result.message}</p>
            {sum && (
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 text-xs pt-2 border-t" style={{ borderColor: s.border }}>
                <dt className="text-gray-500">Change</dt>
                <dd className="text-gray-900 font-mono break-all">{sum.change.repository} · PR #{sum.change.pull_request} · {sum.change.commit.slice(0, 10)}</dd>
                {sum.organization && (<><dt className="text-gray-500">Organization</dt><dd className="text-gray-900">{sum.organization}</dd></>)}
                <dt className="text-gray-500">Scanned</dt><dd className="text-gray-900">{fmt(sum.scanned_at)}</dd>
                <dt className="text-gray-500">Record generated</dt><dd className="text-gray-900">{fmt(sum.generated_at)}</dd>
                {sum.verdict && (<>
                  <dt className="text-gray-500">Verdict</dt>
                  <dd className="text-gray-900">{sum.verdict.overall_risk} risk · merge gate {sum.verdict.merge_gate} · {sum.verdict.ai_share_percent}% AI</dd>
                </>)}
                {sum.summary && (<>
                  <dt className="text-gray-500">Findings</dt>
                  <dd className="text-gray-900">{sum.summary.findings} ({sum.summary.critical} critical, {sum.summary.high} high) · {sum.summary.introduced_by_pr} introduced by the PR · {sum.summary.accepted_or_false_positive} accepted</dd>
                  <dt className="text-gray-500">Attestation</dt>
                  <dd className="text-gray-900">{sum.summary.files_attested} of {sum.summary.files} files attested</dd>
                </>)}
              </dl>
            )}
            {result.status !== "valid" && sum && (
              <p className="text-[11px] text-gray-500">The details above are what the file claims. They are only trustworthy when the record is valid.</p>
            )}
          </div>
        )}
      </div>
    </AuthGuard>
  );
}
