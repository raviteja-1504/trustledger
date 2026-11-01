"use client";

/**
 * /verify: checks a signed report's evidence record (or a Trust Record) in the browser (lib/reportVerification.ts),
 * against the key published at /.well-known/trustledger-export-signing-key. Nothing is uploaded.
 */
import { useState } from "react";
import { verifyEvidence, type PublishedKey, type VerifyResult } from "@/lib/reportVerification";

const VERDICT: Record<VerifyResult["verdict"], { title: string; cls: string }> = {
  verified:     { title: "Verified", cls: "border-emerald-400/60 bg-emerald-400/10 text-emerald-200" },
  failed:       { title: "Does not verify", cls: "border-rose-400/60 bg-rose-400/10 text-rose-200" },
  unverifiable: { title: "Can't be verified here", cls: "border-amber-400/60 bg-amber-400/10 text-amber-200" },
};
const MARK = (ok: boolean | null) => (ok === true ? "✓" : ok === false ? "✗" : "–");

async function publishedKey(): Promise<PublishedKey | null> {
  const res = await fetch("/.well-known/trustledger-export-signing-key");
  if (!res.ok) return null;
  const k = await res.json() as Partial<PublishedKey>;
  return typeof k.key_id === "string" && typeof k.public_key_pem === "string" ? { key_id: k.key_id, public_key_pem: k.public_key_pem } : null;
}

export default function VerifyClient() {
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");

  async function check(file: File) {
    setBusy(true); setResult(null); setError(null); setName(file.name);
    try {
      let doc: unknown;
      try { doc = JSON.parse(await file.text()); } catch { throw new Error("That file isn't JSON. Choose the evidence record (…-evidence.json) saved with the PDF."); }
      setResult(await verifyEvidence(doc, await publishedKey(), globalThis.crypto.subtle));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't check the file.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <label className="block rounded-2xl border border-dashed border-white/25 bg-white/[0.03] px-6 py-8 text-center cursor-pointer hover:border-white/40">
        <span className="block text-sm font-semibold text-white">{busy ? "Checking…" : name ? `Checked ${name}: choose another file` : "Choose the evidence record (JSON)"}</span>
        <span className="block text-xs text-white/50 mt-1">The file saved next to the PDF, ending in -evidence.json. A Trust Record works too.</span>
        <input type="file" accept="application/json,.json" aria-label="Evidence record" className="sr-only"
          onChange={e => { const f = e.target.files?.[0]; if (f) void check(f); }} />
      </label>

      {error && <p role="alert" className="text-sm text-rose-300">{error}</p>}

      {result && (
        <div role="region" aria-label="Verification result" className={`rounded-2xl border px-6 py-5 ${VERDICT[result.verdict].cls}`}>
          <p className="text-lg font-black">{VERDICT[result.verdict].title}</p>
          {result.report && (
            <p className="text-xs mt-1 opacity-80">
              Report {result.report.id} · {result.report.framework} · {result.report.period_start.slice(0, 10)} to {result.report.period_end.slice(0, 10)}
            </p>
          )}
          <ul className="mt-4 space-y-2">
            {result.steps.map(s => (
              <li key={s.label} className="text-sm text-white/85">
                <span className="font-bold mr-2" aria-hidden="true">{MARK(s.ok)}</span>
                <span className="font-semibold">{s.label}:</span> <span className="break-words">{s.detail}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="text-xs text-white/55 leading-relaxed space-y-2">
        <p>
          What a pass means: the record is exactly what TrustLedger signed with its published key, and the PDF printing the
          same SHA-256 was rendered from it. It says nothing about whether the controls are effective — that is the
          auditor&apos;s conclusion.
        </p>
        <p>
          Offline: <code className="text-white/75">node scripts/verify-trust-record.mjs evidence.json key.pem</code>, with the key saved
          from <code className="text-white/75">/.well-known/trustledger-export-signing-key</code>.
        </p>
      </div>
    </div>
  );
}
