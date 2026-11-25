"use client";

/**
 * "Check signature" for one attested file (PR page). Asks /api/attest/verify, which re-checks the attestation's
 * Ed25519 signature and that the signed content really describes this record, and says what came back in plain words.
 * Lazy on purpose: nothing is fetched until someone asks.
 */
import { useState } from "react";
import { authedFetch } from "@/lib/useRealData";

interface VerifyResponse { verify_result: string; has_signature: boolean; is_inherited: boolean; reviewer_email?: string; created_at?: string }
type Tone = "ok" | "warn" | "bad" | "idle";

const RESULT: Record<string, { tone: Tone; title: string; body: string }> = {
  valid: { tone: "ok", title: "Signature valid", body: "Signed with TrustLedger's signing key, and the record has not been altered since." },
  key_retired: { tone: "ok", title: "Signature valid", body: "The key that signed it has since been retired, which is normal after a key rotation. The signature itself still checks out." },
  key_revoked: { tone: "bad", title: "Signed with a revoked key", body: "That key was withdrawn. Do not rely on this record." },
  invalid: { tone: "bad", title: "Signature does not match", body: "The attestation record may have been altered after it was signed." },
  payload_db_mismatch: { tone: "bad", title: "Signed content doesn't match this record", body: "The signature is real, but the content it covers describes a different attestation. It may have been swapped." },
  payload_schema_invalid: { tone: "bad", title: "Signed content is malformed", body: "The record's signed content is incomplete, so it can't be relied on." },
  key_not_found: { tone: "bad", title: "Signing key not found", body: "The key that signed this record can't be found, so the signature can't be checked." },
  no_signature: { tone: "idle", title: "Recorded without a signature", body: "This was attested before signing was switched on. It has a stored hash only." },
  inherited_source_not_found: { tone: "warn", title: "Carried over, original not found", body: "This approval was carried over from an earlier scan, and that earlier record can no longer be found." },
  inherited_content_changed: { tone: "warn", title: "Carried over, but the file changed", body: "This approval was carried over from an earlier scan, but the file's content has changed since, so it no longer applies." },
};
const TONE: Record<Tone, string> = { ok: "bg-emerald-50 text-emerald-800", warn: "bg-amber-50 text-amber-900", bad: "bg-rose-50 text-rose-800", idle: "bg-gray-50 text-gray-700" };

export default function AttestationProof({ attestationId }: { attestationId: string }) {
  const [state, setState] = useState<"idle" | "checking" | "done" | "error">("idle");
  const [res, setRes] = useState<VerifyResponse | null>(null);

  async function check() {
    setState("checking");
    try {
      const r = await authedFetch<VerifyResponse>(`/api/attest/verify?id=${encodeURIComponent(attestationId)}`);
      if (!r || typeof r.verify_result !== "string") throw new Error("unexpected response");
      setRes(r); setState("done");
    } catch { setState("error"); }
  }

  const info = res ? (RESULT[res.verify_result] ?? { tone: "warn" as const, title: "Unrecognised result", body: `The check returned "${res.verify_result}".` }) : null;
  // A carried-over approval that still verifies is described as such, since its signature is the original reviewer's.
  const carried = res?.is_inherited && (res.verify_result === "valid" || res.verify_result === "key_retired");

  return (
    <div className="mt-2">
      <button onClick={check} disabled={state === "checking"} className="text-[11px] font-semibold text-indigo-600 hover:text-indigo-800 underline underline-offset-2 disabled:opacity-50">
        {state === "checking" ? "Checking…" : state === "done" ? "Check again" : "Check signature"}
      </button>
      {state === "error" && <p role="alert" className="mt-1.5 text-[11px] text-rose-600">The check couldn&apos;t run. Please try again.</p>}
      {state === "done" && info && (
        <p role="status" className={`mt-1.5 rounded-lg px-3 py-2 text-[11px] leading-relaxed ${TONE[info.tone]}`}>
          <strong>{carried ? "Carried over from an earlier review; original signature valid" : info.title}.</strong> {carried ? "The file's content is unchanged since that review." : info.body}
        </p>
      )}
    </div>
  );
}
