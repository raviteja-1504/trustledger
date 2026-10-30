"use client";

/**
 * The live demo: pick a sample, scan it with the real engine (/api/demo/scan), follow the trace, apply the fix (or
 * edit the code yourself), rescan, and see how a reviewer's sign-off is tied to the exact file contents. Everything
 * shown about findings, risk and the merge gate comes from the scan response; the sign-off is simulated in this
 * browser and labelled as such.
 */
import { useCallback, useMemo, useState } from "react";
import Link from "next/link";
import { DEMO_SAMPLES, DEMO_LIMITS, type DemoSample } from "@/lib/demoSamples";
import type { DemoFinding, DemoScanResponse } from "@/lib/demoScan";
import { AMBER, BORDER, CYAN, EMERALD, ROSE, SKY, VIOLET } from "@/components/marketing/Site";

type Variant = "vulnerable" | "fixed" | "custom";
const SEV_COLOR: Record<string, string> = { critical: ROSE, high: AMBER, medium: SKY };
const KIND_COLOR: Record<string, string> = { source: CYAN, assignment: "#94a3b8", call: VIOLET, sanitizer: EMERALD, "cross-file": AMBER, parameter: AMBER, sink: ROSE };

function CodePanel({ content, highlight, editable, onChange, label }: { content: string; highlight: Set<number>; editable: boolean; onChange?: (v: string) => void; label: string }) {
  if (editable) {
    return (
      <textarea aria-label={`Edit ${label}`} value={content} onChange={e => onChange?.(e.target.value)} spellCheck={false}
        className="w-full min-h-[22rem] p-4 font-mono text-[12.5px] leading-[1.6] bg-transparent text-white/90 outline-none resize-y"
        maxLength={DEMO_LIMITS.maxFileBytes} />
    );
  }
  const lines = content.split("\n");
  return (
    <pre className="overflow-x-auto p-4 font-mono text-[12.5px] leading-[1.6]" aria-label={label}>
      {lines.map((l, i) => {
        const hot = highlight.has(i + 1);
        return (
          <div key={i} className="flex" style={hot ? { background: `${ROSE}1f`, boxShadow: `inset 3px 0 0 ${ROSE}` } : undefined}>
            <span className="select-none w-9 shrink-0 pr-3 text-right text-white/25">{i + 1}</span>
            <code className="whitespace-pre text-white/85">{l || " "}</code>
          </div>
        );
      })}
    </pre>
  );
}

function TraceView({ f }: { f: DemoFinding }) {
  if (!f.trace.length) return <p className="text-xs text-white/50">No step-by-step trace for this finding: it was matched at line {f.line ?? "?"} without a data-flow path.</p>;
  return (
    <ol className="space-y-3">
      {f.trace.map((s, i) => (
        <li key={i} className="flex gap-3">
          <span className="mt-1 w-2.5 h-2.5 rounded-full shrink-0" style={{ background: KIND_COLOR[s.kind] ?? "#94a3b8", boxShadow: `0 0 8px ${KIND_COLOR[s.kind] ?? "#94a3b8"}` }} />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
              <span className="font-bold uppercase tracking-wider" style={{ color: KIND_COLOR[s.kind] ?? "#94a3b8" }}>{s.kind}</span>
              <span className="text-white/45">{s.file}:{s.line}</span>
            </div>
            <p className="text-[13px] text-white/85">{s.label}</p>
            {s.snippet && <code className="block mt-0.5 text-[12px] font-mono text-white/55 break-all">{s.snippet}</code>}
          </div>
        </li>
      ))}
    </ol>
  );
}

export default function DemoClient() {
  const [sampleId, setSampleId] = useState(DEMO_SAMPLES[0].id);
  const sample = DEMO_SAMPLES.find(s => s.id === sampleId) as DemoSample;
  const [variant, setVariant] = useState<Variant>("vulnerable");
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [editing, setEditing] = useState(false);
  const [activeFile, setActiveFile] = useState(sample.files[0].path);
  const [result, setResult] = useState<DemoScanResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState(0);
  const [showDiff, setShowDiff] = useState(false);
  // simulated sign-off: file path -> the content hash the reviewer approved
  const [signedOff, setSignedOff] = useState<Record<string, string>>({});

  const contentOf = useCallback((path: string, v: Variant = variant) => {
    const f = sample.files.find(x => x.path === path);
    if (!f) return "";
    if (v === "custom") return edits[path] ?? f.vulnerable;
    return v === "fixed" ? f.fixed : f.vulnerable;
  }, [sample, variant, edits]);

  const pick = (id: string) => {
    const s = DEMO_SAMPLES.find(x => x.id === id) as DemoSample;
    setSampleId(id); setVariant("vulnerable"); setEdits({}); setEditing(false); setActiveFile(s.files[0].path);
    setResult(null); setError(null); setSelected(0); setShowDiff(false); setSignedOff({});
  };

  const scan = async (v: Variant) => {
    setBusy(true); setError(null);
    try {
      const body = v === "custom"
        ? { sampleId, variant: v, files: sample.files.map(f => ({ path: f.path, content: edits[f.path] ?? f.vulnerable })) }
        : { sampleId, variant: v };
      const res = await fetch("/api/demo/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error === "too_many_requests" ? "Too many scans in a minute — wait a moment and try again." : `Scan failed (${json.error ?? res.status}).`);
      setResult(json as DemoScanResponse); setVariant(v); setSelected(0); setEditing(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed.");
    } finally {
      setBusy(false);
    }
  };

  const findings = useMemo(() => result?.files.flatMap(f => f.findings.map(x => ({ ...x, file: f.path }))) ?? [], [result]);
  const current = findings[selected];
  const highlight = useMemo(() => new Set(findings.filter(f => f.file === activeFile && f.line).map(f => f.line as number)), [findings, activeFile]);
  const fileResult = result?.files.find(f => f.path === activeFile);

  return (
    <div className="space-y-6">
      {/* 1. sample */}
      <div>
        <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-white/45 font-mono mb-2">Step 1 · choose a sample</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {DEMO_SAMPLES.map(s => (
            <button key={s.id} onClick={() => pick(s.id)} aria-pressed={s.id === sampleId}
              className="text-left rounded-xl border p-3.5 transition-colors"
              style={{ borderColor: s.id === sampleId ? `${CYAN}80` : BORDER, background: s.id === sampleId ? `${CYAN}10` : "rgba(255,255,255,0.03)" }}>
              <p className="text-[11px] font-mono" style={{ color: CYAN }}>{s.cwe} · {s.language}</p>
              <p className="text-sm font-bold text-white mt-1">{s.title}</p>
            </button>
          ))}
        </div>
        <p className="text-sm text-white/60 mt-3 max-w-3xl">{sample.summary}</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1.15fr_1fr] gap-6 items-start">
        {/* code */}
        <div className="rounded-2xl border overflow-hidden" style={{ borderColor: BORDER, background: "rgba(255,255,255,0.025)" }}>
          <div className="flex flex-wrap items-center gap-2 px-3 py-2 border-b" style={{ borderColor: BORDER }}>
            {sample.files.map(f => (
              <button key={f.path} onClick={() => setActiveFile(f.path)} className="text-[12px] font-mono px-2.5 py-1 rounded-md"
                style={{ color: f.path === activeFile ? "#fff" : "rgba(255,255,255,0.55)", background: f.path === activeFile ? "rgba(255,255,255,0.08)" : "transparent" }}>{f.path}</button>
            ))}
            <span className="ml-auto text-[11px] font-mono text-white/40">{variant === "fixed" ? "fixed version" : variant === "custom" ? "your edit" : "vulnerable version"}</span>
          </div>
          {showDiff ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x" style={{ borderColor: BORDER }}>
              <div><p className="px-4 pt-3 text-[11px] font-bold font-mono" style={{ color: ROSE }}>VULNERABLE</p><CodePanel label={`${activeFile} (vulnerable)`} content={contentOf(activeFile, "vulnerable")} highlight={new Set()} editable={false} /></div>
              <div><p className="px-4 pt-3 text-[11px] font-bold font-mono" style={{ color: EMERALD }}>FIXED</p><CodePanel label={`${activeFile} (fixed)`} content={contentOf(activeFile, "fixed")} highlight={new Set()} editable={false} /></div>
            </div>
          ) : (
            <CodePanel label={activeFile} content={editing ? (edits[activeFile] ?? contentOf(activeFile)) : contentOf(activeFile)} highlight={highlight} editable={editing}
              onChange={v => setEdits(e => ({ ...e, [activeFile]: v }))} />
          )}
          <div className="flex flex-wrap gap-2 p-3 border-t" style={{ borderColor: BORDER }}>
            <button disabled={busy} onClick={() => scan("vulnerable")} className="text-sm font-bold px-4 py-2 rounded-lg text-[#050810] disabled:opacity-50" style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})` }}>
              {busy ? "Scanning…" : "Step 2 · Scan the vulnerable code"}
            </button>
            <button disabled={busy} onClick={() => scan("fixed")} className="text-sm font-semibold px-4 py-2 rounded-lg border text-white/85 disabled:opacity-50" style={{ borderColor: `${EMERALD}66`, background: `${EMERALD}14` }}>Step 3 · Apply the fix and rescan</button>
            <button onClick={() => setShowDiff(d => !d)} className="text-sm font-semibold px-3 py-2 rounded-lg border text-white/70" style={{ borderColor: BORDER }}>{showDiff ? "Hide" : "Show"} side-by-side fix</button>
            {!editing
              ? <button onClick={() => { setEditing(true); setShowDiff(false); setEdits(e => Object.fromEntries(sample.files.map(f => [f.path, e[f.path] ?? contentOf(f.path)]))); }} className="text-sm font-semibold px-3 py-2 rounded-lg border text-white/70" style={{ borderColor: BORDER }}>Edit the code</button>
              : <button disabled={busy} onClick={() => scan("custom")} className="text-sm font-bold px-3 py-2 rounded-lg border text-white disabled:opacity-50" style={{ borderColor: `${VIOLET}80`, background: `${VIOLET}1f` }}>Scan my edit</button>}
          </div>
          <p className="px-3 pb-3 text-[11.5px] text-white/45">{sample.fixNote}</p>
        </div>

        {/* result */}
        <div className="space-y-4" aria-live="polite">
          {error && <div className="rounded-xl border p-3 text-sm" style={{ borderColor: `${ROSE}66`, color: ROSE, background: `${ROSE}12` }}>{error}</div>}
          {!result && !error && (
            <div className="rounded-2xl border p-6 text-sm text-white/55" style={{ borderColor: BORDER }}>
              Press <strong className="text-white/80">Scan the vulnerable code</strong>. The request runs the real TrustLedger engine on these files on our server — nothing is stored, and the code is parsed as text, never executed.
            </div>
          )}
          {result && (
            <>
              {/* PR check */}
              <div className="rounded-2xl border overflow-hidden" style={{ borderColor: result.mergeBlocked ? `${ROSE}55` : `${EMERALD}55` }}>
                <div className="px-4 py-3 flex items-center gap-3" style={{ background: result.mergeBlocked ? `${ROSE}12` : `${EMERALD}12` }}>
                  <span className="text-lg" aria-hidden>{result.mergeBlocked ? "⛔" : "✅"}</span>
                  <div className="min-w-0">
                    <p className="text-sm font-bold text-white">TrustLedger check · {result.mergeBlocked ? "merge blocked" : "passed"}</p>
                    <p className="text-[11.5px] text-white/55">
                      {findings.length} finding{findings.length === 1 ? "" : "s"} · overall risk {result.overallRisk} · scanned in {result.durationMs} ms
                    </p>
                  </div>
                </div>
                <p className="px-4 py-2 text-[11.5px] text-white/50 border-t" style={{ borderColor: BORDER }}>
                  Default policy: a file at CRITICAL or HIGH risk blocks the merge until a named reviewer attests it or it is fixed.
                </p>
              </div>

              {/* findings */}
              {findings.length > 0 && (
                <div className="rounded-2xl border" style={{ borderColor: BORDER }}>
                  <div className="divide-y" style={{ borderColor: BORDER }}>
                    {findings.map((f, i) => (
                      <button key={`${f.file}:${f.id}:${f.line}:${i}`} onClick={() => { setSelected(i); setActiveFile(f.file); }}
                        className="w-full text-left px-4 py-3 flex items-start gap-3" style={{ background: i === selected ? "rgba(255,255,255,0.05)" : "transparent", borderColor: BORDER }}>
                        <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded mt-0.5" style={{ color: SEV_COLOR[f.severity] ?? "#fff", background: `${SEV_COLOR[f.severity] ?? "#fff"}1f` }}>{f.severity}</span>
                        <span className="min-w-0">
                          <span className="block text-sm font-semibold text-white">{f.label}{f.cwe ? <span className="text-white/40 font-mono text-[11px]"> · {f.cwe}</span> : null}</span>
                          <span className="block text-[11.5px] font-mono text-white/45">{f.file}:{f.line ?? "?"}</span>
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {current && (
                <div className="rounded-2xl border p-4 space-y-3" style={{ borderColor: BORDER }}>
                  <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-white/45 font-mono">Source → sink trace</p>
                  <TraceView f={current} />
                  {current.detail && <p className="text-[12px] text-white/55 border-t pt-3" style={{ borderColor: BORDER }}>{current.detail}</p>}
                </div>
              )}
              {findings.length === 0 && (
                <div className="rounded-2xl border p-4 text-sm text-white/70" style={{ borderColor: `${EMERALD}55` }}>
                  No security findings in this version — the fix removed the {sample.expectRule} flow.
                </div>
              )}

              {/* attestation */}
              {fileResult && (
                <div className="rounded-2xl border p-4 space-y-2" style={{ borderColor: BORDER }}>
                  <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-white/45 font-mono">Provenance &amp; sign-off · {activeFile}</p>
                  <p className="text-[12.5px] text-white/70">
                    AI-generated estimate: <strong className="text-white">{Math.round(fileResult.aiPercentage * 100)}%</strong>
                    {/* name a tool only when the file reads as AI-written; at a low estimate the attribution is noise */}
                    {fileResult.aiPercentage >= 0.5 && fileResult.aiModel !== "unknown" && fileResult.aiModel !== "human" ? <> · most likely tool: {fileResult.aiModel}</> : null}
                    <span className="text-white/40"> — a probabilistic estimate from code signals, not proof of authorship.</span>
                  </p>
                  <p className="text-[12px] font-mono text-white/55 break-all">content hash {fileResult.contentHash}</p>
                  {signedOff[activeFile] ? (
                    signedOff[activeFile] === fileResult.contentHash
                      ? <p className="text-[12.5px]" style={{ color: EMERALD }}>Signed off for exactly this content. The same file in a later scan keeps this sign-off.</p>
                      : <p className="text-[12.5px]" style={{ color: AMBER }}>The code changed since the sign-off (hash {signedOff[activeFile].slice(0, 12)}… → {fileResult.contentHash.slice(0, 12)}…): the old sign-off no longer covers it and a reviewer must attest again.</p>
                  ) : (
                    <button onClick={() => setSignedOff(s => ({ ...s, [activeFile]: fileResult.contentHash }))} className="text-sm font-semibold px-3 py-1.5 rounded-lg border text-white/85" style={{ borderColor: `${EMERALD}66`, background: `${EMERALD}12` }}>
                      Simulate a reviewer sign-off
                    </button>
                  )}
                  <p className="text-[11px] text-white/40">Simulated in your browser. In the product, an attestation is recorded server-side with the reviewer&apos;s identity, a timestamp and a payload hash, bound to this content hash — then try <em>Edit the code</em> and rescan.</p>
                </div>
              )}
            </>
          )}
        </div>
      </div>
      <p className="text-[12px] text-white/45">Want the same check on your own pull requests? <Link href="/login?mode=signup" className="underline underline-offset-2 text-white/75 hover:text-white">Connect a repository</Link> — the GitHub App asks only for read access to pull requests and code, and write access to checks and commit statuses.</p>
    </div>
  );
}
