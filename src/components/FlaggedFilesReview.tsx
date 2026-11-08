"use client";

/**
 * Full-screen review of the PR's flagged files: a rail of every file with findings on the left, the code window
 * filling the rest of the screen, and keyboard movement -- n / p between findings (CodeViewer), [ / ] between
 * files, Esc to leave. Stepping past a file's last finding carries on into the next file, and stepping back from
 * the first one lands on the previous file's last finding, so one pass reads every finding in the PR.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import CodeViewer from "@/components/CodeViewer";
import RiskBadge from "@/components/RiskBadge";
import Tip from "@/components/Tip";
import { ACTION_TIP, RISK_TIP } from "@/lib/prTooltips";
import type { FileNavigation, FindingMeta } from "@/components/InlineFinding";
import type { FileIndicator, FileResult } from "@/types";

interface Props {
  /** The files to move through, in order: those with security findings. */
  files: FileResult[];
  initialFile: string;
  describe: (id: string) => FindingMeta | undefined;
  isSecurity: (i: FileIndicator) => boolean;
  nav?: FileNavigation;
  onClose: () => void;
  canAttest?: (f: FileResult) => boolean;
  /** Leaves this view and opens the attestation review for the file. */
  onRequestAttest?: (f: FileResult) => void;
}

const SEV_DOT: Record<string, string> = { critical: "bg-violet-400", high: "bg-orange-400", medium: "bg-amber-300", low: "bg-sky-300" };
const isTyping = (t: EventTarget | null) => {
  const el = t as HTMLElement | null;
  return !!el && (el.isContentEditable || /^(?:INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
};

export default function FlaggedFilesReview({ files, initialFile, describe, isSecurity, nav, onClose, canAttest, onRequestAttest }: Props) {
  const [mounted, setMounted] = useState(false);
  const startIdx = Math.max(0, files.findIndex(f => f.file_path === initialFile));
  const [idx, setIdx] = useState(startIdx);
  const [entry, setEntry] = useState<"first" | "last">("first");
  const closeRef = useRef<HTMLButtonElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);
  const file = files[idx];

  useEffect(() => { setMounted(true); }, []);

  // A modal: the page behind stays put, and focus returns to where it was.
  useEffect(() => {
    restoreRef.current = document.activeElement as HTMLElement | null;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; restoreRef.current?.focus?.(); };
  }, []);

  const goFile = useCallback((to: number, arrive: "first" | "last" = "first") => {
    if (to < 0 || to >= files.length) return;
    setIdx(to);
    setEntry(arrive);
  }, [files.length]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); return; }
      if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return;
      if (e.key === "]") { e.preventDefault(); goFile(idx + 1); }
      else if (e.key === "[") { e.preventDefault(); goFile(idx - 1); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [idx, goFile, onClose]);

  const rail = useMemo(() => files.map(f => {
    const sec = (f.indicators ?? []).filter(isSecurity);
    const bySev = (s: string) => sec.filter(i => i.severity === s).length;
    return { path: f.file_path, total: sec.length, critical: bySev("critical"), high: bySev("high"), risk: f.risk_score, attested: !!f.attested };
  }), [files, isSecurity]);

  if (!mounted || !file) return null;
  const needsAttest = !file.attested && (file.risk_score === "HIGH" || file.risk_score === "CRITICAL") && !!canAttest?.(file) && !!onRequestAttest;
  const short = file.file_path.split("/").pop();
  const dir = file.file_path.includes("/") ? file.file_path.split("/").slice(0, -1).join("/") + "/" : "";

  return createPortal(
    <div role="dialog" aria-modal="true" aria-label="Review flagged files" className="fixed inset-0 z-[60] flex flex-col bg-slate-950 text-slate-100">
      {/* Header */}
      <div className="shrink-0 flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-white/10 bg-slate-900 px-4 py-2.5">
        <Tip tip={ACTION_TIP.closeReview} side="bottom">
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close review"
            className="grid h-8 w-8 place-items-center rounded-lg text-slate-300 hover:bg-white/10 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
          </button>
        </Tip>
        <div className="min-w-0">
          <p className="text-[13px] font-bold text-white">Review flagged files</p>
          <p className="text-[11px] text-slate-400" data-testid="file-position">File {idx + 1} of {files.length}</p>
        </div>
        <div className="flex items-center gap-1.5">
          <Tip tip={ACTION_TIP.prevReviewFile} side="bottom">
            <button type="button" onClick={() => goFile(idx - 1)} disabled={idx === 0} aria-label="Previous file"
              className="rounded-md bg-white/10 px-2.5 py-1 text-[11px] font-semibold hover:bg-white/15 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">‹ Previous file</button>
          </Tip>
          <Tip tip={ACTION_TIP.nextReviewFile} side="bottom">
            <button type="button" onClick={() => goFile(idx + 1)} disabled={idx === files.length - 1} aria-label="Next file"
              className="rounded-md bg-white/10 px-2.5 py-1 text-[11px] font-semibold hover:bg-white/15 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">Next file ›</button>
          </Tip>
        </div>
        <select aria-label="Jump to file" value={idx} onChange={e => goFile(Number(e.target.value))}
          className="md:hidden min-w-0 max-w-[14rem] rounded-md bg-slate-800 px-2 py-1 text-[11px] text-slate-100 ring-1 ring-white/10">
          {files.map((f, i) => <option key={f.file_path} value={i}>{f.file_path}</option>)}
        </select>
        <span className="hidden lg:inline text-[10px] text-slate-500">
          <kbd className="rounded bg-slate-800 px-1 text-slate-300">n</kbd> / <kbd className="rounded bg-slate-800 px-1 text-slate-300">p</kbd> finding ·{" "}
          <kbd className="rounded bg-slate-800 px-1 text-slate-300">]</kbd> / <kbd className="rounded bg-slate-800 px-1 text-slate-300">[</kbd> file ·{" "}
          <kbd className="rounded bg-slate-800 px-1 text-slate-300">Esc</kbd> close
        </span>
        <span className="flex-1" />
        {needsAttest && (
          <Tip tip={ACTION_TIP.attest} side="bottom">
            <button type="button" onClick={() => onRequestAttest!(file)}
              className="rounded-lg bg-indigo-600 px-3 py-1.5 text-[11px] font-bold text-white hover:bg-indigo-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">
              Review &amp; Attest
            </button>
          </Tip>
        )}
      </div>

      <div className="flex min-h-0 flex-1">
        {/* File rail */}
        <nav aria-label="Flagged files" className="hidden md:block w-72 shrink-0 overflow-y-auto border-r border-white/10 bg-slate-900/60">
          <ul>
            {rail.map((r, i) => (
              <li key={r.path}>
                <button type="button" onClick={() => goFile(i)} aria-current={i === idx ? "true" : undefined} title={r.path}
                  className={`block w-full border-b border-white/5 px-3 py-2 text-left focus:outline-none focus-visible:bg-white/10 ${i === idx ? "bg-sky-500/15" : "hover:bg-white/5"}`}>
                  <span className="block truncate font-mono text-[10px] text-slate-500">{r.path.includes("/") ? r.path.split("/").slice(0, -1).join("/") + "/" : " "}</span>
                  <span className="flex items-center gap-2">
                    <span className={`truncate font-mono text-[12px] font-semibold ${i === idx ? "text-white" : "text-slate-200"}`}>{r.path.split("/").pop()}</span>
                    <span className="ml-auto flex shrink-0 items-center gap-1.5 text-[10px] tabular-nums">
                      {r.critical > 0 && <span className="inline-flex items-center gap-1 text-violet-200"><span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT.critical}`} />{r.critical}</span>}
                      {r.high > 0 && <span className="inline-flex items-center gap-1 text-orange-200"><span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT.high}`} />{r.high}</span>}
                      <span className="text-slate-400">{r.total} total</span>
                      {r.attested && <span className="text-emerald-300" title="Signed off">✓</span>}
                    </span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </nav>

        {/* Code window */}
        <main className="min-w-0 flex-1 overflow-y-auto p-4">
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <div className="min-w-0">
              {dir && <p className="truncate font-mono text-[11px] text-slate-500">{dir}</p>}
              <h2 className="break-all font-mono text-sm font-bold text-white">{short}</h2>
            </div>
            <Tip tip={RISK_TIP[file.risk_score] ?? RISK_TIP.UNKNOWN} title={file.risk_score} side="bottom">
              <span tabIndex={0} className="cursor-help rounded-full focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"><RiskBadge level={file.risk_score} /></span>
            </Tip>
            {file.attested && <span className="text-[11px] font-semibold text-emerald-300">Signed off</span>}
          </div>
          {file.content ? (
            <CodeViewer
              key={file.file_path}
              code={file.content}
              language={file.language}
              filename={file.file_path}
              indicators={file.indicators}
              riskIndicators={file.risk_indicators}
              fixes={file.fix_suggestions}
              describe={describe}
              nav={nav}
              maxHeight="calc(100vh - 13.5rem)"
              onEdge={dir => goFile(idx + dir, dir === 1 ? "first" : "last")}
              initialFinding={entry}
              autoFocus
            />
          ) : (
            <p className="rounded-xl border border-dashed border-white/15 px-4 py-6 text-sm text-slate-400">Source wasn&apos;t captured for this file in the scan, so there is no code to show.</p>
          )}
        </main>
      </div>
    </div>,
    document.body,
  );
}
