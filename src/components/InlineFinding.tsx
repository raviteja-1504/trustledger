"use client";

import { useMemo, useState } from "react";
import type { FileIndicator, FixSuggestion } from "@/types";
import { buildFindingEvidence, type CheckTone, type FlowStep, type Part } from "@/lib/findingEvidence";
import { cweFor } from "@/lib/cweMap";
import { REACH_DESC, REACH_LABEL, URGENCY_DESC, URGENCY_LABEL } from "@/lib/signalClassification";

export interface FindingMeta { label?: string; desc?: string; security?: boolean }

type Sev = "critical" | "high" | "medium" | "low";
const normSev = (s: string): Sev => (s === "critical" || s === "high" || s === "medium" ? s : "low");

// Same hue per severity as the PR page's own severity badges (critical = violet), in dark-surface tints.
const SEV_STYLE: Record<Sev, { bar: string; pill: string }> = {
  critical: { bar: "bg-violet-500", pill: "bg-violet-500/20 text-violet-200 ring-violet-400/50" },
  high:     { bar: "bg-orange-500", pill: "bg-orange-500/15 text-orange-300 ring-orange-500/40" },
  medium:   { bar: "bg-amber-400",  pill: "bg-amber-400/15 text-amber-200 ring-amber-400/40" },
  low:      { bar: "bg-sky-400",    pill: "bg-sky-400/15 text-sky-200 ring-sky-400/40" },
};
const REACH_STYLE: Record<string, string> = {
  "entry-point":  "bg-rose-500/10 text-rose-300 ring-rose-500/30",
  "tainted-path": "bg-orange-500/10 text-orange-300 ring-orange-500/30",
  "reachable":    "bg-amber-400/10 text-amber-200 ring-amber-400/30",
  "unreachable":  "bg-slate-500/15 text-slate-400 ring-slate-500/30",
};
const URGENCY_STYLE: Record<string, string> = {
  immediate: "bg-rose-500/10 text-rose-300 ring-rose-500/30",
  sprint:    "bg-orange-500/10 text-orange-300 ring-orange-500/30",
  backlog:   "bg-amber-400/10 text-amber-200 ring-amber-400/30",
  monitor:   "bg-slate-500/15 text-slate-400 ring-slate-500/30",
};
const STEP_DOT: Record<FlowStep["kind"], string> = {
  source: "bg-sky-400 ring-sky-400/30", assignment: "bg-slate-400 ring-slate-400/20", call: "bg-slate-400 ring-slate-400/20",
  sanitizer: "bg-amber-400 ring-amber-400/30", "cross-file": "bg-violet-400 ring-violet-400/30", sink: "bg-rose-500 ring-rose-500/30",
};
const CHIP = "inline-flex items-center gap-1 rounded px-1.5 py-px text-[10px] font-semibold ring-1 whitespace-nowrap";
const JS_LANGS = new Set(["javascript", "typescript", "js", "ts", "jsx", "tsx"]);
const FLOW_PREVIEW = 5;

function Code({ children }: { children: string }) {
  return (
    <code className="rounded bg-slate-950/70 px-1 py-px font-mono text-[11px] text-amber-100 ring-1 ring-slate-700/70 break-words [box-decoration-break:clone]">
      {children}
    </code>
  );
}

function Parts({ parts }: { parts: Part[] }) {
  return <>{parts.map((p, i) => (typeof p === "string" ? <span key={i}>{p}</span> : <Code key={i}>{p.code}</Code>))}</>;
}

function CheckIcon({ tone }: { tone: CheckTone }) {
  const common = { width: 12, height: 12, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 3, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  if (tone === "confirmed") return <svg {...common} className="text-emerald-400 shrink-0 mt-[3px]" aria-label="Confirmed"><polyline points="20 6 9 17 4 12" /></svg>;
  if (tone === "absent") return <svg {...common} className="text-rose-400 shrink-0 mt-[3px]" aria-label="Missing"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>;
  if (tone === "caution") return <svg {...common} className="text-amber-400 shrink-0 mt-[3px]" aria-label="Caution"><line x1="12" y1="5" x2="12" y2="14" /><line x1="12" y1="19" x2="12.01" y2="19" /></svg>;
  return <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-slate-500" aria-hidden />;
}

function SectionLabel({ children }: { children: string }) {
  return <p className="mb-1.5 text-[10px] font-bold uppercase tracking-[0.08em] text-slate-500">{children}</p>;
}

function Toggle({ open, onClick, children }: { open: boolean; onClick: () => void; children: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-expanded={open}
      className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] font-semibold text-slate-300 ring-1 ring-slate-600/70 hover:bg-slate-700/60 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 transition-colors"
    >
      {children}
      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" className={`transition-transform ${open ? "rotate-180" : ""}`} aria-hidden>
        <polyline points="6 9 12 15 18 9" />
      </svg>
    </button>
  );
}

function LineLink({ line, onJump }: { line: number; onJump?: (line: number) => void }) {
  if (!onJump) return <span className="font-mono text-[10px] text-slate-500 tabular-nums">L{line}</span>;
  return (
    <button
      type="button"
      onClick={() => onJump(line)}
      title={`Jump to line ${line}`}
      className="font-mono text-[10px] text-sky-400 tabular-nums hover:text-sky-300 hover:underline focus:outline-none focus-visible:ring-1 focus-visible:ring-sky-400 rounded"
    >
      L{line}
    </button>
  );
}

function FlowPath({ flow, fromEndpointsOnly, onJump }: { flow: FlowStep[]; fromEndpointsOnly: boolean; onJump?: (line: number) => void }) {
  const [all, setAll] = useState(false);
  // Always keep the origin and the sink; elide the middle of a long path until asked.
  const hidden = !all && flow.length > FLOW_PREVIEW ? flow.length - FLOW_PREVIEW : 0;
  const shown = hidden ? [...flow.slice(0, FLOW_PREVIEW - 1), flow[flow.length - 1]] : flow;
  return (
    <div>
      <ol className="relative space-y-2">
        {shown.map((s, i) => {
          const isLast = i === shown.length - 1;
          return (
            <li key={`${s.kind}-${s.line}-${i}`} className="relative flex gap-2.5 pl-0.5">
              {!isLast && <span className="absolute left-[5px] top-3.5 bottom-[-10px] w-px bg-slate-600/70" aria-hidden />}
              <span className={`relative mt-1 h-2 w-2 shrink-0 rounded-full ring-4 ${STEP_DOT[s.kind]}`} aria-hidden />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-bold uppercase tracking-wider ${s.kind === "source" ? "text-sky-300" : s.kind === "sink" ? "text-rose-300" : "text-slate-400"}`}>
                    {s.kindLabel}
                  </span>
                  {s.otherFile
                    ? <span className="font-mono text-[10px] text-violet-300">{s.otherFile}{s.line ? `:${s.line}` : ""}</span>
                    : s.line ? <LineLink line={s.line} onJump={onJump} /> : null}
                </div>
                <p className="mt-0.5 font-mono text-[11px] leading-relaxed text-slate-200 break-words">{s.text}</p>
              </div>
            </li>
          );
        })}
      </ol>
      {hidden > 0 && (
        <button type="button" onClick={() => setAll(true)} className="mt-2 text-[11px] font-semibold text-sky-400 hover:text-sky-300 focus:outline-none focus-visible:underline">
          Show all {flow.length} steps
        </button>
      )}
      {fromEndpointsOnly && (
        <p className="mt-2 text-[11px] text-slate-500">Only the start and end of this flow were recorded; intermediate steps aren’t available for this finding.</p>
      )}
    </div>
  );
}

function FixBlock({ fix, language }: { fix: FixSuggestion; language?: string }) {
  const showExample = !!(fix.code_before || fix.code_after) && JS_LANGS.has((language ?? "").toLowerCase());
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <p className="text-[12px] font-semibold text-slate-100">{fix.title}</p>
        <span className={`${CHIP} bg-slate-700/50 text-slate-300 ring-slate-600`}>{fix.effort} effort</span>
      </div>
      <p className="text-[12px] leading-relaxed text-slate-300">{fix.description}</p>
      {showExample && (
        <div className="grid gap-2 sm:grid-cols-2">
          {fix.code_before && (
            <div>
              <p className="mb-1 text-[10px] font-bold uppercase tracking-wider text-rose-300/80">Before</p>
              <pre className="overflow-x-auto rounded-md bg-slate-950/80 p-2 font-mono text-[11px] leading-relaxed text-slate-300 ring-1 ring-rose-500/20">{fix.code_before}</pre>
            </div>
          )}
          {fix.code_after && (
            <div>
              <p className="mb-1 text-[10px] font-bold uppercase tracking-wider text-emerald-300/80">After</p>
              <pre className="overflow-x-auto rounded-md bg-slate-950/80 p-2 font-mono text-[11px] leading-relaxed text-slate-300 ring-1 ring-emerald-500/20">{fix.code_after}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** The inline explanation rendered directly under a flagged line. */
export function InlineSecurityFinding({ ind, filePath, language, meta, fix, siblings, defaultOpen, onJump }: {
  ind: FileIndicator;
  filePath: string;
  language?: string;
  meta?: FindingMeta;
  fix?: FixSuggestion;
  siblings: readonly FileIndicator[];
  defaultOpen?: boolean;
  onJump?: (line: number) => void;
}) {
  const [open, setOpen] = useState(!!defaultOpen);
  const [fixOpen, setFixOpen] = useState(false);
  const ev = useMemo(() => buildFindingEvidence(ind, filePath, siblings), [ind, filePath, siblings]);
  const sev = normSev(ind.severity);
  const style = SEV_STYLE[sev];
  const title = meta?.label ?? ind.label;
  const cweId = ind.cwe ?? cweFor(ind.id)?.id;
  const cweTitle = cweFor(ind.id)?.title;
  const cweNum = cweId?.match(/\d+/)?.[0];
  const muted = ind.codeCategory === "third_party" || ind.codeCategory === "test_code";
  const source = ev.flow.find(s => s.kind === "source");
  const sink = ev.flow[ev.flow.length - 1];

  return (
    <div className={`relative overflow-hidden rounded-lg bg-slate-800/80 ring-1 ring-slate-700/80 font-sans ${muted ? "opacity-80" : ""}`}>
      <span className={`absolute inset-y-0 left-0 w-1 ${muted ? "bg-slate-500" : style.bar}`} aria-hidden />
      <div className="space-y-2.5 py-3 pl-4 pr-3">
        {/* Title + metadata */}
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5">
          <span className={`${CHIP} uppercase tracking-wide ${style.pill}`}>{sev}</span>
          <h4 className="text-[13px] font-semibold text-slate-50">{title}</h4>
          {ind.functionName && (
            <span className="text-[11px] text-slate-400">in <Code>{`${ind.functionName}()`}</Code></span>
          )}
          <span className="ml-auto flex flex-wrap items-center gap-1.5">
            <span className={`${CHIP} ${ev.isDataFlow ? "bg-sky-500/10 text-sky-300 ring-sky-500/30" : "bg-slate-600/30 text-slate-300 ring-slate-500/40"}`}
              title={ev.isDataFlow ? "Found by tracing the value through the parsed code" : "Found by matching a code pattern on this line"}>
              {ev.analysisLabel}{ind.confidence != null ? ` · ${ind.confidence}%` : ""}
            </span>
            {cweId && (
              cweNum
                ? <a href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`} target="_blank" rel="noopener noreferrer"
                    title={cweTitle} className={`${CHIP} bg-slate-700/40 text-slate-300 ring-slate-600 hover:text-white hover:ring-slate-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400`}>{cweId}</a>
                : <span className={`${CHIP} bg-slate-700/40 text-slate-300 ring-slate-600`} title={cweTitle}>{cweId}</span>
            )}
            {ind.reachability && REACH_STYLE[ind.reachability] && (
              <span className={`${CHIP} ${REACH_STYLE[ind.reachability]}`} title={REACH_DESC[ind.reachability]}>{REACH_LABEL[ind.reachability]}</span>
            )}
            {ind.remediation_urgency && !muted && (
              <span className={`${CHIP} ${URGENCY_STYLE[ind.remediation_urgency]}`} title={URGENCY_DESC[ind.remediation_urgency]}>{URGENCY_LABEL[ind.remediation_urgency]}</span>
            )}
            {muted && (
              <span className={`${CHIP} bg-slate-600/30 text-slate-300 ring-slate-500/40`} title="Kept as evidence but excluded from this file's risk score">
                {ind.codeCategory === "third_party" ? "Third-party code" : "Test code"}
              </span>
            )}
          </span>
        </div>

        {/* Explanation */}
        <p className="text-[12.5px] leading-relaxed text-slate-200"><Parts parts={ev.summary} /></p>

        {/* Compact source -> sink, always visible for data-flow findings */}
        {ev.isDataFlow && source && sink && sink !== source && (
          <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-400">
            <span className="font-semibold uppercase tracking-wider text-[10px] text-sky-300">Input</span>
            <Code>{source.text}</Code>
            <span aria-hidden className="text-slate-500">→</span>
            {ev.flow.length > 2 && <><span className="text-slate-500">{ev.flow.length - 2} step{ev.flow.length - 2 === 1 ? "" : "s"}</span><span aria-hidden className="text-slate-500">→</span></>}
            <span className="font-semibold uppercase tracking-wider text-[10px] text-rose-300">Sink</span>
            <Code>{sink.text}</Code>
          </div>
        )}
        {ev.onPathOf && (
          <p className="text-[11px] text-slate-400">
            Part of the confirmed data flow flagged at <LineLink line={ev.onPathOf.line} onJump={onJump} />.
          </p>
        )}

        <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
          <Toggle open={open} onClick={() => setOpen(v => !v)}>{open ? "Hide evidence" : "Show evidence"}</Toggle>
          {fix && <Toggle open={fixOpen} onClick={() => setFixOpen(v => !v)}>Recommended fix</Toggle>}
        </div>

        {open && (
          <div className="grid gap-4 border-t border-slate-700/70 pt-3 grid-cols-[repeat(auto-fit,minmax(min(100%,300px),1fr))]">
            {ev.flow.length > 0 && (
              <div className="min-w-0">
                <SectionLabel>Data flow</SectionLabel>
                <FlowPath flow={ev.flow} fromEndpointsOnly={ev.flowFromEndpointsOnly} onJump={onJump} />
              </div>
            )}
            <div className={`min-w-0 ${ev.flow.length === 0 ? "col-span-full" : ""}`}>
              <SectionLabel>Why this was flagged</SectionLabel>
              <ul className="space-y-1.5">
                {ev.checks.map((c, i) => (
                  <li key={i} className="flex gap-2 text-[12px] leading-relaxed text-slate-300">
                    <CheckIcon tone={c.tone} />
                    <span className="min-w-0"><Parts parts={c.parts} /></span>
                  </li>
                ))}
              </ul>
              {(ind.exploitability_score != null || meta?.desc) && (
                <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
                  {ind.exploitability_score != null && (
                    <>
                      <dt className="text-slate-500">Exploitability</dt>
                      <dd className="text-slate-300 tabular-nums">{ind.exploitability_score.toFixed(1)} / 10</dd>
                    </>
                  )}
                  {cweTitle && cweTitle.toLowerCase() !== title.toLowerCase() && (
                    <>
                      <dt className="text-slate-500">Weakness</dt>
                      <dd className="text-slate-300">{cweTitle}</dd>
                    </>
                  )}
                  {meta?.desc && (
                    <>
                      <dt className="text-slate-500">About</dt>
                      <dd className="text-slate-400">{meta.desc}</dd>
                    </>
                  )}
                </dl>
              )}
            </div>
          </div>
        )}

        {fix && fixOpen && (
          <div className="border-t border-slate-700/70 pt-3">
            <SectionLabel>Recommended fix</SectionLabel>
            <FixBlock fix={fix} language={language} />
          </div>
        )}
      </div>
    </div>
  );
}

/** A one-line note for a non-security (AI-authorship) signal on this line. */
export function InlineSignalNote({ ind, meta }: { ind: FileIndicator; meta?: FindingMeta }) {
  return (
    <div className="flex items-start gap-2 rounded-md bg-slate-800/50 px-3 py-1.5 font-sans ring-1 ring-slate-700/60">
      <span className={`${CHIP} bg-indigo-500/10 text-indigo-300 ring-indigo-500/30`}>AI signal</span>
      <p className="text-[11.5px] leading-relaxed text-slate-300">
        <span className="font-semibold text-slate-200">{meta?.label ?? ind.label}</span>
        {(meta?.desc ?? ind.detail) && <span className="text-slate-400"> — {meta?.desc ?? ind.detail}</span>}
      </p>
    </div>
  );
}
