"use client";

import { useMemo, useState } from "react";
import type { FileIndicator, FixSuggestion } from "@/types";
import { buildFindingEvidence, type CheckTone, type FlowStep, type Part } from "@/lib/findingEvidence";
import type { CrossFileMark } from "@/lib/dataFlowEvidence";
import { cweFor } from "@/lib/cweMap";
import { findingMeta } from "@/lib/findingCatalog";
import { REACH_DESC, REACH_LABEL, URGENCY_DESC, URGENCY_LABEL } from "@/lib/signalClassification";

export interface FindingMeta { label?: string; desc?: string; security?: boolean }

/** Jump to a line in ANOTHER file of this PR (cross-file steps). `canOpenFile` says whether that file is here. */
export interface FileNavigation {
  openFile: (file: string, line: number) => void;
  canOpenFile: (file: string) => boolean;
}

type Sev = "critical" | "high" | "medium" | "low";
const normSev = (s: string): Sev => (s === "critical" || s === "high" || s === "medium" ? s : "low");

// Same hue per severity as the PR page's own severity badges (critical = violet), in dark-surface tints.
const SEV_STYLE: Record<Sev, { bar: string; pill: string; glow: string; icon: string }> = {
  critical: { bar: "from-violet-400 to-fuchsia-500", pill: "bg-violet-500/20 text-violet-100 ring-violet-400/50", glow: "shadow-violet-950/40", icon: "text-violet-300" },
  high:     { bar: "from-orange-400 to-rose-500",    pill: "bg-orange-500/15 text-orange-200 ring-orange-400/45", glow: "shadow-orange-950/30", icon: "text-orange-300" },
  medium:   { bar: "from-amber-300 to-amber-500",    pill: "bg-amber-400/15 text-amber-100 ring-amber-400/40",    glow: "shadow-amber-950/25", icon: "text-amber-300" },
  low:      { bar: "from-sky-300 to-sky-500",        pill: "bg-sky-400/15 text-sky-100 ring-sky-400/40",          glow: "shadow-sky-950/25",   icon: "text-sky-300" },
};
const REACH_STYLE: Record<string, string> = {
  "entry-point":  "bg-rose-500/10 text-rose-200 ring-rose-500/30",
  "tainted-path": "bg-orange-500/10 text-orange-200 ring-orange-500/30",
  "reachable":    "bg-amber-400/10 text-amber-100 ring-amber-400/30",
  "unreachable":  "bg-slate-500/15 text-slate-400 ring-slate-500/30",
};
const URGENCY_STYLE: Record<string, string> = {
  immediate: "bg-rose-500/10 text-rose-200 ring-rose-500/30",
  sprint:    "bg-orange-500/10 text-orange-200 ring-orange-500/30",
  backlog:   "bg-amber-400/10 text-amber-100 ring-amber-400/30",
  monitor:   "bg-slate-500/15 text-slate-400 ring-slate-500/30",
};
const STEP_DOT: Record<FlowStep["kind"], string> = {
  source: "bg-sky-400 ring-sky-400/25", assignment: "bg-slate-400 ring-slate-400/15", call: "bg-slate-300 ring-slate-300/15",
  sanitizer: "bg-amber-400 ring-amber-400/25", "cross-file": "bg-violet-400 ring-violet-400/25", parameter: "bg-violet-300 ring-violet-300/25",
  sink: "bg-rose-500 ring-rose-500/30",
};
const STEP_LABEL_TONE: Partial<Record<FlowStep["kind"], string>> = {
  source: "text-sky-300", sink: "text-rose-300", "cross-file": "text-violet-300", parameter: "text-violet-300", sanitizer: "text-amber-300",
};
const CHIP = "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold ring-1 whitespace-nowrap";
const JS_LANGS = new Set(["javascript", "typescript", "js", "ts", "jsx", "tsx"]);
const FLOW_PREVIEW = 6;

const baseName = (p: string) => p.split("/").pop() ?? p;

function Code({ children }: { children: string }) {
  return (
    <code className="rounded-md bg-black/40 px-1.5 py-px font-mono text-[11px] text-amber-100/95 ring-1 ring-white/10 break-words [box-decoration-break:clone]">
      {children}
    </code>
  );
}

function Parts({ parts }: { parts: Part[] }) {
  return <>{parts.map((p, i) => (typeof p === "string" ? <span key={i}>{p}</span> : <Code key={i}>{p.code}</Code>))}</>;
}

function Icon({ d, className = "", size = 12 }: { d: string; className?: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d={d} />
    </svg>
  );
}
const ICON = {
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM12 8v4M12 16h.01",
  file: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6",
  arrow: "M5 12h14M13 6l6 6-6 6",
  wrench: "M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-2.4z",
  eye: "M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
  link: "M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7",
};

function CheckIcon({ tone }: { tone: CheckTone }) {
  const box = "mt-[1px] grid h-4 w-4 shrink-0 place-items-center rounded-full ring-1";
  if (tone === "confirmed") return <span className={`${box} bg-emerald-500/15 ring-emerald-400/40 text-emerald-300`} aria-label="Confirmed"><Icon d="M20 6 9 17l-5-5" size={9} /></span>;
  if (tone === "absent") return <span className={`${box} bg-rose-500/15 ring-rose-400/40 text-rose-300`} aria-label="Missing"><Icon d="M18 6 6 18M6 6l12 12" size={9} /></span>;
  if (tone === "caution") return <span className={`${box} bg-amber-400/15 ring-amber-400/40 text-amber-300`} aria-label="Caution"><Icon d="M12 6v8M12 18h.01" size={9} /></span>;
  return <span className={`${box} bg-slate-500/10 ring-slate-500/30`} aria-hidden><span className="h-1 w-1 rounded-full bg-slate-400" /></span>;
}

function SectionLabel({ children, icon }: { children: string; icon?: string }) {
  return (
    <p className="mb-2 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.1em] text-slate-400">
      {icon && <Icon d={icon} size={11} className="text-slate-500" />}
      {children}
    </p>
  );
}

function Toggle({ open, onClick, icon, children }: { open: boolean; onClick: () => void; icon: string; children: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-expanded={open}
      className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px] font-semibold ring-1 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
        open ? "bg-white/10 text-white ring-white/20" : "text-slate-300 ring-white/10 hover:bg-white/5 hover:text-white"}`}
    >
      <Icon d={icon} size={11} />
      {children}
      <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" className={`transition-transform ${open ? "rotate-180" : ""}`} aria-hidden>
        <polyline points="6 9 12 15 18 9" />
      </svg>
    </button>
  );
}

/** A line reference: in this file it scrolls the viewer; in another file of the PR it opens that file. */
function LineRef({ line, file, filePath, onJump, nav, emphasis }: {
  line: number; file?: string; filePath: string; onJump?: (line: number) => void; nav?: FileNavigation; emphasis?: boolean;
}) {
  const other = !!file && file !== filePath;
  const label = other ? `${baseName(file!)}:${line}` : `L${line}`;
  const cls = `font-mono text-[10px] tabular-nums rounded px-1 ${emphasis ? "font-semibold" : ""}`;
  if (other) {
    if (nav?.canOpenFile(file!)) {
      return (
        <button type="button" onClick={() => nav.openFile(file!, line)} title={`Open ${file} at line ${line}`}
          className={`${cls} text-violet-300 hover:bg-violet-500/15 hover:text-violet-200 focus:outline-none focus-visible:ring-1 focus-visible:ring-violet-400`}>
          {label}
        </button>
      );
    }
    return <span className={`${cls} text-violet-300/80`} title={`${file}:${line} — not among this PR's changed files`}>{label}</span>;
  }
  if (!onJump) return <span className={`${cls} text-slate-500`}>{label}</span>;
  return (
    <button type="button" onClick={() => onJump(line)} title={`Jump to line ${line}`}
      className={`${cls} text-sky-300 hover:bg-sky-500/15 hover:text-sky-200 focus:outline-none focus-visible:ring-1 focus-visible:ring-sky-400`}>
      {label}
    </button>
  );
}

interface FileGroup { file: string; steps: FlowStep[] }

/** Consecutive steps in the same file, in path order. */
function groupByFile(flow: readonly FlowStep[], filePath: string): FileGroup[] {
  const groups: FileGroup[] = [];
  for (const s of flow) {
    const file = s.otherFile ?? filePath;
    const last = groups[groups.length - 1];
    if (last && last.file === file) last.steps.push(s);
    else groups.push({ file, steps: [s] });
  }
  return groups;
}

/** The whole path at a glance: input -> (the files it crosses) -> sink. Always visible for data-flow findings. */
function FlowRibbon({ flow, filePath, onJump, nav }: { flow: FlowStep[]; filePath: string; onJump?: (line: number) => void; nav?: FileNavigation }) {
  const source = flow.find(s => s.kind === "source");
  const sink = flow[flow.length - 1];
  if (!source || !sink || sink === source) return null;
  const groups = groupByFile(flow, filePath);
  const crossesFiles = groups.length > 1;
  const middle = flow.length - 2;
  const node = (kind: "source" | "sink", s: FlowStep) => (
    <span className={`inline-flex max-w-full items-center gap-1.5 rounded-lg px-2 py-1 ring-1 ${kind === "source" ? "bg-sky-500/10 ring-sky-400/25" : "bg-rose-500/10 ring-rose-400/25"}`}>
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${kind === "source" ? "bg-sky-400" : "bg-rose-400"}`} aria-hidden />
      <span className={`text-[10px] font-bold uppercase tracking-wider ${kind === "source" ? "text-sky-300" : "text-rose-300"}`}>{kind === "source" ? "Input" : "Sink"}</span>
      <code className="truncate font-mono text-[11px] text-slate-100">{s.text}</code>
      {s.line != null && <LineRef line={s.line} file={s.otherFile} filePath={filePath} onJump={onJump} nav={nav} />}
    </span>
  );
  const arrow = <Icon d={ICON.arrow} size={12} className="shrink-0 text-slate-500" />;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {node("source", source)}
      {crossesFiles ? (
        groups.slice(1, -1).map(g => (
          <span key={g.file} className="inline-flex items-center gap-1.5">
            {arrow}
            <span className="inline-flex items-center gap-1 rounded-lg bg-violet-500/10 px-2 py-1 font-mono text-[10.5px] text-violet-200 ring-1 ring-violet-400/25" title={g.file}>
              <Icon d={ICON.file} size={10} className="text-violet-300" />{baseName(g.file)}
            </span>
          </span>
        ))
      ) : middle > 0 ? (
        <>{arrow}<span className="text-[10.5px] text-slate-400">{middle} step{middle === 1 ? "" : "s"}</span></>
      ) : null}
      {arrow}
      {node("sink", sink)}
      {crossesFiles && (
        <span className={`${CHIP} ml-0.5 bg-violet-500/10 text-violet-200 ring-violet-400/30`} title="The value is traced through calls into other files">
          crosses {groups.length - 1} file boundar{groups.length - 1 === 1 ? "y" : "ies"}
        </span>
      )}
    </div>
  );
}

/** Every step of the path, grouped by the file it happens in. */
function FlowPath({ flow, filePath, fromEndpointsOnly, onJump, nav }: {
  flow: FlowStep[]; filePath: string; fromEndpointsOnly: boolean; onJump?: (line: number) => void; nav?: FileNavigation;
}) {
  const [all, setAll] = useState(false);
  // Always keep the origin and the sink; elide the middle of a long path until asked.
  const hidden = !all && flow.length > FLOW_PREVIEW ? flow.length - FLOW_PREVIEW : 0;
  const shown = hidden ? [...flow.slice(0, FLOW_PREVIEW - 1), flow[flow.length - 1]] : flow;
  const groups = groupByFile(shown, filePath);
  let n = 0;
  return (
    <div className="space-y-2.5">
      {groups.map((g, gi) => {
        const here = g.file === filePath;
        return (
          <div key={`${g.file}-${gi}`} className={`rounded-lg ring-1 ${here ? "bg-white/[0.025] ring-white/[0.07]" : "bg-violet-500/[0.05] ring-violet-400/15"}`}>
            <div className="flex items-center gap-1.5 border-b border-white/[0.06] px-2.5 py-1.5">
              <Icon d={ICON.file} size={11} className={here ? "text-slate-500" : "text-violet-300"} />
              <span className={`truncate font-mono text-[10.5px] ${here ? "text-slate-300" : "text-violet-200"}`} title={g.file}>{g.file || "this file"}</span>
              {here && <span className="ml-auto text-[9.5px] font-semibold uppercase tracking-wider text-slate-500">this file</span>}
            </div>
            <ol className="space-y-2 px-2.5 py-2">
              {g.steps.map((s, i) => {
                n++;
                const lastInGroup = i === g.steps.length - 1;
                const elidedAfter = hidden > 0 && n === FLOW_PREVIEW - 1;
                return (
                  <li key={`${s.kind}-${s.line}-${i}`} className="relative flex gap-2.5">
                    {!lastInGroup && <span className="absolute left-[3.5px] top-3.5 bottom-[-10px] w-px bg-gradient-to-b from-slate-500/60 to-slate-600/30" aria-hidden />}
                    <span className={`relative mt-[5px] h-2 w-2 shrink-0 rounded-full ring-4 ${STEP_DOT[s.kind]}`} aria-hidden />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <span className={`text-[10px] font-bold uppercase tracking-wider ${STEP_LABEL_TONE[s.kind] ?? "text-slate-400"}`}>{s.kindLabel}</span>
                        {s.line != null && <LineRef line={s.line} file={s.otherFile} filePath={filePath} onJump={onJump} nav={nav} emphasis={s.kind === "sink"} />}
                      </div>
                      <p className="mt-0.5 font-mono text-[11px] leading-relaxed text-slate-200 break-words">{s.text}</p>
                      {elidedAfter && (
                        <button type="button" onClick={() => setAll(true)}
                          className="mt-1.5 text-[10.5px] font-semibold text-sky-300 hover:text-sky-200 focus:outline-none focus-visible:underline">
                          … {hidden} more step{hidden === 1 ? "" : "s"}
                        </button>
                      )}
                    </div>
                  </li>
                );
              })}
            </ol>
          </div>
        );
      })}
      {fromEndpointsOnly && (
        <p className="text-[11px] text-slate-500">Only the start and end of this flow were recorded; intermediate steps aren’t available for this finding.</p>
      )}
    </div>
  );
}

function FixBlock({ fix, language }: { fix: FixSuggestion; language?: string }) {
  const showExample = !!(fix.code_before || fix.code_after) && JS_LANGS.has((language ?? "").toLowerCase());
  return (
    <div className="space-y-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-[12.5px] font-semibold text-slate-50">{fix.title}</p>
        <span className={`${CHIP} bg-white/5 text-slate-300 ring-white/10`}>{fix.effort} effort</span>
      </div>
      <p className="text-[12px] leading-relaxed text-slate-300">{fix.description}</p>
      {showExample && (
        <div className="grid gap-2 sm:grid-cols-2">
          {fix.code_before && (
            <div className="overflow-hidden rounded-lg ring-1 ring-rose-400/20">
              <p className="bg-rose-500/10 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-rose-200/90">Before</p>
              <pre className="overflow-x-auto bg-black/40 p-2.5 font-mono text-[11px] leading-relaxed text-slate-300">{fix.code_before}</pre>
            </div>
          )}
          {fix.code_after && (
            <div className="overflow-hidden rounded-lg ring-1 ring-emerald-400/20">
              <p className="bg-emerald-500/10 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-emerald-200/90">After</p>
              <pre className="overflow-x-auto bg-black/40 p-2.5 font-mono text-[11px] leading-relaxed text-slate-300">{fix.code_after}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** The inline explanation rendered directly under a flagged line. */
export function InlineSecurityFinding({ ind, filePath, language, meta, fix, siblings, defaultOpen, onJump, nav }: {
  ind: FileIndicator;
  filePath: string;
  language?: string;
  meta?: FindingMeta;
  fix?: FixSuggestion;
  siblings: readonly FileIndicator[];
  defaultOpen?: boolean;
  onJump?: (line: number) => void;
  nav?: FileNavigation;
}) {
  const [open, setOpen] = useState(!!defaultOpen);
  const [fixOpen, setFixOpen] = useState(false);
  const ev = useMemo(() => buildFindingEvidence(ind, filePath, siblings), [ind, filePath, siblings]);
  const sev = normSev(ind.severity);
  const style = SEV_STYLE[sev];
  const title = meta?.label ?? findingMeta(ind.id, ind.label).title;
  const cweId = ind.cwe ?? cweFor(ind.id)?.id;
  const cweTitle = cweFor(ind.id)?.title;
  const cweNum = cweId?.match(/\d+/)?.[0];
  const muted = ind.codeCategory === "third_party" || ind.codeCategory === "test_code";
  const related = ind.relatedLocations ?? [];

  return (
    <div className={`relative overflow-hidden rounded-xl bg-gradient-to-b from-slate-800/95 to-slate-900/95 font-sans shadow-lg ${style.glow} ring-1 ring-white/10 ${muted ? "opacity-80" : ""}`}>
      <span className={`absolute inset-y-0 left-0 w-1 bg-gradient-to-b ${muted ? "from-slate-500 to-slate-600" : style.bar}`} aria-hidden />
      <div className="space-y-3 py-3.5 pl-5 pr-4">
        {/* Title + metadata */}
        <div className="flex flex-wrap items-start gap-x-3 gap-y-2">
          <div className="flex min-w-0 flex-1 items-start gap-2.5">
            <span className={`mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-white/5 ring-1 ring-white/10 ${style.icon}`}>
              <Icon d={ICON.shield} size={15} />
            </span>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h4 className="text-[13.5px] font-semibold leading-snug text-white">{title}</h4>
                <span className={`${CHIP} uppercase tracking-wide ${style.pill}`}>{sev}</span>
              </div>
              {ind.functionName && (
                <p className="mt-0.5 text-[11px] text-slate-400">in <span className="font-mono text-slate-300">{ind.functionName}()</span></p>
              )}
            </div>
          </div>
          <span className="flex flex-wrap items-center gap-1.5">
            <span className={`${CHIP} ${ev.isDataFlow ? "bg-sky-500/10 text-sky-200 ring-sky-400/30" : "bg-white/5 text-slate-300 ring-white/10"}`}
              title={ev.isDataFlow ? "Found by tracing the value through the parsed code" : "Found by matching a code pattern on this line"}>
              {ev.analysisLabel}{ind.confidence != null ? ` · ${ind.confidence}%` : ""}
            </span>
            {cweId && (
              cweNum
                ? <a href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`} target="_blank" rel="noopener noreferrer"
                    title={cweTitle} className={`${CHIP} bg-white/5 text-slate-300 ring-white/10 hover:text-white hover:ring-white/25 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400`}>{cweId}</a>
                : <span className={`${CHIP} bg-white/5 text-slate-300 ring-white/10`} title={cweTitle}>{cweId}</span>
            )}
            {ind.reachability && REACH_STYLE[ind.reachability] && (
              <span className={`${CHIP} ${REACH_STYLE[ind.reachability]}`} title={REACH_DESC[ind.reachability]}>{REACH_LABEL[ind.reachability]}</span>
            )}
            {ind.remediation_urgency && !muted && (
              <span className={`${CHIP} ${URGENCY_STYLE[ind.remediation_urgency]}`} title={URGENCY_DESC[ind.remediation_urgency]}>{URGENCY_LABEL[ind.remediation_urgency]}</span>
            )}
            {muted && (
              <span className={`${CHIP} bg-white/5 text-slate-300 ring-white/10`} title="Kept as evidence but excluded from this file's risk score">
                {ind.codeCategory === "third_party" ? "Third-party code" : "Test code"}
              </span>
            )}
          </span>
        </div>

        {/* Explanation */}
        <p className="text-[12.5px] leading-relaxed text-slate-200"><Parts parts={ev.summary} /></p>

        {/* The path at a glance */}
        {ev.isDataFlow && <FlowRibbon flow={ev.flow} filePath={filePath} onJump={onJump} nav={nav} />}
        {ev.onPathOf && (
          <p className="text-[11px] text-slate-400">
            Part of the confirmed data flow flagged at <LineRef line={ev.onPathOf.line} filePath={filePath} onJump={onJump} />.
          </p>
        )}
        {(ind.reachedFrom ?? []).length > 0 && (
          <p className="flex flex-wrap items-center gap-1 text-[11px] text-slate-400">
            <Icon d={ICON.arrow} size={11} className="text-violet-300" />
            <span>Reached by the confirmed data flow from</span>
            {ind.reachedFrom!.map(o => (
              <LineRef key={`${o.file}:${o.line}:${o.id}`} line={o.line} file={o.file} filePath={filePath} onJump={onJump} nav={nav} />
            ))}
          </p>
        )}
        {related.length > 0 && (
          <p className="flex flex-wrap items-center gap-1 text-[11px] text-slate-400">
            <Icon d={ICON.link} size={11} className="text-slate-500" />
            <span>Same issue also reported at</span>
            {related.map(r => (
              <span key={`${r.line}-${r.id}`} title={`${r.label} (${r.reason === "on-path" ? "on this data-flow path" : "same line"})`}>
                <LineRef line={r.line} filePath={filePath} onJump={onJump} />
              </span>
            ))}
          </p>
        )}

        <div className="flex flex-wrap items-center gap-1.5">
          <Toggle open={open} onClick={() => setOpen(v => !v)} icon={ICON.eye}>{open ? "Hide evidence" : "Show evidence"}</Toggle>
          {fix && <Toggle open={fixOpen} onClick={() => setFixOpen(v => !v)} icon={ICON.wrench}>Recommended fix</Toggle>}
        </div>

        {open && (
          <div className="grid gap-4 border-t border-white/[0.07] pt-3.5 grid-cols-[repeat(auto-fit,minmax(min(100%,300px),1fr))]">
            {ev.flow.length > 0 && (
              <div className="min-w-0">
                <SectionLabel>Data flow</SectionLabel>
                <FlowPath flow={ev.flow} filePath={filePath} fromEndpointsOnly={ev.flowFromEndpointsOnly} onJump={onJump} nav={nav} />
              </div>
            )}
            <div className={`min-w-0 ${ev.flow.length === 0 ? "col-span-full" : ""}`}>
              <SectionLabel>Why this was flagged</SectionLabel>
              <ul className="space-y-2">
                {ev.checks.map((c, i) => (
                  <li key={i} className="flex gap-2.5 text-[12px] leading-relaxed text-slate-300">
                    <CheckIcon tone={c.tone} />
                    <span className="min-w-0"><Parts parts={c.parts} /></span>
                  </li>
                ))}
              </ul>
              {(ind.exploitability_score != null || meta?.desc || (cweTitle && cweTitle.toLowerCase() !== title.toLowerCase())) && (
                <dl className="mt-3.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 rounded-lg bg-white/[0.03] p-2.5 text-[11px] ring-1 ring-white/[0.06]">
                  {ind.exploitability_score != null && (
                    <>
                      <dt className="text-slate-500">Exploitability</dt>
                      <dd className="flex items-center gap-2 text-slate-200 tabular-nums">
                        <span className="h-1.5 w-16 overflow-hidden rounded-full bg-white/10">
                          <span className="block h-full rounded-full bg-gradient-to-r from-amber-400 to-rose-500" style={{ width: `${Math.min(100, ind.exploitability_score * 10)}%` }} />
                        </span>
                        {ind.exploitability_score.toFixed(1)} / 10
                      </dd>
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
          <div className="border-t border-white/[0.07] pt-3.5">
            <SectionLabel icon={ICON.wrench}>Recommended fix</SectionLabel>
            <FixBlock fix={fix} language={language} />
          </div>
        )}
      </div>
    </div>
  );
}

export type { CrossFileMark };

const MARK_WORDS: Record<CrossFileMark["role"], string> = {
  parameter: "Enters this file as a parameter —",
  step: "A step of",
  sink: "The sink of",
  merged: "Reported as part of",
};

/** Under a line of this file: "The sink of the SQL Injection flow reported at users.ts:5". */
export function InlineCrossFileMark({ marks, filePath, nav }: { marks: CrossFileMark[]; filePath: string; nav?: FileNavigation }) {
  const [m, ...rest] = marks;
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg bg-violet-500/[0.07] px-3 py-1.5 font-sans ring-1 ring-violet-400/20">
      <span className={`${CHIP} bg-violet-500/15 text-violet-200 ring-violet-400/30`}>
        <Icon d={ICON.link} size={10} />Cross-file flow
      </span>
      <p className="text-[11.5px] leading-relaxed text-slate-300">
        {MARK_WORDS[m.role]} the <span className="font-semibold text-slate-100">{m.title}</span> flow reported at{" "}
        <LineRef line={m.fromLine} file={m.fromFile} filePath={filePath} nav={nav} />
        {rest.length > 0 && <span className="text-slate-500"> (+{rest.length} more)</span>}
      </p>
    </div>
  );
}

/** A one-line note for a non-security (AI-authorship) signal on this line. */
export function InlineSignalNote({ ind, meta }: { ind: FileIndicator; meta?: FindingMeta }) {
  return (
    <div className="flex items-start gap-2.5 rounded-lg bg-indigo-500/[0.06] px-3 py-2 font-sans ring-1 ring-indigo-400/15">
      <span className={`${CHIP} bg-indigo-500/15 text-indigo-200 ring-indigo-400/30`}>AI signal</span>
      <p className="text-[11.5px] leading-relaxed text-slate-300">
        <span className="font-semibold text-slate-100">{meta?.label ?? ind.label}</span>
        {(meta?.desc ?? ind.detail) && <span className="text-slate-400"> — {meta?.desc ?? ind.detail}</span>}
      </p>
    </div>
  );
}
