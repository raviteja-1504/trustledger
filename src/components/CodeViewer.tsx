"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FileIndicator, FixSuggestion } from "@/types";
import { findingMeta } from "@/lib/findingCatalog";
import Tip from "@/components/Tip";
import { ACTION_TIP } from "@/lib/prTooltips";
import { InlineCrossFileMark, InlineSecurityFinding, InlineSignalNote, type CrossFileMark, type FileNavigation, type FindingMeta } from "@/components/InlineFinding";

interface Props {
  code: string;
  language?: string;
  filename?: string;
  // Real per-line findings from the scanner (file.indicators from /api/scans/[id]), each with a .line
  // number. Each flagged line is highlighted and gets its evidence rendered inline directly beneath it.
  indicators?: FileIndicator[];
  // Accepted for existing callers; line-level rendering comes from `indicators` only.
  riskIndicators?: string[];
  maxHeight?: string;
  // Remediation guidance (file.fix_suggestions), matched to findings by vulnerability id.
  fixes?: FixSuggestion[];
  // Curated label/description for a finding id, and whether it is a security finding (vs an AI signal).
  describe?: (id: string) => FindingMeta | undefined;
  // Opening another file of the PR from a cross-file data-flow step (absent: those steps aren't links).
  nav?: FileNavigation;
  // Scroll to and flash this line (e.g. when another file's finding links here). `seq` re-triggers the same line.
  jumpRequest?: { line: number; seq: number };
  // Lines other files' data flows pass through (dataFlowEvidence.ts crossFileMarks).
  crossFileMarks?: CrossFileMark[];
  // Stepping past the last (1) or before the first (-1) finding: lets a host move on to the next/previous file.
  // Without it, stepping wraps around within this file.
  onEdge?: (dir: 1 | -1) => void;
  // Which finding to land on when this viewer opens (arriving from a following / preceding file).
  initialFinding?: "first" | "last";
  // Focus the viewer when it opens, so the n / p keys work at once.
  autoFocus?: boolean;
}

type TokType = "keyword" | "string" | "comment" | "number" | "builtin" | "plain" | "operator";

interface Tok { type: TokType; text: string }

const PY_KW  = new Set(["def","class","import","from","return","if","elif","else","for","while","try","except","finally","with","as","pass","break","continue","None","True","False","and","or","not","in","is","lambda","yield","raise","del","global","nonlocal","async","await"]);
const TS_KW  = new Set(["const","let","var","function","class","return","if","else","for","while","try","catch","finally","import","export","default","type","interface","enum","extends","implements","new","delete","typeof","instanceof","void","null","undefined","true","false","async","await","yield"]);
const DANGER = new Set(["eval","exec"]);

function tokenizeLine(line: string, lang: string): Tok[] {
  const toks: Tok[] = [];
  const kw = lang === "typescript" || lang === "javascript" ? TS_KW : PY_KW;
  let i = 0;
  while (i < line.length) {
    const ch = line[i];
    // Single-line comment
    if (ch === "#" || (ch === "/" && line[i+1] === "/")) {
      toks.push({ type: "comment", text: line.slice(i) }); break;
    }
    // String
    if (ch === '"' || ch === "'" || ch === "`") {
      let j = i + 1;
      while (j < line.length && line[j] !== ch) { if (line[j] === "\\") j++; j++; }
      toks.push({ type: "string", text: line.slice(i, j + 1) });
      i = j + 1; continue;
    }
    // Number
    if (/[0-9]/.test(ch) && (i === 0 || /\W/.test(line[i-1]))) {
      let j = i; while (j < line.length && /[0-9._xXa-fA-F]/.test(line[j])) j++;
      toks.push({ type: "number", text: line.slice(i, j) }); i = j; continue;
    }
    // Identifier / keyword
    if (/[a-zA-Z_]/.test(ch)) {
      let j = i; while (j < line.length && /[a-zA-Z0-9_]/.test(line[j])) j++;
      const word = line.slice(i, j);
      toks.push({ type: DANGER.has(word) ? "builtin" : kw.has(word) ? "keyword" : "plain", text: word });
      i = j; continue;
    }
    toks.push({ type: "plain", text: ch }); i++;
  }
  return toks;
}

const TOKEN_CLS: Record<TokType, string> = {
  keyword:  "text-violet-400 font-semibold",
  string:   "text-amber-300",
  comment:  "text-slate-500 italic",
  number:   "text-sky-300",
  builtin:  "text-rose-400 font-bold",
  operator: "text-slate-400",
  plain:    "text-slate-300",
};

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const GUTTER_PX = 44;
const PANEL_WIDTH = `calc(100cqw - ${GUTTER_PX + 24}px)`;

export default function CodeViewer({ code, language = "python", filename, indicators = [], maxHeight = "380px", fixes, describe, nav, jumpRequest, crossFileMarks, onEdge, initialFinding, autoFocus }: Props) {
  const lines = useMemo(() => code.split("\n"), [code]);
  const marksByLine = useMemo(() => {
    const m = new Map<number, CrossFileMark[]>();
    for (const mark of crossFileMarks ?? []) m.set(mark.line, [...(m.get(mark.line) ?? []), mark]);
    return m;
  }, [crossFileMarks]);
  const scrollRef = useRef<HTMLDivElement>(null);
  const rowRefs = useRef(new Map<number, HTMLTableRowElement>());
  const [flashLine, setFlashLine] = useState<number | null>(null);

  const isSecurity = useCallback((ind: FileIndicator) => !!describe?.(ind.id)?.security || !!ind.cwe, [describe]);

  // line -> findings on that line: security findings first, most severe first.
  const byLine = useMemo(() => {
    const m = new Map<number, FileIndicator[]>();
    for (const ind of indicators) {
      if (ind.line == null) continue;
      const arr = m.get(ind.line) ?? [];
      arr.push(ind);
      m.set(ind.line, arr);
    }
    for (const arr of m.values()) {
      arr.sort((a, b) => Number(isSecurity(b)) - Number(isSecurity(a)) || (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0));
    }
    return m;
  }, [indicators, isSecurity]);

  const securityLines = useMemo(
    () => [...byLine.entries()].filter(([, arr]) => arr.some(isSecurity)).map(([l]) => l).sort((a, b) => a - b),
    [byLine, isSecurity],
  );
  // The single most severe security finding in the file opens with its evidence already expanded.
  const autoOpen = useMemo(() => {
    let best: FileIndicator | undefined;
    for (const ind of indicators) {
      if (ind.line == null || !isSecurity(ind) || ind.codeCategory === "third_party" || ind.codeCategory === "test_code") continue;
      if (!best || (SEV_RANK[ind.severity] ?? 0) > (SEV_RANK[best.severity] ?? 0)) best = ind;
    }
    return best;
  }, [indicators, isSecurity]);
  const fixById = useMemo(() => new Map((fixes ?? []).map(f => [f.vuln_id, f])), [fixes]);

  const jumpTo = useCallback((line: number) => {
    const container = scrollRef.current;
    const row = rowRefs.current.get(line);
    if (!container || !row) return;
    container.scrollTo({ top: Math.max(0, row.offsetTop - 48), behavior: "smooth" });
    setFlashLine(line);
  }, []);

  // Another file's finding linked here: bring this viewer into view, then the line.
  useEffect(() => {
    if (!jumpRequest) return;
    scrollRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    const t = setTimeout(() => jumpTo(jumpRequest.line), 250);
    return () => clearTimeout(t);
  }, [jumpRequest, jumpTo]);

  useEffect(() => {
    if (flashLine == null) return;
    const t = setTimeout(() => setFlashLine(null), 1400);
    return () => clearTimeout(t);
  }, [flashLine]);

  // Open on the first flagged line rather than the top of a long file. Scrolls only this viewer.
  const firstFinding = securityLines[0];
  useEffect(() => {
    const container = scrollRef.current;
    const row = firstFinding != null ? rowRefs.current.get(firstFinding) : undefined;
    if (container && row && row.offsetTop > container.clientHeight * 0.6) container.scrollTop = Math.max(0, row.offsetTop - 48);
  }, [firstFinding, code]);

  // One entry per flagged line for the findings strip: its most severe security finding.
  const findingList = useMemo(() => securityLines.map(line => {
    const top = (byLine.get(line) ?? []).find(isSecurity)!;
    return { line, sev: top.severity, title: describe?.(top.id)?.label ?? findingMeta(top.id, top.label).title };
  }), [securityLines, byLine, isSecurity, describe]);

  // The flagged line the reviewer is on. `stepSeq` changes on every move, so a finding opens its evidence each
  // time it is stepped to -- even one that was closed before.
  const [navIdx, setNavIdx] = useState(0);
  const [stepSeq, setStepSeq] = useState(0);
  const goTo = useCallback((idx: number) => {
    if (securityLines.length === 0) return;
    setNavIdx(idx);
    setStepSeq(s => s + 1);
    jumpTo(securityLines[idx]);
  }, [securityLines, jumpTo]);
  const step = (dir: 1 | -1) => {
    if (securityLines.length === 0) return;
    const next = navIdx + dir;
    if (onEdge && (next < 0 || next >= securityLines.length)) { onEdge(dir); return; }
    goTo((next + securityLines.length) % securityLines.length);
  };
  // The viewer opens on the first flagged line, so the position always names a finding (the first until moved).
  const activeLine = securityLines[navIdx];

  // Arrived from the next file going backwards: start on its last finding.
  useEffect(() => {
    if (initialFinding !== "last" || securityLines.length < 2) return undefined;
    const t = setTimeout(() => goTo(securityLines.length - 1), 0);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const wrapRef = useRef<HTMLDivElement>(null);
  useEffect(() => { if (autoFocus) wrapRef.current?.focus({ preventScroll: true }); }, [autoFocus]);
  // n / p step through the findings. Ignored while typing (the triage reason box, the evidence panels' inputs).
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const t = e.target as HTMLElement;
    if (t.isContentEditable || /^(?:INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) return;
    if (e.key === "n") { e.preventDefault(); step(1); }
    else if (e.key === "p") { e.preventDefault(); step(-1); }
  };

  const canStep = securityLines.length > 1 || (securityLines.length > 0 && !!onEdge);

  return (
    <div ref={wrapRef} tabIndex={0} onKeyDown={onKeyDown} aria-keyshortcuts="n p"
      className="rounded-xl overflow-hidden border border-slate-700/60 text-xs font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60">
      {(filename || securityLines.length > 0) && (
        <div className="bg-slate-800 border-b border-slate-700">
          <div className="flex items-center justify-between gap-3 px-4 py-2">
            <span className="text-slate-400 truncate">{filename}</span>
            <span className="text-slate-600 capitalize shrink-0">{language}</span>
          </div>
          {securityLines.length > 0 && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-slate-700/70 px-4 py-2 font-sans">
              <span className="text-[12px] font-semibold text-rose-300" data-testid="finding-position">
                Finding {navIdx + 1} of {securityLines.length}
              </span>
              {canStep && (
                <span className="flex items-center gap-1.5">
                  <Tip tip={ACTION_TIP.prevFinding}>
                    <button type="button" onClick={() => step(-1)} aria-label="Previous finding"
                      className="rounded-md bg-slate-700/70 px-2.5 py-1 text-[11px] font-semibold text-slate-100 hover:bg-slate-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">‹ Previous</button>
                  </Tip>
                  <Tip tip={ACTION_TIP.nextFinding}>
                    <button type="button" onClick={() => step(1)} aria-label="Next finding"
                      className="rounded-md bg-slate-700/70 px-2.5 py-1 text-[11px] font-semibold text-slate-100 hover:bg-slate-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">Next ›</button>
                  </Tip>
                  <span className="hidden text-[10px] text-slate-500 sm:inline">or press <kbd className="rounded bg-slate-700 px-1 text-slate-300">p</kbd> / <kbd className="rounded bg-slate-700 px-1 text-slate-300">n</kbd></span>
                </span>
              )}
            </div>
          )}
          {findingList.length > 1 && (
            <div className="flex gap-1.5 overflow-x-auto border-t border-slate-700/70 px-4 py-2 font-sans" role="group" aria-label="Findings in this file">
              {findingList.map((f, i) => (
                <button key={f.line} type="button" onClick={() => goTo(i)} aria-current={activeLine === f.line ? "true" : undefined}
                  className={`shrink-0 inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-medium ring-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
                    activeLine === f.line ? "bg-sky-500/25 text-sky-50 ring-sky-400/60" : "bg-slate-900/60 text-slate-300 ring-slate-600/60 hover:bg-slate-700/60"}`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${f.sev === "critical" ? "bg-violet-400" : f.sev === "high" ? "bg-orange-400" : f.sev === "medium" ? "bg-amber-300" : "bg-sky-300"}`} aria-hidden />
                  <span className="tabular-nums text-slate-400">L{f.line}</span> {f.title}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
      {/* An inline-size container, so inline panels can size to the VISIBLE width (100cqw) and stay put while
          long code lines scroll horizontally -- correct from the first (server-rendered) paint. */}
      <div ref={scrollRef} className="relative overflow-auto bg-slate-900" style={{ maxHeight, containerType: "inline-size" }}>
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((line, idx) => {
              const lineNo = idx + 1;
              const found = byLine.get(lineNo) ?? [];
              const security = found.filter(isSecurity);
              const signals = found.filter(i => !isSecurity(i));
              const hasSecurity = security.length > 0;
              const marks = marksByLine.get(lineNo) ?? [];
              const rowCls = flashLine === lineNo
                ? "bg-sky-500/25 transition-colors"
                : hasSecurity ? "bg-rose-900/30 hover:bg-rose-900/40"
                : marks.length > 0 ? "bg-violet-900/25 hover:bg-violet-900/35"
                : signals.length > 0 ? "bg-indigo-900/20 hover:bg-indigo-900/30"
                : "hover:bg-slate-800/40";
              return [
                <tr
                  key={`l${lineNo}`}
                  ref={el => { if (el) rowRefs.current.set(lineNo, el); else rowRefs.current.delete(lineNo); }}
                  className={rowCls}
                >
                  <td
                    className={`select-none text-right pr-3 pl-4 py-px border-r align-top tabular-nums ${hasSecurity ? "text-rose-300 font-semibold border-rose-500/60" : "text-slate-600 border-slate-800/60"}`}
                    style={{ width: GUTTER_PX, minWidth: GUTTER_PX }}
                  >
                    {lineNo}
                  </td>
                  <td className="pl-4 py-px whitespace-pre leading-relaxed">
                    {hasSecurity && <span className="text-rose-500 mr-2 text-[10px]" aria-hidden>⚠</span>}
                    {tokenizeLine(line, language).map((tok, ti) => (
                      <span key={ti} className={TOKEN_CLS[tok.type]}>{tok.text}</span>
                    ))}
                  </td>
                </tr>,
                (found.length > 0 || marks.length > 0) && (
                  <tr key={`f${lineNo}`} className="bg-slate-900">
                    <td className={`border-r ${hasSecurity ? "border-rose-500/60" : "border-slate-800/60"}`} style={{ width: GUTTER_PX, minWidth: GUTTER_PX }} />
                    <td className="py-2 pl-3 pr-3 whitespace-normal">
                      <div className="sticky left-3 space-y-2" style={{ width: PANEL_WIDTH }}>
                        {security.map((ind, i) => (
                          <InlineSecurityFinding
                            key={`${ind.id}:${ind.fingerprint ?? i}`}
                            ind={ind}
                            filePath={filename ?? ""}
                            language={language}
                            meta={describe?.(ind.id)}
                            fix={fixById.get(ind.id)}
                            siblings={indicators}
                            defaultOpen={ind === autoOpen}
                            focusSeq={stepSeq > 0 && activeLine === lineNo ? stepSeq : undefined}
                            onJump={jumpTo}
                            nav={nav}
                          />
                        ))}
                        {marks.length > 0 && <InlineCrossFileMark marks={marks} filePath={filename ?? ""} nav={nav} />}
                        {signals.map((ind, i) => (
                          <InlineSignalNote key={`${ind.id}:${i}`} ind={ind} meta={describe?.(ind.id)} />
                        ))}
                      </div>
                    </td>
                  </tr>
                ),
              ];
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
