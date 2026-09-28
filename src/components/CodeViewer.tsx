"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FileIndicator, FixSuggestion } from "@/types";
import { InlineSecurityFinding, InlineSignalNote, type FindingMeta } from "@/components/InlineFinding";

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

export default function CodeViewer({ code, language = "python", filename, indicators = [], maxHeight = "380px", fixes, describe }: Props) {
  const lines = useMemo(() => code.split("\n"), [code]);
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

  const [navIdx, setNavIdx] = useState(0);
  const step = (dir: 1 | -1) => {
    if (securityLines.length === 0) return;
    const next = (navIdx + dir + securityLines.length) % securityLines.length;
    setNavIdx(next);
    jumpTo(securityLines[next]);
  };

  return (
    <div className="rounded-xl overflow-hidden border border-slate-700/60 text-xs font-mono">
      {(filename || securityLines.length > 0) && (
        <div className="flex items-center justify-between gap-3 bg-slate-800 px-4 py-2 border-b border-slate-700">
          <span className="text-slate-400 truncate">{filename}</span>
          <div className="flex items-center gap-3 shrink-0">
            {securityLines.length > 0 && (
              <div className="flex items-center gap-1 font-sans">
                <span className="text-[11px] font-semibold text-rose-300">
                  {securityLines.length} flagged line{securityLines.length === 1 ? "" : "s"}
                </span>
                {securityLines.length > 1 && (
                  <>
                    <button type="button" onClick={() => step(-1)} aria-label="Previous flagged line"
                      className="ml-1 h-5 w-5 rounded text-slate-300 hover:bg-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">‹</button>
                    <button type="button" onClick={() => step(1)} aria-label="Next flagged line"
                      className="h-5 w-5 rounded text-slate-300 hover:bg-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">›</button>
                  </>
                )}
              </div>
            )}
            <span className="text-slate-600 capitalize">{language}</span>
          </div>
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
              const rowCls = flashLine === lineNo
                ? "bg-sky-500/25 transition-colors"
                : hasSecurity ? "bg-rose-900/30 hover:bg-rose-900/40"
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
                found.length > 0 && (
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
                            onJump={jumpTo}
                          />
                        ))}
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
