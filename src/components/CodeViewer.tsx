"use client";

interface Props {
  code: string;
  language?: string;
  filename?: string;
  riskIndicators?: string[];
  maxHeight?: string;
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

// Lines containing these patterns get a risk highlight
const RISKY: RegExp[] = [
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /password\s*=\s*["'][^"']{4,}/i,
  /secret\s*=\s*["'][^"']{4,}/i,
  /api_key\s*=\s*["'][^"']{4,}/i,
  /sk_live_/i,
  /whsec_/i,
  /verify_signature.*False/i,
  /\.execute\(\s*[^?][^,)]{10,}\)/,
  /["']\s*\+\s*str\(/,
  /f["'][^"']*\{[a-zA-Z_]/,
];

export default function CodeViewer({ code, language = "python", filename, riskIndicators = [], maxHeight = "380px" }: Props) {
  const lines = code.split("\n");

  return (
    <div className="rounded-xl overflow-hidden border border-slate-700/60 text-xs font-mono">
      {filename && (
        <div className="flex items-center justify-between bg-slate-800 px-4 py-2 border-b border-slate-700">
          <span className="text-slate-400">{filename}</span>
          <span className="text-slate-600 capitalize">{language}</span>
        </div>
      )}
      <div className="overflow-auto bg-slate-900" style={{ maxHeight }}>
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((line, idx) => {
              const isRisky = RISKY.some(re => re.test(line));
              return (
                <tr
                  key={idx}
                  className={isRisky ? "bg-rose-900/25 hover:bg-rose-900/35" : "hover:bg-slate-800/40"}
                >
                  <td className="select-none text-right pr-3 pl-4 py-px text-slate-600 border-r border-slate-800/60 w-9 min-w-[36px] align-top">
                    {idx + 1}
                  </td>
                  <td className="pl-4 py-px whitespace-pre leading-relaxed">
                    {isRisky && (
                      <span className="text-rose-500 mr-2 text-[10px]" title="Risk pattern detected">⚠</span>
                    )}
                    {tokenizeLine(line, language).map((tok, ti) => (
                      <span key={ti} className={TOKEN_CLS[tok.type]}>{tok.text}</span>
                    ))}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
