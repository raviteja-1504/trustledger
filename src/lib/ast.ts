/**
 * TrustLedger Structural AST Engine
 *
 * Multi-language structural analysis via a line-level scanner. Produces function
 * topology, class hierarchy, import/export graph, cyclomatic complexity, Halstead
 * volume, and an index of AST-level security risk patterns. No external parser
 * required — runs entirely in pure TypeScript.
 *
 * Supported: TypeScript/JavaScript, Python, Go
 */

// ── Public types ──────────────────────────────────────────────────────────────

export type NodeKind =
  | "program" | "function" | "arrow" | "method" | "class"
  | "if" | "else" | "for" | "while" | "do" | "switch" | "try" | "catch"
  | "assignment" | "vardecl" | "return" | "throw"
  | "call" | "member" | "binary" | "import" | "export" | "block" | "unknown";

export interface AstNode {
  kind:      NodeKind;
  text:      string;
  line:      number;
  endLine:   number;
  depth:     number;
  children:  AstNode[];
  name?:     string;
  params?:   string[];
  isAsync?:  boolean;
  isExport?: boolean;
}

export interface FunctionInfo {
  name:        string;
  line:        number;
  endLine:     number;
  paramCount:  number;
  isAsync:     boolean;
  isExported:  boolean;
  isArrow:     boolean;
  isMethod:    boolean;
  complexity:  number;
  nestDepth:   number;
}

export interface ClassInfo {
  name:        string;
  line:        number;
  endLine:     number;
  methods:     string[];
  isExported:  boolean;
  superClass?: string;
}

export interface ImportInfo {
  from:      string;
  symbols:   string[];
  isDynamic: boolean;
  isDefault: boolean;
  line:      number;
}

export interface ExportInfo {
  name: string;
  kind: "function" | "class" | "const" | "let" | "default" | "type" | "re-export";
  line: number;
}

export interface AstRisk {
  kind:     string;
  line:     number;
  severity: "low" | "medium" | "high";
  detail:   string;
}

export interface AstMetrics {
  cyclomaticComplexity: number;
  maxNestingDepth:      number;
  functionCount:        number;
  classCount:           number;
  avgFunctionLines:     number;
  maxFunctionLines:     number;
  callbackDepth:        number;
  commentRatio:         number;
  halsteadVolume:       number;
  linesOfCode:          number;
}

export interface ParseResult {
  root:      AstNode;
  metrics:   AstMetrics;
  functions: FunctionInfo[];
  classes:   ClassInfo[];
  imports:   ImportInfo[];
  exports:   ExportInfo[];
  risks:     AstRisk[];
}

// ── Visitor API ───────────────────────────────────────────────────────────────

export function walkAst(node: AstNode, fn: (n: AstNode, depth: number) => boolean | void): void {
  const walk = (n: AstNode, d: number): void => {
    if (fn(n, d) === false) return;
    for (const child of n.children) walk(child, d + 1);
  };
  walk(node, 0);
}

export function findNodes(root: AstNode, kind: NodeKind): AstNode[] {
  const out: AstNode[] = [];
  walkAst(root, n => { if (n.kind === kind) out.push(n); });
  return out;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

type Lang = "typescript" | "javascript" | "python" | "go" | "unknown";

function toLang(s: string): Lang {
  switch (s.toLowerCase()) {
    case "typescript": case "ts": case "tsx": return "typescript";
    case "javascript": case "js": case "jsx": return "javascript";
    case "python":     case "py":             return "python";
    case "go":         case "golang":         return "go";
    default:                                  return "unknown";
  }
}

function stripped(raw: string): string {
  let out = "";
  let inStr = false;
  let strCh = "";
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    const n = i + 1 < raw.length ? raw[i + 1] : "";
    if (!inStr && c === "/" && n === "/") break;
    if (!inStr && (c === "#") && out.trimStart().length === 0) break;
    if (!inStr && (c === "'" || c === '"' || c === "`")) { inStr = true; strCh = c; continue; }
    if (inStr && c === "\\" && strCh !== "`") { i++; continue; }
    if (inStr && c === strCh) { inStr = false; continue; }
    if (!inStr) out += c;
  }
  return out;
}

function countCh(s: string, ch: string): number {
  let n = 0;
  for (const c of s) if (c === ch) n++;
  return n;
}

function parseParams(raw: string): string[] {
  return raw
    .split(",")
    .map(p => p.trim().replace(/^\.\.\./, "").split(/:|\s*=\s*/)[0].replace(/[?[\]]/g, "").trim())
    .filter(p => p.length > 0 && /^\w+$/.test(p));
}

// ── Cyclomatic complexity for a line range ────────────────────────────────────

function cyclomaticInRange(lines: string[], start: number, end: number): number {
  let cc = 1;
  for (let i = start; i < Math.min(end, lines.length); i++) {
    const s = stripped(lines[i]);
    // Each branching keyword adds 1; logical operators &&/|| each add 1
    const branches = (s.match(/\b(if|else\s+if|for|while|do\b|catch|case\b)\b/g) ?? []).length;
    const logicals  = (s.match(/&&|\|\|/g) ?? []).length;
    // Ternary: count `?` not preceded by another `?` and not followed by another `?`
    const ternary   = (s.match(/[^?]\?[^?:]/g) ?? []).length;
    cc += branches + logicals + ternary;
  }
  return cc;
}

// ── Function parser ───────────────────────────────────────────────────────────

function parseFunctions(lines: string[], lang: Lang): FunctionInfo[] {
  const funcs: FunctionInfo[] = [];

  if (lang === "python") {
    type PyFrame = { indent: number; info: Omit<FunctionInfo, "endLine" | "complexity">; idx: number };
    const stack: PyFrame[] = [];

    for (let i = 0; i < lines.length; i++) {
      const raw   = lines[i];
      const trim  = raw.trimStart();
      if (!trim) continue;
      const indent = raw.length - trim.length;

      // Close frames whose indent >= current (we're back outside them)
      for (let k = stack.length - 1; k >= 0; k--) {
        if (indent <= stack[k].indent && trim && !trim.startsWith("#")) {
          const fr = stack.splice(k, 1)[0];
          funcs[fr.idx] = {
            ...fr.info,
            endLine:    i,
            complexity: cyclomaticInRange(lines, fr.info.line - 1, i),
          };
        }
      }

      const m = trim.match(/^(async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->[^:]+)?\s*:/);
      if (m) {
        const info: Omit<FunctionInfo, "endLine" | "complexity"> = {
          name:       m[2],
          line:       i + 1,
          paramCount: parseParams(m[3]).length,
          isAsync:    !!m[1],
          isExported: !m[2].startsWith("_"),
          isArrow:    false,
          isMethod:   stack.length > 0,
          nestDepth:  stack.length,
        };
        stack.push({ indent, info, idx: funcs.length });
        funcs.push({ ...info, endLine: i + 1, complexity: 1 });
      }
    }
    for (const fr of stack) {
      funcs[fr.idx] = {
        ...fr.info,
        endLine:    lines.length,
        complexity: cyclomaticInRange(lines, fr.info.line - 1, lines.length),
      };
    }
    return funcs;
  }

  // Brace-based languages (JS/TS/Go)
  type BrFrame = { depth: number; startLine: number; info: Omit<FunctionInfo, "endLine" | "complexity">; idx: number };
  const byDepth = new Map<number, BrFrame>();
  let braceDepth = 0;

  for (let i = 0; i < lines.length; i++) {
    const raw  = lines[i];
    const s    = stripped(raw);
    const open = countCh(s, "{");
    const clos = countCh(s, "}");

    let detected: Omit<FunctionInfo, "endLine" | "complexity" | "nestDepth"> | null = null;

    // export async function name(params)
    let m = raw.match(/(export\s+)?(default\s+)?(async\s+)?function\s*\*?\s*(\w+)\s*\(([^)]*)\)/);
    if (m) {
      detected = { name: m[4], paramCount: parseParams(m[5]).length, isAsync: !!m[3], isExported: !!m[1], isArrow: false, isMethod: false, line: i + 1 };
    }

    // const/let/var name = (async?) (params) =>  or  name = async? (params) =>
    if (!detected) {
      m = raw.match(/(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(async\s*)?\(([^)]*)\)\s*(?::\s*[\w<>[\]|,\s]+\s*)?\s*=>/);
      if (m) {
        detected = { name: m[1], paramCount: parseParams(m[3]).length, isAsync: !!m[2], isExported: raw.trim().startsWith("export"), isArrow: true, isMethod: false, line: i + 1 };
      }
    }

    // const name = async param => (single-param shorthand)
    if (!detected) {
      m = raw.match(/(?:const|let|var)\s+(\w+)\s*=\s*(async\s+)(\w+)\s*=>/);
      if (m) {
        detected = { name: m[1], paramCount: 1, isAsync: true, isExported: false, isArrow: true, isMethod: false, line: i + 1 };
      }
    }

    // Go: func (recv?) name(params) or func name(params)
    if (!detected && lang === "go") {
      m = raw.match(/^func(?:\s+\([^)]+\))?\s+(\w+)\s*\(([^)]*)\)/);
      if (m) {
        detected = { name: m[1], paramCount: parseParams(m[2]).length, isAsync: false, isExported: /^[A-Z]/.test(m[1]), isArrow: false, isMethod: false, line: i + 1 };
      }
    }

    // Method: async? name(params) {  — only if already inside a class (braceDepth > 0)
    if (!detected && open > 0) {
      m = raw.match(/^\s+(async\s+)?(\w+)\s*\(([^)]*)\)\s*(?::\s*[\w<>[\]|,\s]+\s*)?\{/);
      if (m) {
        const ban = new Set(["if","for","while","switch","catch","else","do"]);
        if (!ban.has(m[2])) {
          detected = { name: m[2], paramCount: parseParams(m[3]).length, isAsync: !!m[1], isExported: false, isArrow: false, isMethod: true, line: i + 1 };
        }
      }
    }

    if (detected && open > 0) {
      const openDepth = braceDepth + 1;
      const frame: BrFrame = {
        depth: openDepth, startLine: i + 1,
        info: { ...detected, nestDepth: braceDepth },
        idx: funcs.length,
      };
      byDepth.set(openDepth, frame);
      funcs.push({ ...detected, nestDepth: braceDepth, endLine: i + 1, complexity: 1 });
    }

    for (let b = 0; b < open; b++) braceDepth++;
    for (let b = 0; b < clos; b++) {
      if (byDepth.has(braceDepth)) {
        const fr = byDepth.get(braceDepth)!;
        byDepth.delete(braceDepth);
        funcs[fr.idx] = {
          ...fr.info,
          endLine:    i + 1,
          complexity: cyclomaticInRange(lines, fr.info.line - 1, i + 1),
        };
      }
      braceDepth = Math.max(0, braceDepth - 1);
    }
  }

  return funcs;
}

// ── Class parser ──────────────────────────────────────────────────────────────

function parseClasses(lines: string[], lang: Lang, funcs: FunctionInfo[]): ClassInfo[] {
  const classes: ClassInfo[] = [];

  if (lang === "python") {
    type PyClassFrame = { indent: number; info: Omit<ClassInfo, "endLine" | "methods"> };
    const stack: PyClassFrame[] = [];

    for (let i = 0; i < lines.length; i++) {
      const raw  = lines[i];
      const trim = raw.trimStart();
      if (!trim) continue;
      const indent = raw.length - trim.length;

      for (let k = stack.length - 1; k >= 0; k--) {
        if (indent <= stack[k].indent && trim && !trim.startsWith("#")) {
          const fr = stack.splice(k, 1)[0];
          const methods = funcs.filter(f => f.line > fr.info.line && f.line <= i && f.isMethod).map(f => f.name);
          classes.push({ ...fr.info, endLine: i, methods });
        }
      }

      const m = trim.match(/^class\s+(\w+)(?:\(([^)]*)\))?\s*:/);
      if (m) {
        stack.push({ indent, info: { name: m[1], line: i + 1, isExported: !m[1].startsWith("_"), superClass: m[2]?.trim() || undefined } });
      }
    }
    for (const fr of stack) {
      const methods = funcs.filter(f => f.line > fr.info.line && f.isMethod).map(f => f.name);
      classes.push({ ...fr.info, endLine: lines.length, methods });
    }
    return classes;
  }

  // Brace-based
  type BrClassFrame = { depth: number; info: Omit<ClassInfo, "endLine" | "methods"> };
  const stack: BrClassFrame[] = [];
  let braceDepth = 0;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const s   = stripped(raw);
    const open = countCh(s, "{");
    const clos = countCh(s, "}");

    const m = raw.match(/(export\s+)?(abstract\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?/);
    if (m && open > 0) {
      stack.push({ depth: braceDepth + 1, info: { name: m[3], line: i + 1, isExported: !!m[1], superClass: m[4] || undefined } });
    }

    for (let b = 0; b < open; b++) braceDepth++;
    for (let b = 0; b < clos; b++) {
      const idx = stack.findIndex(c => c.depth === braceDepth);
      if (idx >= 0) {
        const fr = stack.splice(idx, 1)[0];
        const methods = funcs.filter(f => f.line > fr.info.line && f.line <= i + 1 && f.isMethod).map(f => f.name);
        classes.push({ ...fr.info, endLine: i + 1, methods });
      }
      braceDepth = Math.max(0, braceDepth - 1);
    }
  }

  return classes;
}

// ── Import parser ─────────────────────────────────────────────────────────────

function parseImports(lines: string[], lang: Lang): ImportInfo[] {
  const imports: ImportInfo[] = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];

    if (lang === "python") {
      // from module import a, b, c
      let m = raw.match(/^from\s+([^\s#]+)\s+import\s+(.+)/);
      if (m) {
        const syms = m[2].replace(/[()]/g, "").split(",")
          .map(s => s.trim().split(/\s+as\s+/)[0].trim()).filter(Boolean);
        imports.push({ from: m[1], symbols: syms, isDynamic: false, isDefault: false, line: i + 1 });
        continue;
      }
      // import module
      m = raw.match(/^import\s+([\w.]+)/);
      if (m) {
        imports.push({ from: m[1], symbols: [m[1]], isDynamic: false, isDefault: true, line: i + 1 });
      }
      continue;
    }

    // ES static: import { a, b } from 'mod'  /  import * as m from 'mod'  /  import m from 'mod'
    let m = raw.match(/^import\s+(?:type\s+)?(?:\*\s+as\s+(\w+)|\{([^}]*)\}|(\w+)(?:\s*,\s*\{([^}]*)\})?)\s+from\s+['"]([^'"]+)['"]/);
    if (m) {
      const syms: string[] = [];
      if (m[1]) syms.push(m[1]);
      if (m[2]) syms.push(...m[2].split(",").map(s => s.trim().split(/\s+as\s+/)[0].trim()).filter(Boolean));
      if (m[3]) syms.push(m[3]);
      if (m[4]) syms.push(...m[4].split(",").map(s => s.trim().split(/\s+as\s+/)[0].trim()).filter(Boolean));
      imports.push({ from: m[5], symbols: syms, isDynamic: false, isDefault: !!m[3], line: i + 1 });
      continue;
    }

    // Dynamic import()
    m = raw.match(/import\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/);
    if (m) { imports.push({ from: m[1], symbols: [], isDynamic: true, isDefault: false, line: i + 1 }); continue; }

    // CommonJS require()
    m = raw.match(/require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/);
    if (m) { imports.push({ from: m[1], symbols: [], isDynamic: false, isDefault: true, line: i + 1 }); }
  }

  return imports;
}

// ── Export parser ─────────────────────────────────────────────────────────────

function parseExports(lines: string[], lang: Lang): ExportInfo[] {
  const out: ExportInfo[] = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();

    if (lang === "python") {
      // __all__ = ['a', 'b']
      const m = raw.match(/__all__\s*=\s*\[([^\]]+)\]/);
      if (m) {
        const names = m[1].match(/['"](\w+)['"]/g) ?? [];
        names.forEach(n => out.push({ name: n.replace(/['"]/g, ""), kind: "const", line: i + 1 }));
      }
      continue;
    }

    if (!raw.startsWith("export")) continue;

    let m = raw.match(/^export\s+(async\s+)?function\s*\*?\s*(\w+)/);
    if (m) { out.push({ name: m[2], kind: "function", line: i + 1 }); continue; }

    m = raw.match(/^export\s+(?:abstract\s+)?class\s+(\w+)/);
    if (m) { out.push({ name: m[1], kind: "class", line: i + 1 }); continue; }

    m = raw.match(/^export\s+(const|let)\s+(\w+)/);
    if (m) { out.push({ name: m[2], kind: m[1] as "const" | "let", line: i + 1 }); continue; }

    m = raw.match(/^export\s+(?:type|interface)\s+(\w+)/);
    if (m) { out.push({ name: m[1], kind: "type", line: i + 1 }); continue; }

    if (raw.match(/^export\s+default\b/)) { out.push({ name: "default", kind: "default", line: i + 1 }); continue; }

    // export { a, b } from 'mod'
    m = raw.match(/^export\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/);
    if (m) {
      m[1].split(",").map(s => s.trim().split(/\s+as\s+/)[0].trim()).filter(Boolean)
        .forEach(n => out.push({ name: n, kind: "re-export", line: i + 1 }));
      continue;
    }

    // export { a, b }
    m = raw.match(/^export\s+\{([^}]+)\}/);
    if (m) {
      m[1].split(",").map(s => s.trim().split(/\s+as\s+/)[0].trim()).filter(Boolean)
        .forEach(n => out.push({ name: n, kind: "const", line: i + 1 }));
    }
  }

  return out;
}

// ── AST risk patterns ─────────────────────────────────────────────────────────

const HIGH_RISKS: Array<[RegExp, string, string]> = [
  [/\beval\s*\(/,                       "eval-usage",           "eval() executes arbitrary code strings"],
  [/new\s+Function\s*\(/,               "new-function",         "new Function() executes a string as code"],
  [/document\.write\s*\(/,              "document-write",       "document.write() enables XSS injection"],
  [/__proto__\s*=|Object\.setPrototypeOf/, "prototype-pollution", "Direct prototype chain manipulation"],
  [/dangerouslySetInnerHTML/,            "unsafe-inner-html",    "React XSS vector via dangerouslySetInnerHTML"],
  [/child_process|execSync\s*\(|spawn\s*\(/, "command-exec",    "Command execution sink detected"],
];

const MED_RISKS: Array<[RegExp, string, string]> = [
  [/require\s*\(\s*(?!['"`])[^)]+\)/,   "dynamic-require",      "Dynamic require() with runtime argument"],
  [/innerHTML\s*=|outerHTML\s*=/,        "inner-html-write",     "innerHTML mutation — potential XSS"],
  [/Math\.random\s*\(\)/,                "weak-random",          "Math.random() is not cryptographically secure"],
  [/(?:createHash|hash)\s*\(\s*['"](?:md5|sha1)['"]/i, "weak-hash", "Weak hash algorithm (MD5/SHA1)"],
  [/http:\/\/(?!localhost|127\.)/,       "plaintext-http",       "Non-TLS HTTP endpoint in code"],
  [/0\.0\.0\.0/,                         "bind-all-interfaces",  "Binding server to all network interfaces"],
  [/TODO.*(?:security|auth|crypto|vuln|fix)/i, "security-todo", "Unresolved security-related TODO"],
  [/os\.system\s*\(\s*[^'"]/,            "os-system-dynamic",    "os.system() with dynamic argument"],
];

const LOW_RISKS: Array<[RegExp, string, string]> = [
  [/console\.(log|debug|info)\s*\(/,    "debug-log",            "Debug logging left in source"],
  [/\bdebugger\b/,                       "debugger-stmt",        "Debugger breakpoint in source"],
  [/\/\/\s*@ts-ignore|\/\/\s*eslint-disable/, "suppressed-lint", "Type/lint check suppressed inline"],
  [/process\.exit\s*\(/,                 "process-exit",         "Unconditional process.exit() call"],
];

function detectRisks(lines: string[], _lang: Lang): AstRisk[] {
  const risks: AstRisk[] = [];
  for (let i = 0; i < lines.length; i++) {
    const s = stripped(lines[i]);
    for (const [re, kind, detail] of HIGH_RISKS) {
      if (re.test(s)) risks.push({ kind, line: i + 1, severity: "high", detail });
    }
    for (const [re, kind, detail] of MED_RISKS) {
      if (re.test(s)) risks.push({ kind, line: i + 1, severity: "medium", detail });
    }
    for (const [re, kind, detail] of LOW_RISKS) {
      if (re.test(s)) risks.push({ kind, line: i + 1, severity: "low", detail });
    }
  }
  return risks;
}

// ── Metrics computation ────────────────────────────────────────────────────────

function computeMetrics(lines: string[], funcs: FunctionInfo[], classes: ClassInfo[]): AstMetrics {
  const nonBlank = lines.filter(l => l.trim().length > 0);
  const commentLines = lines.filter(l => {
    const t = l.trim();
    return t.startsWith("//") || t.startsWith("#") || t.startsWith("*") || t.startsWith("/*") || t.startsWith("<!--");
  });

  let maxDepth = 0, curDepth = 0;
  let cbDepth = 0, curCbDepth = 0;
  const cbStack: number[] = [];

  for (const raw of lines) {
    const s = stripped(raw);
    const open = countCh(s, "{");
    const clos = countCh(s, "}");
    for (let j = 0; j < open; j++) {
      curDepth++;
      if (curDepth > maxDepth) maxDepth = curDepth;
      if (s.includes("=>")) {
        curCbDepth++;
        if (curCbDepth > cbDepth) cbDepth = curCbDepth;
        cbStack.push(curDepth);
      }
    }
    for (let j = 0; j < clos; j++) {
      if (cbStack.length > 0 && cbStack[cbStack.length - 1] === curDepth) {
        cbStack.pop();
        curCbDepth = Math.max(0, curCbDepth - 1);
      }
      curDepth = Math.max(0, curDepth - 1);
    }
  }

  const funcLens = funcs.map(f => f.endLine - f.line + 1).filter(l => l > 0);
  const sumCC    = funcs.reduce((s, f) => s + f.complexity, 0);
  const allText  = lines.join(" ");

  const opsMatches = allText.match(/[+\-*/%&|^~<>=!]{1,3}/g) ?? [];
  const opndsMatches = allText.match(/\b[a-zA-Z_]\w*\b/g) ?? [];
  const n1 = new Set(opsMatches).size;
  const n2 = new Set(opndsMatches).size;
  const n = n1 + n2;
  const N = opsMatches.length + opndsMatches.length;
  const halsteadVolume = n > 1 ? Math.round(N * Math.log2(n)) : 0;

  return {
    cyclomaticComplexity: sumCC > 0 ? sumCC : 1,
    maxNestingDepth:      maxDepth,
    functionCount:        funcs.length,
    classCount:           classes.length,
    avgFunctionLines:     funcLens.length ? Math.round(funcLens.reduce((a, b) => a + b, 0) / funcLens.length) : 0,
    maxFunctionLines:     funcLens.length ? Math.max(...funcLens) : 0,
    callbackDepth:        cbDepth,
    commentRatio:         nonBlank.length > 0 ? commentLines.length / nonBlank.length : 0,
    halsteadVolume,
    linesOfCode:          nonBlank.length,
  };
}

// ── AST tree builder ──────────────────────────────────────────────────────────

function buildTree(lines: string[], funcs: FunctionInfo[], classes: ClassInfo[]): AstNode {
  const root: AstNode = {
    kind: "program", text: "", line: 1, endLine: lines.length, depth: 0, children: [],
  };

  for (const cls of classes) {
    const clsNode: AstNode = {
      kind: "class", text: `class ${cls.name}`, line: cls.line, endLine: cls.endLine,
      depth: 0, children: [], name: cls.name, isExport: cls.isExported,
    };
    for (const methodName of cls.methods) {
      const mf = funcs.find(f => f.name === methodName && f.line >= cls.line && f.line <= cls.endLine);
      if (mf) {
        clsNode.children.push({
          kind: "method", text: `${mf.name}()`, line: mf.line, endLine: mf.endLine,
          depth: 1, children: [], name: mf.name, isAsync: mf.isAsync,
          params: mf.paramCount > 0 ? [`${mf.paramCount} params`] : [],
        });
      }
    }
    root.children.push(clsNode);
  }

  for (const fn of funcs.filter(f => !f.isMethod)) {
    root.children.push({
      kind:    fn.isArrow ? "arrow" : "function",
      text:    `${fn.name}()`,
      line:    fn.line,
      endLine: fn.endLine,
      depth:   fn.nestDepth,
      children: [],
      name:    fn.name,
      isAsync: fn.isAsync,
      isExport: fn.isExported,
      params: fn.paramCount > 0 ? [`${fn.paramCount} params`] : [],
    });
  }

  return root;
}

// ── Main exports ──────────────────────────────────────────────────────────────

export function parseAst(content: string, lang: string): ParseResult {
  const lines   = content.split("\n");
  const l       = toLang(lang);
  const funcs   = parseFunctions(lines, l);
  const classes = parseClasses(lines, l, funcs);
  const imports = parseImports(lines, l);
  const exports = parseExports(lines, l);
  const risks   = detectRisks(lines, l);
  const metrics = computeMetrics(lines, funcs, classes);
  const root    = buildTree(lines, funcs, classes);
  return { root, metrics, functions: funcs, classes, imports, exports, risks };
}

/** Standalone cyclomatic complexity estimate — fast path for a single file. */
export function computeCyclomaticComplexity(content: string): number {
  return cyclomaticInRange(content.split("\n"), 0, content.split("\n").length);
}
