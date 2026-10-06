/**
 * Ruby (Rails / Sinatra) taint detection: request input reaching a dangerous call, in Ruby's own syntax.
 *
 * The shared regex detectors catch Ruby only when `params[...]` sits inline in a few call shapes, so a value read
 * into a variable first, a call written without parentheses (`send_file path`), backticks, or Rails-specific
 * sinks went unflagged. This pass is line-based like the other named-taint detectors in scanner.ts and uses the
 * existing finding ids, so Ruby findings are treated like every other language's.
 *
 * Sources: params[...] / params.fetch / params.require, cookies[...], request.params/body/headers/... (inline or
 * through assignments, incl. @instance variables). Propagation: `x = <expression using a tainted value>`,
 * including "#{...}" interpolation. Not taint: .to_i/.to_f/Integer()/Float() conversions and sanitiser calls
 * (Shellwords.escape, File.basename, sanitize_sql, connection.quote, ERB::Util.h).
 * Rails' safe query forms stay clean: hash conditions where(name: x) and placeholders where("a = ?", x).
 * Same accepted imprecision as the rest of the named-taint layer: one taint set per file, no branches.
 */
import type { ScanIndicator } from "@/lib/scanner";

/** Pseudo-names standing for inline request input. */
const INLINE_SOURCES = ["params", "cookies"];
const REQUEST_SOURCE_RE = /\brequest\.(?:params|query_parameters|request_parameters|path_parameters|body|raw_post|headers|referer|referrer|url|original_url|fullpath|query_string|env)\b/;

const SAFE_VALUE_RE = /(?:\.(?:to_i|to_f|to_r|to_c|present\?|blank\?|nil\?|empty\?|size|length|count)\s*$|^(?:Integer|Float|Rational)\s*\(|Shellwords\.(?:escape|shellescape)|\.shellescape\b|File\.basename|sanitize_sql\w*|connection\.quote|ERB::Util\.(?:h|html_escape)|\bCGI\.escape)/;
const ASSIGN_RE = /^\s*(@?[a-z_]\w*)\s*(?:\|\||&&|\+)?=(?![=~>])\s*(.+)$/;

/** Identifiers an expression uses: code outside strings (not symbols or hash keys), plus #{...} inside
 * double-quoted strings, backticks and %x / %Q / %() literals. Inline request input is reported as "params". */
export function rubyReferencedNames(expr: string): string[] {
  const names: string[] = [];
  let code = "";
  const interpolations = (body: string) => {
    for (const m of body.matchAll(/#\{([^}]*)\}/g)) names.push(...rubyReferencedNames(m[1]));
  };
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (ch === "#" && expr[i + 1] !== "{") break;                       // comment
    if (ch === '"' || ch === "`" || ch === "'") {
      let j = i + 1;
      while (j < expr.length && expr[j] !== ch) { if (expr[j] === "\\") j++; j++; }
      if (ch !== "'") interpolations(expr.slice(i + 1, j));
      i = j; code += " "; continue;
    }
    const pct = /^%[xQWI]?([({[<|!])/.exec(expr.slice(i));
    if (pct && (i === 0 || /[\s(,=]/.test(expr[i - 1]))) {
      const open = pct[1], close = ({ "(": ")", "{": "}", "[": "]", "<": ">" } as Record<string, string>)[open] ?? open;
      const j = expr.indexOf(close, i + pct[0].length);
      interpolations(expr.slice(i + pct[0].length, j < 0 ? expr.length : j));
      i = j < 0 ? expr.length : j; code += " "; continue;
    }
    code += ch;
  }
  if (REQUEST_SOURCE_RE.test(code)) names.push("params");
  const cleaned = code
    .replace(/\b[a-z_]\w*:(?!:)/gi, " ")          // hash keys  (name: x)
    .replace(/(?<![:\w]):[a-z_]\w*[?!]?/gi, " ");  // symbols    (:name)
  for (const m of cleaned.matchAll(/@?[A-Za-z_]\w*/g)) names.push(m[0]);
  return names;
}

/** Variables holding request input in this Ruby file (always includes the inline-source pseudo-names). */
export function rubyTaintedNames(lines: string[]): Set<string> {
  const tainted = new Set<string>(INLINE_SOURCES);
  for (const raw of lines) {
    if (/^\s*#/.test(raw)) continue;
    const a = ASSIGN_RE.exec(raw);
    if (!a) continue;
    const [, name, rhs] = a;
    const value = rhs.trim().replace(/\s+(?:if|unless)\s+.*$/, "");
    if (SAFE_VALUE_RE.test(value)) continue;
    if (rubyReferencedNames(value).some(n => tainted.has(n))) tainted.add(name);
  }
  return tainted;
}

/** The argument text of a call whose name ends at `at`: balanced (...) if present, else the rest of the
 * statement (Ruby allows `redirect_to target`), stopping at a trailing `if`/`unless`/`do`. */
function rubyCallArgs(line: string, at: number): string {
  let i = at;
  while (line[i] === " ") i++;
  if (line[i] === "(") {
    let depth = 0;
    for (let j = i; j < line.length; j++) {
      if (line[j] === "(") depth++;
      else if (line[j] === ")") { depth--; if (depth === 0) return line.slice(i + 1, j); }
    }
    return line.slice(i + 1);
  }
  return line.slice(i).replace(/\s+(?:if|unless|do)\b.*$/, "").replace(/\s*\{\s*\|.*$/, "");
}

/** The first top-level argument (commas inside brackets or strings don't split). */
export function rubyFirstArg(args: string): string {
  let depth = 0; let quote = "";
  for (let i = 0; i < args.length; i++) {
    const c = args[i];
    if (quote) { if (c === "\\") i++; else if (c === quote) quote = ""; continue; }
    if (c === '"' || c === "'" || c === "`") quote = c;
    else if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    else if (c === "," && depth === 0) return args.slice(0, i);
  }
  return args;
}

/** The receiver expression right before `.method` at `at` (a string literal or a call chain). */
function receiverBefore(line: string, at: number): string {
  let depth = 0; let quote = "";
  for (let i = at - 1; i >= 0; i--) {
    const c = line[i];
    if (quote) { if (c === quote && line[i - 1] !== "\\") quote = ""; continue; }
    if (c === '"' || c === "'" || c === "`") { quote = c; continue; }
    if (")]}".includes(c)) depth++;
    else if ("([{".includes(c)) { if (depth === 0) return line.slice(i + 1, at); depth--; }
    else if (depth === 0 && /[\s=,]/.test(c) && !/^\s*\./.test(line.slice(i, at))) return line.slice(i + 1, at);
  }
  return line.slice(0, at);
}

interface Sink {
  id: string; label: string; severity: "critical" | "high";
  re: RegExp;
  /** which arguments matter: "first" (bound values follow), "all", or "receiver" (x.method) */
  args: "first" | "all" | "receiver";
  /** SQL: a first argument that is a hash (name: x) or placeholder string is the safe form */
  sql?: boolean;
  detail: (v: string) => string;
}

const SINKS: Sink[] = [
  { id: "sql-injection", label: "SQL Injection", severity: "critical", args: "first", sql: true,
    re: /\.(?:where|not|or|order|reorder|group|having|pluck|joins|from|select|lock|find_by_sql|count_by_sql|exec_query|execute|select_all|select_one|select_value|select_values|select_rows|update_all|delete_all|calculate|maximum|minimum|sum|average)(?=\s*\(|\s+["'@\w])/g,
    detail: () => `Request input is built into SQL — use hash conditions (where(name: x)) or placeholders (where("name = ?", x))` },
  { id: "command-injection", label: "Command Injection", severity: "critical", args: "first",
    re: /(?:(?<![.\w])(?:system|exec|spawn|open)|Process\.spawn|IO\.popen|Kernel\.(?:system|exec|spawn|open)|Open3\.(?:capture2e?|capture3|popen2e?|popen3|pipeline\w*))(?=\s*\(|\s+["'@\w%`])/g,
    detail: () => `Request input reaches a shell command — pass a fixed command as separate arguments and validate the value (Shellwords.escape)` },
  { id: "path-traversal", label: "Path Traversal", severity: "critical", args: "all",
    re: /(?:(?:File|IO)\.(?:read|readlines|binread|write|binwrite|open|new|foreach|delete|unlink|join|expand_path|exist\?|readable\?)|Dir\.(?:glob|entries|children|\[\]|exist\?|mkdir|rmdir)|FileUtils\.\w+|Pathname\.new|Rails\.root\.join|(?<![.\w])send_file)(?=\s*\(|\s+["'@\w])/g,
    detail: () => `Request input is used in a file path — use File.basename or check the resolved path stays inside the intended directory` },
  { id: "ssrf", label: "Server-Side Request Forgery", severity: "critical", args: "first",
    re: /(?:Net::HTTP\.(?:get|get_response|post|post_form|start|new)|URI\.open|(?:HTTParty|Faraday|RestClient|Excon|HTTP|Typhoeus)\.(?:get|post|put|patch|delete|head|new|request)|RestClient::Request\.execute)(?=\s*\(|\s+["'@\w])/g,
    detail: () => `Request input decides where the server sends a request — allow-list hosts or map input to known URLs` },
  { id: "open-redirect", label: "Open Redirect", severity: "high", args: "first",
    re: /(?<![.\w])(?:redirect_to|redirect)(?=\s*\(|\s+["'@\w])/g,
    detail: () => `Request input decides the redirect target — only redirect to relative paths or an allow-list (allow_other_host: false)` },
  { id: "insecure-deserialization", label: "Insecure Deserialization", severity: "critical", args: "first",
    re: /(?:Marshal\.(?:load|restore)|YAML\.(?:load|unsafe_load|load_file)|Psych\.(?:load|unsafe_load)|Oj\.load|JSON\.load)(?=\s*\(|\s+["'@\w])/g,
    detail: () => `Request input is deserialised with a loader that can build arbitrary objects — use JSON.parse or YAML.safe_load` },
  { id: "eval-exec", label: "Unsafe Reflection", severity: "critical", args: "first",
    re: /(?:\.(?:send|public_send|__send__|instance_variable_get|instance_variable_set|method)|(?:Object|Kernel|Module)\.const_get|(?<![.\w])(?:instance_eval|class_eval|module_eval))(?=\s*\(|\s+["'@\w:])/g,
    detail: () => `Request input picks which method/constant runs — map input to an explicit allow-list instead` },
  { id: "eval-exec", label: "Unsafe Reflection", severity: "critical", args: "receiver",
    re: /\.(?:constantize|safe_constantize)\b/g,
    detail: () => `Request input is turned into a class name (constantize) — map input to an explicit allow-list of classes` },
  { id: "xss", label: "Cross-Site Scripting (XSS)", severity: "high", args: "receiver",
    re: /\.html_safe\b/g,
    detail: () => `Request input is marked html_safe and rendered unescaped — leave it escaped or sanitize it first` },
  { id: "xss", label: "Cross-Site Scripting (XSS)", severity: "high", args: "first",
    re: /(?<![.\w])raw(?=\s*\(|\s+["'@\w])/g,
    detail: () => `Request input is rendered unescaped with raw() — leave it escaped or sanitize it first` },
  { id: "ssti", label: "Server-Side Template Injection", severity: "critical", args: "first",
    re: /(?:\binline:|ERB\.new|Liquid::Template\.parse|Haml::Engine\.new|Slim::Template\.new)(?=\s*\(|\s*["'@\w])/g,
    detail: () => `Request input is compiled as a template — render a fixed template and pass the value as a variable` },
];

/** A SQL sink's first argument in one of Rails' safe forms: hash conditions, or a string literal with ?/:name
 * placeholders and no interpolation. */
function safeSqlArg(arg: string): boolean {
  const a = arg.trim();
  if (/^\{|^[a-z_]\w*:\s/i.test(a)) return true;                       // where(name: x) / where({ ... })
  if (/^(['"])(?:(?!\1).)*\1$/.test(a) && !/#\{/.test(a)) return true;  // a plain string literal, nothing interpolated
  return false;
}

const SHELL_INVOCATION_RE = /["'](?:\/bin\/)?(?:sh|bash|zsh)["']\s*,\s*["']-c["']/;

export function findRubyTaintFindings(lines: string[]): ScanIndicator[] {
  const tainted = rubyTaintedNames(lines);
  const isTainted = (expr: string) => rubyReferencedNames(expr).find(n => tainted.has(n));
  const found: ScanIndicator[] = [];
  const seen = new Set<string>();
  const report = (s: Sink, line: number, via: string) => {
    const key = `${s.id}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push({ id: s.id, label: s.label, severity: s.severity, line, detail: s.detail(via) });
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*#/.test(line)) continue;

    // backticks and %x{...}: the whole literal is a shell command
    for (const m of line.matchAll(/`([^`]*)`|%x([({[<|!])/g)) {
      const body = m[1] ?? line.slice((m.index ?? 0) + 3);
      const hit = rubyReferencedNames(`"${body.replace(/"/g, "")}"`).find(n => tainted.has(n));
      if (hit) report(SINKS[1], i + 1, hit);
    }

    for (const sink of SINKS) {
      for (const m of line.matchAll(sink.re)) {
        const end = (m.index ?? 0) + m[0].length;
        let target: string;
        if (sink.args === "receiver") target = receiverBefore(line, m.index ?? 0);
        else {
          const args = rubyCallArgs(line, end);
          const viaShell = sink.id === "command-injection" && SHELL_INVOCATION_RE.test(args);
          target = sink.args === "all" || viaShell ? args : rubyFirstArg(args);
          if (sink.sql && safeSqlArg(target)) continue;
        }
        const hit = isTainted(target);
        if (hit) report(sink, i + 1, hit);
      }
    }
  }
  return found;
}
