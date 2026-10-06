/**
 * Kotlin taint detection: user input reaching a dangerous call, in Kotlin's own syntax.
 *
 * The Java AST engine (astTaintJava.ts) can't parse Kotlin, and the shared regex detectors key on Java idioms
 * (`String x = request.getParameter(...)`), so a Kotlin controller -- input arriving as annotated function
 * parameters, values built with string templates -- went unflagged. This pass is line-based like the other
 * named-taint detectors in scanner.ts and uses the same finding ids, so Kotlin findings are treated exactly
 * like Java's everywhere else (PR page, SARIF, triage, policy).
 *
 * Sources: Spring @RequestParam/@PathVariable/@RequestHeader/@RequestBody/@CookieValue parameters, Ktor
 * call.parameters / call.request.queryParameters / call.receive*, Servlet request.getParameter / getHeader.
 * Propagation: `val/var y = <expression using x>`, including "...$x..." and "${...x...}" templates.
 * Not taint: parameters typed as numbers/booleans/UUIDs/dates, and values converted with toInt()-style calls.
 * Same accepted imprecision as the rest of the named-taint layer: one taint set per file, no branches.
 */
import type { ScanIndicator } from "@/lib/scanner";

const SAFE_TYPES = /^(?:Int|Long|Short|Byte|Double|Float|Boolean|UUID|java\.util\.UUID|LocalDate|LocalDateTime|Instant|BigDecimal|BigInteger)\??$/;
const SAFE_CONVERSION = /\.(?:toInt|toLong|toShort|toByte|toDouble|toFloat|toBoolean|toIntOrNull|toLongOrNull|toDoubleOrNull|toBigDecimal|toBigInteger)\s*\(\s*\)\s*!*\s*$|^UUID\.fromString\s*\(|^(?:Integer|Long)\.(?:parseInt|parseLong|valueOf)\s*\(/;

const SPRING_PARAM_RE = /@(?:RequestParam|PathVariable|RequestHeader|RequestBody|CookieValue)(?:\s*\([^)]*\))?\s+(?:(?:val|var)\s+)?(\w+)\s*:\s*([\w.<>, ?]+?)(?=\s*[,)=]|\s*$)/g;
const KTOR_SOURCE_RE = /\bcall\.(?:parameters|request\.queryParameters|request\.headers|request\.cookies)\s*\[|\bcall\.receive(?:Text|Parameters|Multipart)?\s*(?:<[^>]*>)?\s*\(/;
const SERVLET_SOURCE_RE = /\brequest\.(?:getParameter|getHeader|getQueryString|getPathInfo|getRequestURI)\s*\(/;
const ASSIGN_RE = /^\s*(?:(?:private|internal|public)\s+)?(?:val|var)\s+(\w+)\s*(?::\s*[\w.<>?, ]+)?=\s*(.+)$/;

/** Identifiers an expression uses: code outside string literals, plus $name / ${...} inside them. */
export function referencedNames(expr: string): string[] {
  const names: string[] = [];
  let code = "";
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (ch === '"') {
      // a string literal ("..." or """...""") -- read its templates, skip its text
      const triple = expr.startsWith('"""', i);
      const end = triple ? expr.indexOf('"""', i + 3) : (() => { let j = i + 1; while (j < expr.length && expr[j] !== '"') { if (expr[j] === "\\") j++; j++; } return j; })();
      const body = expr.slice(i + (triple ? 3 : 1), end < 0 ? expr.length : end);
      for (const m of body.matchAll(/\$\{([^}]*)\}|\$([A-Za-z_]\w*)/g)) {
        if (m[2]) names.push(m[2]);
        else for (const n of m[1].matchAll(/\b([A-Za-z_]\w*)\b/g)) names.push(n[1]);
      }
      i = end < 0 ? expr.length : end + (triple ? 2 : 0);
      code += " ";
      continue;
    }
    code += ch;
  }
  for (const n of code.matchAll(/\b([A-Za-z_]\w*)\b/g)) names.push(n[1]);
  return names;
}

/** Variables holding user input in this Kotlin file. */
export function kotlinTaintedNames(lines: string[]): Set<string> {
  const tainted = new Set<string>();
  for (const line of lines) {
    for (const m of line.matchAll(SPRING_PARAM_RE)) {
      if (!SAFE_TYPES.test(m[2].trim())) tainted.add(m[1]);
    }
  }
  // assignments, in order (a later line can build on an earlier one)
  for (const raw of lines) {
    const a = ASSIGN_RE.exec(raw);
    if (!a) continue;
    const [, name, rhs] = a;
    const value = rhs.trim();
    if (SAFE_CONVERSION.test(value)) continue;
    if (KTOR_SOURCE_RE.test(value) || SERVLET_SOURCE_RE.test(value) || referencedNames(value).some(n => tainted.has(n))) tainted.add(name);
  }
  return tainted;
}

/** The text inside the parentheses of the call that starts at `open` (index of "("), balanced. */
function callArgs(line: string, open: number): string {
  let depth = 0;
  for (let i = open; i < line.length; i++) {
    if (line[i] === "(") depth++;
    else if (line[i] === ")") { depth--; if (depth === 0) return line.slice(open + 1, i); }
  }
  return line.slice(open + 1);
}

/** The first top-level argument (commas inside parentheses, brackets and strings don't split). */
export function firstArg(args: string): string {
  let depth = 0, inStr = false;
  for (let i = 0; i < args.length; i++) {
    const c = args[i];
    if (inStr) { if (c === "\\") i++; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true;
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) return args.slice(0, i);
  }
  return args;
}

/** allArgs: every argument is dangerous (File(base, name)); otherwise only the first one is -- later arguments of
 * a query/command/request are bound values, the safe way to pass input (jdbc.query("... = ?", id)). */
interface Sink { id: string; label: string; severity: "critical" | "high"; re: RegExp; allArgs?: boolean; detail: (v: string) => string }

const SINKS: Sink[] = [
  { id: "sql-injection", label: "SQL Injection", severity: "critical",
    re: /\.(?:query|queryForList|queryForObject|queryForMap|queryForRowSet|update|batchUpdate|execute|executeQuery|executeUpdate|prepareStatement|createQuery|createNativeQuery|createStatement|exec)\s*(?=\()/g,
    detail: v => `User input '${v}' is built into a SQL statement — use bind parameters (?, :name) instead of concatenation or string templates` },
  { id: "command-injection", label: "Command Injection", severity: "critical",
    re: /(?:Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec|\bProcessBuilder)\s*(?=\()/g,
    detail: v => `User input '${v}' reaches a shell/process command — pass a fixed command with an argument list and validate the value` },
  { id: "path-traversal", label: "Path Traversal", severity: "critical", allArgs: true,
    re: /(?:\bFile|\bFileInputStream|\bFileOutputStream|\bFileReader|Paths\.get|Path\.of|Files\.(?:readAllBytes|readAllLines|readString|newInputStream|newOutputStream|newBufferedReader|newBufferedWriter|write|writeString|delete|copy|move))\s*(?=\()/g,
    detail: v => `User input '${v}' is used to build a file path — resolve it and check it stays inside the intended base directory` },
  { id: "ssrf", label: "Server-Side Request Forgery", severity: "critical",
    re: /(?:\.(?:getForObject|getForEntity|postForObject|postForEntity|exchange)|\bURL|URI\.create|\.uri|HttpRequest\.newBuilder|\bclient\.(?:get|post|put|delete|request))\s*(?=\()/g,
    detail: v => `User input '${v}' decides where the server sends a request — allow-list hosts or map input to known URLs` },
  { id: "open-redirect", label: "Open Redirect", severity: "high",
    re: /(?:\.sendRedirect|\.respondRedirect|\bRedirectView|\bModelAndView)\s*(?=\()/g,
    detail: v => `User input '${v}' decides the redirect target — only redirect to relative paths or an allow-list` },
];

const COMMENT_RE = /^\s*(?:\/\/|\*|\/\*)/;
const SHELL_INVOCATION_RE = /"(?:\/bin\/)?(?:sh|bash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)"\s*,\s*"(?:-c|\/c|-Command)"/i;

export function findKotlinTaintFindings(lines: string[]): ScanIndicator[] {
  const tainted = kotlinTaintedNames(lines);
  if (tainted.size === 0) return [];
  const found: ScanIndicator[] = [];
  const seen = new Set<string>();
  const report = (s: Pick<Sink, "id" | "label" | "severity">, line: number, detail: string) => {
    const key = `${s.id}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push({ id: s.id, label: s.label, severity: s.severity, line, detail });
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (COMMENT_RE.test(line)) continue;
    for (const sink of SINKS) {
      for (const m of line.matchAll(sink.re)) {
        const open = (m.index ?? 0) + m[0].length;
        const args = callArgs(line, open);
        // ProcessBuilder("sh", "-c", cmd): the shell runs a later argument as a command line.
        const viaShell = sink.id === "command-injection" && SHELL_INVOCATION_RE.test(args);
        const hit = referencedNames(sink.allArgs || viaShell ? args : firstArg(args)).find(n => tainted.has(n));
        if (hit) report(sink, i + 1, sink.detail(hit));
      }
    }
    // Spring MVC: return "redirect:" + next   /   "redirect:$next"
    const redirect = /"redirect:([^"]*)"\s*(?:\+\s*(\w+))?/.exec(line);
    if (redirect) {
      const hit = (redirect[2] && tainted.has(redirect[2]) ? redirect[2] : undefined)
        ?? referencedNames(`"${redirect[1]}"`).find(n => tainted.has(n));
      if (hit) report(SINKS[4], i + 1, SINKS[4].detail(hit));
    }
  }
  return found;
}
