/**
 * A small, line-aware reader for configuration files (YAML and JSON) -- enough structure for IaC, container
 * and API-spec checks to scope a rule to ONE container, resource or operation and report the exact line,
 * without a new dependency.
 *
 * YAML: the block subset real manifests use -- nested mappings and sequences (including `- key: value` items),
 * plain/quoted scalars, block scalars (`|`, `>`), simple flow collections (`[a, b]`, `{a: b}`), comments,
 * multiple documents (`---`), CloudFormation short tags (`!Ref x` is read as the scalar "!Ref x"), and Helm
 * templates (a line that is only a `{{ ... }}` directive is skipped; `{{ }}` inside a value stays text).
 * Anchors/aliases and complex keys are not resolved. Never throws: an unreadable file yields no documents.
 */

export type CNode =
  | { kind: "map"; line: number; entries: CEntry[] }
  | { kind: "seq"; line: number; items: CNode[] }
  | { kind: "scalar"; line: number; value: string; quoted: boolean };

export interface CEntry { key: string; line: number; node: CNode }

interface Line { indent: number; text: string; no: number }

const EMPTY_SCALAR = (line: number): CNode => ({ kind: "scalar", line, value: "", quoted: false });

/** Remove a trailing `# comment` that is outside quotes. */
function stripComment(s: string): string {
  let q: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === q && s[i - 1] !== "\\") q = null; continue; }
    if (c === '"' || c === "'") { if (i === 0 || /[\s:[{,-]/.test(s[i - 1])) q = c; continue; }
    if (c === "#" && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i).trimEnd();
  }
  return s.trimEnd();
}

function unquote(raw: string): { value: string; quoted: boolean } {
  const t = raw.trim();
  if (t.length >= 2 && ((t[0] === '"' && t.endsWith('"')) || (t[0] === "'" && t.endsWith("'")))) {
    return { value: t.slice(1, -1).replace(t[0] === "'" ? /''/g : /\\"/g, t[0]), quoted: true };
  }
  return { value: t, quoted: false };
}

/** Split `key: rest` at the first mapping colon outside quotes/brackets; null when the text is not a pair. */
function splitPair(text: string): { key: string; rest: string } | null {
  let q: string | null = null;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === q) q = null; continue; }
    if ((c === '"' || c === "'") && i === 0) { q = c; continue; }
    if (c === "[" || c === "{") depth++;
    else if (c === "]" || c === "}") depth--;
    else if (c === ":" && depth === 0 && (i === text.length - 1 || text[i + 1] === " " || text[i + 1] === "\t")) {
      const key = unquote(text.slice(0, i)).value;
      if (!key || /\s{2,}/.test(key)) return null;
      return { key, rest: text.slice(i + 1).trim() };
    }
  }
  return null;
}

/** A flow collection or scalar on one line. */
function parseFlow(src: string, line: number): CNode {
  let i = 0;
  const ws = () => { while (i < src.length && /\s/.test(src[i])) i++; };
  const value = (): CNode => {
    ws();
    if (src[i] === "[") {
      i++;
      const items: CNode[] = [];
      for (;;) {
        ws();
        if (i >= src.length) break;
        if (src[i] === "]") { i++; break; }
        items.push(value());
        ws();
        if (src[i] === ",") i++;
      }
      return { kind: "seq", line, items };
    }
    if (src[i] === "{") {
      i++;
      const entries: CEntry[] = [];
      for (;;) {
        ws();
        if (i >= src.length) break;
        if (src[i] === "}") { i++; break; }
        const k = atom(":,}");
        ws();
        let node: CNode = EMPTY_SCALAR(line);
        if (src[i] === ":") { i++; node = value(); }
        entries.push({ key: unquote(k).value, line, node });
        ws();
        if (src[i] === ",") i++;
      }
      return { kind: "map", line, entries };
    }
    const a = unquote(atom(",]}"));
    return { kind: "scalar", line, value: a.value, quoted: a.quoted };
  };
  const atom = (stops: string): string => {
    ws();
    const start = i;
    if (src[i] === '"' || src[i] === "'") {
      const q = src[i++];
      while (i < src.length && src[i] !== q) i++;
      i++;
      return src.slice(start, i);
    }
    while (i < src.length && !stops.includes(src[i])) i++;
    return src.slice(start, i).trim();
  };
  const t = src.trim();
  if ((t.startsWith("[") || t.startsWith("{")) && !t.startsWith("{{")) {
    try { return value(); } catch { /* fall through to a plain scalar */ }
  }
  const u = unquote(t);
  return { kind: "scalar", line, value: u.value, quoted: u.quoted };
}

class YamlReader {
  private i = 0;
  constructor(private readonly lines: Line[]) {}

  parseDocument(): CNode | null {
    if (this.i >= this.lines.length) return null;
    return this.block(this.lines[this.i].indent);
  }

  private block(indent: number): CNode {
    const first = this.lines[this.i];
    if (this.isSeqItem(first.text)) return this.seq(first.indent);
    return this.map(indent);
  }

  private isSeqItem(text: string): boolean { return text === "-" || text.startsWith("- "); }

  private map(indent: number): CNode {
    const start = this.lines[this.i];
    const entries: CEntry[] = [];
    while (this.i < this.lines.length) {
      const ln = this.lines[this.i];
      if (ln.indent < indent || (ln.indent === indent && this.isSeqItem(ln.text))) break;
      if (ln.indent > indent) { this.i++; continue; }   // stray over-indented line: skip, don't loop
      const pair = splitPair(ln.text);
      if (!pair) {
        // A bare scalar where a mapping was expected (a lone document scalar): treat as the value.
        if (entries.length === 0) { this.i++; return parseFlow(ln.text, ln.no); }
        this.i++;
        continue;
      }
      this.i++;
      entries.push({ key: pair.key, line: ln.no, node: this.valueAfterKey(pair.rest, ln, indent) });
    }
    return { kind: "map", line: start.no, entries };
  }

  private valueAfterKey(rest: string, ln: Line, indent: number): CNode {
    if (/^[|>][+-]?\d*$/.test(rest)) return this.blockScalar(ln, indent);
    if (rest && !/^&\S+$/.test(rest) && !/^!\S+$/.test(rest)) return parseFlow(rest, ln.no);
    // Nested block: deeper indentation, or a sequence at the same indentation (`key:\n- a`).
    const next = this.lines[this.i];
    if (next && (next.indent > indent || (next.indent === indent && this.isSeqItem(next.text)))) {
      return next.indent === indent ? this.seq(indent) : this.block(next.indent);
    }
    return EMPTY_SCALAR(ln.no);
  }

  private blockScalar(ln: Line, indent: number): CNode {
    const parts: string[] = [];
    while (this.i < this.lines.length && this.lines[this.i].indent > indent) parts.push(this.lines[this.i++].text);
    return { kind: "scalar", line: ln.no, value: parts.join("\n"), quoted: true };
  }

  private seq(indent: number): CNode {
    const start = this.lines[this.i];
    const items: CNode[] = [];
    while (this.i < this.lines.length) {
      const ln = this.lines[this.i];
      if (ln.indent !== indent || !this.isSeqItem(ln.text)) {
        if (ln.indent > indent) { this.i++; continue; }
        break;
      }
      const content = ln.text === "-" ? "" : ln.text.slice(2).trimStart();
      if (!content) {
        this.i++;
        const next = this.lines[this.i];
        items.push(next && next.indent > indent ? this.block(next.indent) : EMPTY_SCALAR(ln.no));
        continue;
      }
      const col = indent + (ln.text.length - content.length);
      if (this.isSeqItem(content) || (splitPair(content) && !content.startsWith("[") && !content.startsWith("{"))) {
        // `- key: value` (or `- - x`): the item is a block starting at the content's column.
        this.lines[this.i] = { indent: col, text: content, no: ln.no };
        items.push(this.block(col));
        continue;
      }
      this.i++;
      items.push(parseFlow(content, ln.no));
    }
    return { kind: "seq", line: start.no, items };
  }
}

/** Key of the placeholder entry that stands for a content-producing Helm directive (see parseYamlDocuments). */
export const HELM_TEMPLATE_KEY = "__helm_template__";

/** Is (part of) this node filled in at render time -- a `{{ }}` value or a Helm content directive inside it? */
export function isTemplatedNode(node: CNode | undefined): boolean {
  if (!node) return false;
  if (node.kind === "scalar") return node.value.includes("{{");
  if (node.kind === "map") return node.entries.some(e => e.key === HELM_TEMPLATE_KEY);
  return node.items.some(isTemplatedNode);
}

/** Every YAML document in `content` (empty documents skipped). */
export function parseYamlDocuments(content: string): CNode[] {
  try {
    const docs: Line[][] = [[]];
    const raw = content.replace(/\r\n?/g, "\n").split("\n");
    for (let n = 0; n < raw.length; n++) {
      const line = raw[n];
      if (/^(?:---|\.\.\.)(?:\s|$)/.test(line)) { docs.push([]); continue; }
      if (/^\s*%/.test(line) && docs[docs.length - 1].length === 0) continue;   // %YAML directive
      const body = stripComment(line.replace(/\t/g, "  "));
      const text = body.trim();
      if (!text) continue;
      const indent = body.length - body.trimStart().length;
      if (/^\{\{-?.*-?\}\}$/.test(text)) {
        // Helm: a directive that PRODUCES content (toYaml/include/tpl/a value) stands for keys filled in at
        // render time -- kept as a placeholder entry so checks can tell "absent" from "templated".
        // Control flow (if/with/range/end/define/else) is dropped.
        if (/\b(?:toYaml|include|tpl|template|toJson|\.Values)\b/.test(text) && !/^\{\{-?\s*(?:if|else|end|with|range|define|block)\b/.test(text)) {
          docs[docs.length - 1].push({ indent, text: `${HELM_TEMPLATE_KEY}: ${JSON.stringify(text)}`, no: n + 1 });
        }
        continue;
      }
      docs[docs.length - 1].push({ indent, text, no: n + 1 });
    }
    const out: CNode[] = [];
    for (const lines of docs) {
      if (!lines.length) continue;
      const minIndent = Math.min(...lines.map(l => l.indent));
      const reader = new YamlReader(lines.map(l => ({ ...l, indent: l.indent - minIndent })));
      const doc = reader.parseDocument();
      if (doc) out.push(doc);
    }
    return out;
  } catch {
    return [];
  }
}

/** A JSON document with line numbers, or null when it isn't valid JSON. */
export function parseJsonTree(content: string): CNode | null {
  let i = 0;
  let line = 1;
  const s = content;
  const ws = () => {
    for (; i < s.length; i++) {
      const c = s[i];
      if (c === "\n") line++;
      else if (c !== " " && c !== "\t" && c !== "\r") break;
    }
  };
  const str = (): string => {
    let out = "";
    i++;
    for (; i < s.length; i++) {
      const c = s[i];
      if (c === '"') { i++; return out; }
      if (c === "\\") { const n = s[++i]; out += n === "n" ? "\n" : n === "t" ? "\t" : n === "u" ? String.fromCharCode(parseInt(s.slice(i + 1, i + 5), 16)) : n; if (n === "u") i += 4; continue; }
      if (c === "\n") line++;
      out += c;
    }
    throw new Error("unterminated string");
  };
  const value = (): CNode => {
    ws();
    const at = line;
    const c = s[i];
    if (c === "{") {
      i++;
      const entries: CEntry[] = [];
      ws();
      if (s[i] === "}") { i++; return { kind: "map", line: at, entries }; }
      for (;;) {
        ws();
        if (s[i] !== '"') throw new Error("key expected");
        const keyLine = line;
        const key = str();
        ws();
        if (s[i++] !== ":") throw new Error("colon expected");
        entries.push({ key, line: keyLine, node: value() });
        ws();
        if (s[i] === ",") { i++; continue; }
        if (s[i] === "}") { i++; return { kind: "map", line: at, entries }; }
        throw new Error("bad object");
      }
    }
    if (c === "[") {
      i++;
      const items: CNode[] = [];
      ws();
      if (s[i] === "]") { i++; return { kind: "seq", line: at, items }; }
      for (;;) {
        items.push(value());
        ws();
        if (s[i] === ",") { i++; continue; }
        if (s[i] === "]") { i++; return { kind: "seq", line: at, items }; }
        throw new Error("bad array");
      }
    }
    if (c === '"') return { kind: "scalar", line: at, value: str(), quoted: true };
    const m = /^(?:-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(s.slice(i, i + 64));
    if (!m) throw new Error("bad value");
    i += m[0].length;
    return { kind: "scalar", line: at, value: m[0], quoted: false };
  };
  try {
    const v = value();
    ws();
    return i >= s.length ? v : null;
  } catch {
    return null;
  }
}

/** YAML or JSON by content: a document that starts with `{`/`[` is tried as JSON first. */
export function parseConfigDocuments(content: string): CNode[] {
  const t = content.trimStart();
  if (t.startsWith("{") || t.startsWith("[")) {
    const j = parseJsonTree(content);
    if (j) return [j];
  }
  return parseYamlDocuments(content);
}

// ── Accessors ────────────────────────────────────────────────────────────────

export function get(node: CNode | undefined, key: string): CNode | undefined {
  if (node?.kind !== "map") return undefined;
  for (let k = node.entries.length - 1; k >= 0; k--) if (node.entries[k].key === key) return node.entries[k].node;
  return undefined;
}

/** Case-insensitive key lookup (ARM/CloudFormation property casing varies between authors). */
export function getCI(node: CNode | undefined, key: string): CNode | undefined {
  if (node?.kind !== "map") return undefined;
  const k = key.toLowerCase();
  for (let n = node.entries.length - 1; n >= 0; n--) if (node.entries[n].key.toLowerCase() === k) return node.entries[n].node;
  return undefined;
}

export function entryLine(node: CNode | undefined, key: string): number | undefined {
  if (node?.kind !== "map") return undefined;
  for (let k = node.entries.length - 1; k >= 0; k--) if (node.entries[k].key === key) return node.entries[k].line;
  return undefined;
}

export function path(node: CNode | undefined, ...keys: string[]): CNode | undefined {
  let cur = node;
  for (const k of keys) cur = get(cur, k);
  return cur;
}

export function str(node: CNode | undefined): string | undefined {
  return node?.kind === "scalar" ? node.value : undefined;
}

/** true / false for YAML/JSON booleans (and their quoted forms), undefined otherwise. */
export function bool(node: CNode | undefined): boolean | undefined {
  const v = str(node)?.toLowerCase();
  if (v === "true" || v === "yes" || v === "on") return true;
  if (v === "false" || v === "no" || v === "off") return false;
  return undefined;
}

export function items(node: CNode | undefined): CNode[] {
  return node?.kind === "seq" ? node.items : node ? [node] : [];
}

/** Scalar values of a node that may be a single scalar or a list of them. */
export function strings(node: CNode | undefined): string[] {
  return items(node).flatMap(n => n.kind === "scalar" ? [n.value] : []);
}

export function entries(node: CNode | undefined): CEntry[] {
  return node?.kind === "map" ? node.entries : [];
}

/** Every map node in the tree, depth-first, with its key path. */
export function walkMaps(node: CNode, visit: (map: Extract<CNode, { kind: "map" }>, keyPath: string[]) => void, keyPath: string[] = []): void {
  if (node.kind === "map") {
    visit(node, keyPath);
    for (const e of node.entries) walkMaps(e.node, visit, [...keyPath, e.key]);
  } else if (node.kind === "seq") {
    for (const it of node.items) walkMaps(it, visit, keyPath);
  }
}
