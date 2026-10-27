/**
 * Constant evaluation of a C-family expression's SOURCE TEXT (Java, C#, JS-like): literals, arithmetic, comparisons,
 * boolean operators, string concatenation and `"ABC".charAt(n)`, with identifiers resolved through `lookup`.
 * Used to prune the arm of a branch that can never run (`(7 * 18) + num > 200 ? "safe" : param` with
 * `int num = 106`) -- the OWASP Benchmark shape, but also ordinary feature flags and dead debug branches.
 * Returns undefined for anything it can't prove; a caller then keeps both arms, exactly as before.
 */

export type ConstVal = number | string | boolean;

const TOKEN_RE = /\s+|(\d+(?:\.\d+)?)[LlFfDd]?|"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.))'|([A-Za-z_]\w*)|(&&|\|\||[<>=!]=|[-+*/%()<>!.,])/y;

interface Tok { kind: "num" | "str" | "char" | "id" | "op"; text: string; value?: ConstVal; int?: boolean }

function tokenize(src: string): Tok[] | null {
  const out: Tok[] = [];
  TOKEN_RE.lastIndex = 0;
  while (TOKEN_RE.lastIndex < src.length) {
    const at = TOKEN_RE.lastIndex;
    const m = TOKEN_RE.exec(src);
    if (!m || m.index !== at) return null;
    if (m[1] !== undefined) out.push({ kind: "num", text: m[0], value: Number(m[1]), int: !m[1].includes(".") && !/[FfDd]$/.test(m[0]) });
    else if (m[2] !== undefined) out.push({ kind: "str", text: m[0], value: m[2].replace(/\\(.)/g, "$1") });
    else if (m[3] !== undefined) out.push({ kind: "char", text: m[0], value: m[3].replace(/^\\(.)$/, "$1") });
    else if (m[4] !== undefined) out.push({ kind: "id", text: m[4] });
    else if (m[5] !== undefined) out.push({ kind: "op", text: m[5] });
  }
  return out;
}

export function evalConstExpr(src: string, lookup: (name: string) => ConstVal | undefined): ConstVal | undefined {
  const toks = tokenize(src);
  if (!toks || toks.length === 0 || toks.length > 200) return undefined;
  let i = 0;
  const peek = () => toks[i]?.text;
  const fail = Symbol("fail");
  type R = ConstVal | typeof fail;
  const isNum = (v: R): v is number => typeof v === "number";

  const primary = (): R => {
    const t = toks[i++];
    if (!t) return fail;
    let v: R;
    if (t.kind === "num" || t.kind === "str" || t.kind === "char") v = t.value!;
    else if (t.kind === "id") {
      if (t.text === "true") v = true;
      else if (t.text === "false") v = false;
      else { const x = lookup(t.text); v = x === undefined ? fail : x; }
    } else if (t.text === "(") {
      v = or();
      if (toks[i++]?.text !== ")") return fail;
    } else return fail;
    // postfix: .charAt(n) / .length()
    while (v !== fail && peek() === ".") {
      const name = toks[i + 1]?.text;
      if (toks[i + 2]?.text !== "(") return fail;
      i += 3;
      if (name === "length" && toks[i]?.text === ")") { i++; v = typeof v === "string" ? v.length : fail; continue; }
      if (name === "charAt") {
        const idx = or();
        if (toks[i++]?.text !== ")" || typeof v !== "string" || !isNum(idx)) return fail;
        v = idx >= 0 && idx < v.length ? v[idx] : fail;
        continue;
      }
      return fail;
    }
    return v;
  };
  const unary = (): R => {
    if (peek() === "!") { i++; const v = unary(); return typeof v === "boolean" ? !v : fail; }
    if (peek() === "-") { i++; const v = unary(); return isNum(v) ? -v : fail; }
    return primary();
  };
  const mult = (): R => {
    let l = unary();
    while (l !== fail && (peek() === "*" || peek() === "/" || peek() === "%")) {
      const op = toks[i++].text;
      const r = unary();
      if (!isNum(l) || !isNum(r)) return fail;
      if (op === "*") l = l * r;
      else if (r === 0) return fail;
      // integer operands divide like Java/C#: truncated
      else if (op === "/") l = Number.isInteger(l) && Number.isInteger(r) ? Math.trunc(l / r) : l / r;
      else l = l % r;
    }
    return l;
  };
  const add = (): R => {
    let l = mult();
    while (l !== fail && (peek() === "+" || peek() === "-")) {
      const op = toks[i++].text;
      const r = mult();
      if (r === fail) return fail;
      if (op === "+" && (typeof l === "string" || typeof r === "string")) l = String(l) + String(r);
      else if (isNum(l) && isNum(r)) l = op === "+" ? l + r : l - r;
      else return fail;
    }
    return l;
  };
  const rel = (): R => {
    let l = add();
    while (l !== fail && ["<", ">", "<=", ">="].includes(peek() ?? "")) {
      const op = toks[i++].text;
      const r = add();
      if (!isNum(l) || !isNum(r)) return fail;
      l = op === "<" ? l < r : op === ">" ? l > r : op === "<=" ? l <= r : l >= r;
    }
    return l;
  };
  const eq = (): R => {
    let l = rel();
    while (l !== fail && (peek() === "==" || peek() === "!=")) {
      const op = toks[i++].text;
      const r = rel();
      if (r === fail || typeof l !== typeof r) return fail;
      l = op === "==" ? l === r : l !== r;
    }
    return l;
  };
  const and = (): R => {
    let l = eq();
    while (l !== fail && peek() === "&&") {
      i++;
      const r = eq();
      if (typeof l !== "boolean" || typeof r !== "boolean") return fail;
      l = l && r;
    }
    return l;
  };
  const or = (): R => {
    let l = and();
    while (l !== fail && peek() === "||") {
      i++;
      const r = and();
      if (typeof l !== "boolean" || typeof r !== "boolean") return fail;
      l = l || r;
    }
    return l;
  };
  const v = or();
  return v === fail || i !== toks.length ? undefined : v;
}
