/**
 * What validating a value against a regex character-class alphabet proves, shared by every engine's guard
 * recognition (`re.MatchString(x)`, `Regex::is_match`, `preg_match`) and alphabet sanitizers
 * (`preg_replace('/[^a-z0-9]/', '', $x)`).
 *
 * A value drawn only from an alphabet without injection metacharacters (quotes, `<>`, `;|&$`, backticks,
 * parentheses, braces, whitespace) can't break out of any quoted or concatenated context: every injection class is
 * cleared -- except that an alphabet admitting a literal `-` still lets the value be read as an OPTION by a program
 * (argument injection rides on the CMD class), and one admitting `/` or `\` still lets it name a nested path.
 */
import { INJECTION, SinkClass } from "./taintCore";

/** Characters whose presence in an alphabet means the guard proves nothing (`^` also rejects a negated class, which admits everything else). */
const META_RE = /[<>'"`;|&$(){}\s*?+^]/;
/** What any metacharacter-free alphabet proves. Not EVAL: an identifier-only value is exactly what eval, send and
 * const_get need to reach any method or constant (`Object.const_get("Kernel")`, `obj.send("exit")`). */
const ALPHABET_CLEARS = INJECTION & ~SinkClass.EVAL;

/** Does a character class's body (`a-z0-9_-`) admit a literal `-`, as opposed to only using it for ranges? */
export function classAdmitsDash(cls: string): boolean {
  for (let i = 0; i < cls.length; i++) {
    if (cls[i] === "\\") { if (cls[i + 1] === "-") return true; i++; continue; }
    if (cls[i] !== "-") continue;
    if (i === 0 || i === cls.length - 1) return true;
    // `a-z`: a range operator; `0-9-_`: right after a range, a literal
    if (i >= 2 && cls[i - 2] === "-" && (i < 3 || cls[i - 3] !== "\\")) return true;
  }
  return false;
}

/** The classes a value drawn only from this (non-negated) class body is safe for, or null when it admits metacharacters. */
export function charClassClears(cls: string): number | null {
  // escapes that stand for a set (\s \S \W \D \w \d) are judged by what they admit: only \w and \d are safe
  if (/\\[sSWDpP]/.test(cls)) return null;
  const literal = cls.replace(/\\[wd]/g, "").replace(/\\(.)/g, "$1");
  if (META_RE.test(literal.replace(/-/g, ""))) return null;
  let clears = ALPHABET_CLEARS;
  if (classAdmitsDash(cls)) clears &= ~SinkClass.CMD;
  if (/[/\\]/.test(cls.replace(/\\[wd.\-_]/g, ""))) clears &= ~SinkClass.PATH;
  return clears;
}

/**
 * An anchored pattern built only from character classes, escaped punctuation, word literals and word alternations
 * (`^[a-zA-Z0-9_-]+$`, `^[a-z0-9_-]+\.(jpg|png|pdf)$`): what a full match proves, else null.
 */
export function anchoredPatternClears(pattern: string): number | null {
  const m = /^\^(.*)\$$/.exec(pattern);
  if (!m) return null;
  let rest = m[1];
  let clears = ALPHABET_CLEARS;
  let sawClass = false, sawLiteral = false;
  // `^field_[0-9]+$` / `^get_[a-z]+$`: a literal word first confines every value to that namespace
  const literalPrefix = /^(?:\((?:\?:)?[\w|.-]+\)|[A-Za-z_]\w*)(?![+*?{])/.test(rest);
  const QUANT = /^(?:[+*?]|\{\d+(?:,\d*)?\})/;
  while (rest.length) {
    let t: RegExpExecArray | null;
    if ((t = /^\[((?:\\.|[^\]\\])+)\]/.exec(rest))) {
      const c = charClassClears(t[1]);
      if (c === null) return null;
      clears &= c;
      sawClass = true;
    } else if ((t = /^\\[.\-_@]/.exec(rest))) {
      if (t[0] === "\\-") clears &= ~SinkClass.CMD;
    } else if ((t = /^\\[wd]/.exec(rest))) {
      sawClass = true;
    } else if ((t = /^\((?:\?:)?([\w|.-]+)\)/.exec(rest))) {
      // (jpg|png): literal alternatives
      sawLiteral = true;
    } else if ((t = /^[\w]+/.exec(rest))) {
      // a word literal
      sawLiteral = true;
    } else {
      return null;
    }
    rest = rest.slice(t[0].length);
    const q = QUANT.exec(rest);
    if (q) rest = rest.slice(q[0].length);
  }
  // classes or \w/\d: the alphabet is known. Nothing but literals (`^(dev|staging|prod)$`): the whole set of values is,
  // an allow-list -- safe even to evaluate or reflect on.
  return sawClass ? (literalPrefix ? clears | SinkClass.EVAL : clears) : sawLiteral ? clears | SinkClass.EVAL : null;
}

/**
 * Does a regex body match CR and LF each on its own (`[\r\n]`, `\r|\n`, `(\r\n|\r|\n)+`)? Replacing every match
 * with text free of line breaks then leaves none: the value is one header line / one log entry.
 * `\r\n` alone or `\r?\n` don't qualify -- a bare CR survives them.
 */
export function removesLineBreaks(body: string): boolean {
  let b = body.replace(/[+*]$/, "");
  const grp = /^\((?:\?:)?(.*)\)$/.exec(b);
  if (grp) b = grp[1];
  // every control character: POSIX/Unicode control classes, or a range from \x00 through at least \x1f
  if (/^(?:\[\[:cntrl:\]\]|\\p\{(?:Cntrl|Cc)\}|\[\\p\{(?:Cntrl|Cc)\}\]|\\p\{Cntrl\}|\[\\x00-\\x1[fF](?:\\x7[fF])?\])$/.test(b)) return true;
  const singles = new Set<string>();
  for (const alt of b.split("|")) {
    // a class may also take the other control whitespace (`[\r\n\t]`) and hex/unicode escapes (`[\r\n\x00]`)
    if (/^\[(?:\\[rn0tfv]|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})+\]$/.test(alt)) {
      for (const m of alt.matchAll(/\\([rn0])/g)) singles.add(m[1]);
      for (const m of alt.matchAll(/\\(?:x|u00)(0[aAdD])/g)) singles.add(m[1].toLowerCase() === "0a" ? "n" : "r");
    }
    else if (!/^(?:\\[rn0])+$/.test(alt)) return false;
    else if (alt.length === 2) singles.add(alt[1]);
  }
  return singles.has("r") && singles.has("n");
}

/** A PHP/JS-style delimited pattern literal (`/^[a-z]+$/i`, `#...#`) -> its body, else null. */
export function delimitedPatternBody(text: string): string | null {
  const m = /^(['"])([^\w\s\\])([\s\S]*)\2[imsxuADSUXJ]*\1$/.exec(text.trim());
  return m ? m[3] : null;
}
