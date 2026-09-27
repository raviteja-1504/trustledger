// ── Sink-argument shape: WHERE in a URL the untrusted part lands ──────────────
//
// The taint mask answers "is this value attacker-influenced, and for which sink classes?". For SSRF that is not
// enough, because the same tainted value is a critical vulnerability in one position and harmless in another:
//
//     fetch(userUrl)                              attacker picks the whole target           -> SSRF
//     fetch("https://" + host + "/users")         attacker picks the host                   -> SSRF
//     fetch(`https://api.example.com/users/${id}`) host is a literal; attacker only shapes a
//                                                  path segment on a server the code chose   -> NOT SSRF
//
// The engines used to report all three identically (only the mask was consulted), so the third -- an extremely
// common pattern, every REST client call -- was a steady source of false positives.
//
// The same position question also corrects the OTHER direction. URL-encoding (encodeURIComponent, quote, ...)
// genuinely neutralizes a value placed in a path or query component, but does nothing for a value in the HOST
// position: `169.254.169.254` contains no character that encoding touches, so `"http://" + enc(host)` still lets
// the attacker choose the target. Treating an encoder as clearing SSRF unconditionally made that a false negative.
//
// So a URL argument is decomposed into an ordered list of literal and opaque parts (each engine does this from its
// own AST), and this module decides, position by position, whether an untrusted part can influence the host.
// It is deliberately engine-independent: no AST types, only strings and masks, so it is unit-testable in isolation
// and the JS/TS and Python engines cannot drift apart on the rule.

import { KIND_POSITION_SENSITIVE, SinkClass, wasCleared } from "./taintCore";

export type UrlPart<N> = { kind: "literal"; text: string } | { kind: "opaque"; node: N };

/** Stands in for an untainted, non-literal operand (a config value, a constant): it is opaque, but the code chose it. */
const TRUSTED_OPAQUE = "\u0001";

/**
 * Has the URL's authority (`scheme://user@host:port`) been closed by literal text? True once the text so far contains
 * a `/`, `?` or `#` after the optional scheme and `//` -- from then on nothing appended can change which host is
 * contacted. False for `"https://api.example.com"` (no terminator yet: a following `.evil.com` or `@evil.com` would
 * change the host) and for `"https://"` (the next operand IS the host).
 */
export function hostPinned(textBeforeOperand: string): boolean {
  // Strip the scheme and `//` FIRST, as a separate step. A single regex with the terminator after them backtracks:
  // `[^/?#]*` would swallow `https:` and count the first slash of `//` as the terminator, calling `https://` pinned.
  const prefix = /^(?:[a-z][a-z0-9+.\-]*:)?(?:\/\/)?/i.exec(textBeforeOperand)![0];
  return /[/?#]/.test(textBeforeOperand.slice(prefix.length));
}

/**
 * Is the text so far sitting INSIDE an unterminated authority -- `https://`, `https://api.`, `//`? That is the only
 * place an encoded value can pick the host. Encoded text can't contain `:`, `/`, `?`, `#` or `@`, so with nothing
 * before it (or a path before it) it is just a relative path segment, and `fetch` cannot mistake it for a host.
 */
export function insideOpenAuthority(text: string): boolean {
  return /^(?:[a-z][a-z0-9+.\-]*:)?\/\/[^/?#]*$/i.test(text);
}

export type PositionVerdict =
  | "vulnerable"   // some attacker-influenced operand sits where it can still do damage
  | "safe"         // every attacker-influenced operand sits where its own clearing actually holds
  | "no-taint";    // nothing attacker-influenced at all -- callers fall back to their ordinary logic

export interface SsrfAssessment<N> {
  verdict: PositionVerdict;
  /** For "vulnerable": the operand that can shape the host -- lets a finding name `host`, not the whole template. */
  culprit?: N;
  /** For "vulnerable": the culprit was URL-encoded and only the ENCODING cleared it (so the message can say why that isn't enough). */
  encoded?: boolean;
}

/**
 * Decide an SSRF URL argument, position by position. `maskOf` is the engine's own taint evaluation of one opaque
 * operand (with the env at the sink), so sanitizers, guards and propagation are exactly what the engine already
 * computed -- this only adds the positional question.
 *
 * The two kinds of attacker-influenced operand are judged differently, because they can do different things:
 *   - a plainly TAINTED one can inject anything, including a scheme or a whole other host, so it is safe only after a
 *     literal has closed the authority (`hostPinned`);
 *   - a URL-ENCODED one (kind bit, with the encoding being what cleared it) cannot inject delimiters, so it can only
 *     pick the host where a literal has just opened one and left it unfinished (`insideOpenAuthority`). In a path,
 *     a query, or standing alone it is harmless -- that is exactly what encoding is for.
 * A value cleared by a GUARD (allowlist membership, numeric check) or by coercion carries no kind bit and is safe
 * anywhere.
 */
export function assessSsrfUrl<N>(parts: readonly UrlPart<N>[], maskOf: (node: N) => number): SsrfAssessment<N> {
  let text = "";
  let sawInfluencedButPinned = false;
  for (const part of parts) {
    if (part.kind === "literal") { text += part.text; continue; }
    const m = maskOf(part.node);
    const tainted = (m & SinkClass.SSRF) !== 0;
    const encodedOnly = !tainted && (m & KIND_POSITION_SENSITIVE) !== 0 && wasCleared(m, SinkClass.SSRF);
    if (tainted || encodedOnly) {
      if (tainted ? !hostPinned(text) : insideOpenAuthority(text)) return { verdict: "vulnerable", culprit: part.node, encoded: encodedOnly };
      sawInfluencedButPinned = true;
      text += TRUSTED_OPAQUE;      // attacker-shaped, but it lands where it cannot pick the host; later parts stay safe
    } else {
      text += TRUSTED_OPAQUE;
    }
  }
  return { verdict: sawInfluencedButPinned ? "safe" : "no-taint" };
}

// ── SQL sink-argument shape: is the untrusted part inside a quoted string literal? ────────────

// The same shape question, for a different reason. A string-ESCAPER (mysqli_real_escape_string, addslashes,
// connection.escape) neutralizes exactly the characters that let a value break out of a QUOTED SQL string
// literal -- a real defence there, and no defence at all outside one:
//
//     "SELECT * FROM t WHERE name = '" + escape(name) + "'"    escaper's job: name can't end the literal early   -> safe
//     "SELECT * FROM t WHERE id = " + escape(id)                no quotes to break out of -- escape() only removes
//                                                                 quote/backslash characters, and `1 OR 1=1` has
//                                                                 none -- the value is still arbitrary SQL          -> vulnerable
//     "SELECT * FROM t ORDER BY " + escape(column)               same: an identifier position, no quotes at all   -> vulnerable
//
// Unlike a URL, a plainly TAINTED (unescaped) value is vulnerable in EVERY position here -- a raw value can break
// out of a string literal (`'; DROP TABLE t--`) exactly as easily as it can inject unquoted SQL (`1; DROP TABLE
// t--`), so there is no SQL analogue of hostPinned's "safe once a literal has closed off the position" case for
// tainted operands. Only the ESCAPED case is position-dependent, which is exactly what the shared
// KIND_POSITION_SENSITIVE bit was built to answer.

/**
 * Is the text built so far INSIDE an open, single-quoted SQL string literal? Toggles on every unescaped `'`.
 * A backslash escaping the next character (MySQL, and Postgres with standard_conforming_strings off) skips it
 * so an escaped quote never toggles. SQL's OTHER escape for a literal quote inside one -- doubling it, `''` --
 * needs no special case: two toggles is a no-op by simple parity, the same as skipping the pair outright.
 */
export function insideSqlStringLiteral(textBeforeOperand: string): boolean {
  let inString = false;
  for (let i = 0; i < textBeforeOperand.length; i++) {
    const c = textBeforeOperand[i];
    if (c === "\\" && inString) { i++; continue; }
    if (c === "'") inString = !inString;
  }
  return inString;
}

export interface SqlAssessment<N> {
  verdict: PositionVerdict;
  /** For "vulnerable": the operand that carries the injection. */
  culprit?: N;
  /** For "vulnerable": the culprit was escaped and only the ESCAPING cleared it (so the message can say why that isn't enough here). */
  escaped?: boolean;
}

/**
 * Decide a SQL query argument, position by position. `maskOf` is the engine's own taint evaluation of one opaque
 * operand at the sink. A plainly TAINTED operand is vulnerable in every position (see module docblock above); an
 * ESCAPED one (kind bit, escaping is what cleared it) is vulnerable only OUTSIDE a quoted string literal. A value
 * cleared by a GUARD or a full coercion carries no kind bit and is safe anywhere.
 */
export function assessSqlInjection<N>(parts: readonly UrlPart<N>[], maskOf: (node: N) => number): SqlAssessment<N> {
  let text = "";
  let sawInfluencedButSafe = false;
  for (const part of parts) {
    if (part.kind === "literal") { text += part.text; continue; }
    const m = maskOf(part.node);
    const tainted = (m & SinkClass.SQL) !== 0;
    const escapedOnly = !tainted && (m & KIND_POSITION_SENSITIVE) !== 0 && wasCleared(m, SinkClass.SQL);
    if (tainted) return { verdict: "vulnerable", culprit: part.node, escaped: false };
    if (escapedOnly) {
      if (!insideSqlStringLiteral(text)) return { verdict: "vulnerable", culprit: part.node, escaped: true };
      sawInfluencedButSafe = true;
      text += TRUSTED_OPAQUE;      // an escaped value can't itself contain an unescaped quote, so it can't change whether later text is "inside a literal"
    } else {
      text += TRUSTED_OPAQUE;
    }
  }
  return { verdict: sawInfluencedButSafe ? "safe" : "no-taint" };
}

// ── Argument-injection sink shape: could this array/list element be read as a FLAG? ──────────

// A shell quoting function (shlex.quote, escapeshellarg) makes a value a safe, atomic SHELL token -- it
// says nothing about how the TARGET PROGRAM's own argument parser reads that token once the shell (or no
// shell at all, for an argv-array call like spawn/execFile/subprocess.run(list)) hands it over. A value that
// happens to start with `-`/`--` is still read as a FLAG by the program, not as data -- CWE-88, distinct from
// the shell-metacharacter injection (CWE-78) escaping defends against. This is a real, if less famous, class
// of vulnerability: rsync's `--rsh=<cmd>` runs an arbitrary command as the remote shell, tar's
// `--checkpoint-action=exec=<cmd>` does the same, and many other tools have an option that reaches a shell,
// a file write, or worse.
//
// Escaping never protects here -- correctly-shell-quoted text can still start with `-`. What DOES protect it:
//   - a literal `--` element earlier in the SAME argv array (the POSIX end-of-options marker every well-behaved
//     CLI parser honors: everything after it is a positional argument, never a flag) -- checked by the caller,
//     one array at a time, since it is about SIBLING elements, not this element's own construction;
//   - a non-empty LITERAL prefix within this element's OWN text (`"./" + name`, `"--file=" + name`) -- the
//     result can't start with `-` if something real comes before the attacker-controlled part.
// An opaque-but-UNTAINTED prefix (a config value, a constant) does NOT count: its content is unknown, and
// nothing rules out it being empty at runtime, so a tainted part right after it could still land first.

export interface ArgInjectionAssessment<N> {
  verdict: PositionVerdict;
  /** For "vulnerable": the operand that could be read as a flag by the target program. */
  culprit?: N;
}

/**
 * Decide ONE argv element, in isolation: could the attacker-controlled part of it be the element's first
 * character? `maskOf` is the engine's own taint evaluation at the sink; the CONTROL bit (see taintCore.ts) is
 * "the caller chose this value" -- exactly what matters here, and unlike the injection classes it survives
 * both a numeric coercion and a shell-escape untouched, since neither stops a value from starting with `-`.
 */
export function assessArgumentInjection<N>(parts: readonly UrlPart<N>[], maskOf: (node: N) => number): ArgInjectionAssessment<N> {
  let leadingDashRuledOut = false;
  for (const part of parts) {
    if (part.kind === "literal") {
      if (part.text.length > 0) leadingDashRuledOut = true;
      continue;
    }
    if (leadingDashRuledOut) continue;
    if ((maskOf(part.node) & SinkClass.CONTROL) !== 0) return { verdict: "vulnerable", culprit: part.node };
  }
  return { verdict: "no-taint" };
}
