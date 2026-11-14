/**
 * Hardcoded credentials assigned to a name that says what they are: `"consumerSecret": "..."`, `'PASSWORD': '...'`,
 * `MYSQL_ROOT_PASSWORD: ...`, `GANDI_API_KEY=...`.
 *
 * The provider-format patterns in scanner.ts (AKIA..., ghp_..., sk-...) need no context. These do: the NAME is the
 * evidence, so everything depends on telling a credential from the many strings that merely sit beside such a name
 * (`credentials: 'include'`, `password: opts.Password`, `TRANSIP_PRIVATE_KEY_PATH = "transip.key"`, a hash, an OID, a
 * file name, a template, a placeholder). Tuned on CredData (Samsung's manually labelled credential dataset): on its
 * credential lines outside test directories this rule more than doubles what the pattern table alone finds, and adds
 * a handful of false positives per 2,500 labelled non-credentials. See docs/security/secret-detection.md.
 *
 * Pure: takes a line, returns the credential's key name and kind, or null.
 */

/** Names that mark a value as a credential. Matched anywhere in a key (`consumerSecret`, `secret-key`, `MYSQL_ROOT_PASSWORD`). */
const CREDENTIAL_NAMES = "password|passwd|passphrase|pwd|requirepass|masterauth|(?<=[_-])pass(?![A-Za-z])|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|signing[_-]?key|encryption[_-]?key|auth[_-]?key|credential|client[_-]?secret|consumer[_-]?secret|cookie[_-]?validation[_-]?key|hmac";
const NAME_PRESENT_RE = new RegExp(CREDENTIAL_NAMES, "i");
const PASSWORD_LIKE_RE = /pass|pwd|secret|credential/i;

/** A key that ends in one of these holds something ABOUT a credential (its path, id, hash, name, expiry...), not the credential. */
const NOT_A_CREDENTIAL_KEY_RE = /(?:path|file|dir|folder|_?id|name|url|uri|type|length|size|version|ttl|expir\w*|header|prefix|suffix|field|param|hash|digest|checksum|fingerprint|thumbprint|salt|algorithm|alg|format|mode|policy|endpoint|host|port|label|title|description|message|text|usage|period|bits|count|min|max|action|code|blob|identifiers?|issuer)[^A-Za-z0-9]*$/i;

/** Words and shapes that are placeholders, validation text or UI wording rather than a secret. */
const EXTRA_PLACEHOLDER_RE = /\b(?:none|null|undefined|empty|unset|todo|bar)\b|insert|replace|redacted|<[^>]*>|your[-_ ]|\.\.\.|^\*+$|^(.)\1{4,}$/i;
const COMMON_VALUE_RE = /^(?:change[-_]?(?:me|it)\d*|passw0rd\d*|12345678?|01234567890?|0{4,}|1{4,}|abcd\w*|qwerty\w*|password\d*|passwd\d*|letmein\d*|admin\d*|root\d*|secret\d*|token\d*|test\d*|user\d*|username|pass|pwd|true|false|string|boolean|number|object|hidden|required|invalid|default|value|key|apikey|api_key|access_key|include|omit|same-origin|your\w*)$/i;
const ENV_VAR_NAME_RE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;

/** Files where `NAME=value` / `NAME: value` without quotes is how a setting is written. */
const SETTINGS_EXT_RE = /\.(?:env|toml|ya?ml|conf|cfg|ini|properties|sh|bash|zsh|service|tfvars|md|txt|json|rst)$|(?:^|\/)[^./]+$|(?:^|\/)\.[A-Za-z0-9_-]+$|(?:^|\/)\.env[^/]*$/i;

export interface CredentialHit { key: string; value: string; passwordLike: boolean }

export interface CredentialOptions {
  /** Shortest quoted password-like value. */
  minQuotedPassword?: number;
  /** Shortest value for other credential names. */
  minOther?: number;
  /** Shortest unquoted password-like value. */
  minUnquotedPassword?: number;
  /** Shortest all-letters value (a short word is more likely a word than a secret). */
  minAlphabetic?: number;
  /** The scanner's own placeholder wording (demo, sample, example, fake...), so the two cannot drift apart. */
  isPlaceholder?: (value: string) => boolean;
}

/** Is `value` just the name again ("secrets": "secrets", token = "tokens")? A mapping of names to names, not a secret. */
function valueRepeatsName(value: string, keyName: string): boolean {
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
  const v = norm(value), k = norm(keyName.split(/[.\[]/).pop() ?? keyName);
  if (!v || !k) return false;
  return v === k || (Math.abs(v.length - k.length) <= 2 && (v.startsWith(k) || k.startsWith(v)));   // plural / singular
}

/** Whether `value`, assigned to the name `keyName`, can be a credential. */
export function plausibleCredentialValue(value: string, keyName: string, o: CredentialOptions = {}): boolean {
  const minPw = o.minQuotedPassword ?? 6, minOther = o.minOther ?? 8, minAlpha = o.minAlphabetic ?? 7;
  if (NOT_A_CREDENTIAL_KEY_RE.test(keyName) || /__/.test(keyName)) return false;   // a Django lookup is password__startswith
  if (valueRepeatsName(value, keyName)) return false;
  if (value.length < (PASSWORD_LIKE_RE.test(keyName) ? minPw : minOther)) return false;
  if (/\s/.test(value)) return false;
  if (/^(?:anonymous|use-credentials|same-origin|include|omit)$/i.test(value)) return false;   // fetch / CORS credential modes
  // a reference, call, template, path or placeholder syntax: the secret, if any, is elsewhere
  if (/^[$@%<{(\[/~.]|\$\{|\{\{|%\(|\$\(|%s|\)|\(|;$/.test(value)) return false;
  // dotted identifier / OID / indexed lookup (auth.pass, opts.Password, 1.2.840.113549, values[Env])
  if (/^\w+(?:\.\w+)+$/.test(value) && /[A-Za-z]/.test(value) && !/\d{3}/.test(value)) return false;
  if (/^\d+(?:\.\d+)+$/.test(value) || /^\w+\[.*\]$/.test(value)) return false;
  if (/0123456789|1234567890|abcdefghij|9876543210/.test(value)) return false;           // sequences are examples
  if (/^https?:\/\/[^@]*$/i.test(value) || /^(?:file|ftp):/i.test(value)) return false;   // a URL with no password in it
  if (o.isPlaceholder?.(value) || EXTRA_PLACEHOLDER_RE.test(value) || COMMON_VALUE_RE.test(value) || ENV_VAR_NAME_RE.test(value)) return false;
  // an identifier is made of words of 3+ letters (ResetPassword, someVariableName); a random mixed-case run (vhZsvokmid) has pieces that are not words
  if (/^[a-z]{3,}\d*(?:[A-Z]{1,3}[a-z]{2,})+$/.test(value) || /^(?:[A-Z]{1,4}[a-z]{2,}){2,}$/.test(value)) return false;
  if (/^[A-Za-z]+$/.test(value) && value.length < minAlpha) return false;
  if (/^_*[A-Za-z]+(?:[-_]+[A-Za-z]+)+_*$/.test(value)) return false;                      // words joined: base64-encoded, sentinel_specific_pass
  if (/^[A-Za-z_]+\.[a-z]{2,4}$/.test(value)) return false;                                 // a file name: make.bat
  // styling and labels, which sit beside names like "pass" or "secret" in status and category maps:
  if (/^#[0-9a-fA-F]{3,8}$/.test(value)) return false;                                      // a colour: "#dc2626"
  if (/^(?:[a-z]+:)*[a-z]+(?:-[a-z0-9]+)*-\d{1,3}(?:\/\d{1,3})?$/.test(value)) return false; // a CSS utility class: "bg-emerald-500", "text-gray-400"
  if (/^[A-Z][a-z]{3,}$/.test(value)) return false;                                         // a single capitalised word: a label ("Credentials")
  return true;
}

// Bounded runs (`{0,60}`): a long minified line cannot make the key search backtrack badly.
const QUOTED_ASSIGNMENT_RE = new RegExp(`([A-Za-z0-9_.-]{0,60}(?:${CREDENTIAL_NAMES})[A-Za-z0-9_.-]{0,60})["']?\\s*(?::=|=>|=|:)\\s*[bru]?(["'])([^"'\\s]{4,300})\\2`, "i");
const UNQUOTED_ASSIGNMENT_RE = new RegExp(`^\\s*(?:export\\s+|ENV\\s+|-\\s+|set\\s+|setenv\\s+)?([A-Za-z0-9_.-]{0,60}(?:${CREDENTIAL_NAMES})[A-Za-z0-9_.-]{0,60})\\s*[:=]\\s*([^\\s"'#,;{}\\\\]{4,300})(?:\\s+(?:#|;|//).*)?\\s*\\\\?\\s*$`, "i");
// A command line: `mysql --user=root --password=2mPnZ9z5rx`, `--token abc123...`, `--api-key=...`
const CLI_FLAG_RE = /(?:^|\s)--?(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token|requirepass|masterauth)(?:=|\s+)([^\s"'$<>|;&]{6,200})/i;
const MAX_LINE = 2000;

/** The credential assigned on this line, or null. `ext` is the file path (only its ending matters). */
export function findCredentialAssignment(line: string, filePath: string, o: CredentialOptions = {}): CredentialHit | null {
  if (line.length > MAX_LINE || !NAME_PRESENT_RE.test(line)) return null;
  let q = QUOTED_ASSIGNMENT_RE.exec(line);
  // `x === 'use-credentials' ? 'use-credentials' : 'anonymous'`: the `:` of a ternary is not a key/value separator
  if (q && /\?\s*["']?$/.test(line.slice(0, q.index))) q = null;
  // `"API_KEY=" + UUID.randomUUID()`: a literal that only STARTS a value built at runtime is not the secret.
  const concatenated = q ? /^\s*\+/.test(line.slice(q.index + q[0].length)) : false;
  if (q && !concatenated && plausibleCredentialValue(q[3], q[1], o)) return { key: q[1], value: q[3], passwordLike: PASSWORD_LIKE_RE.test(q[1]) };
  if (SETTINGS_EXT_RE.test(filePath)) {
    const c = CLI_FLAG_RE.exec(line);
    if (c && plausibleCredentialValue(c[1], "password", o)) return { key: "command-line flag", value: c[1], passwordLike: true };
    const u = UNQUOTED_ASSIGNMENT_RE.exec(line);
    if (u && plausibleCredentialValue(u[2], u[1], o)) {
      const pw = PASSWORD_LIKE_RE.test(u[1]);
      // unquoted: a password needs 8+ characters; any other name needs a long value mixing letters and digits
      if (pw ? u[2].length >= (o.minUnquotedPassword ?? 8) : (u[2].length >= 16 && /[A-Za-z]/.test(u[2]) && /\d/.test(u[2]))) return { key: u[1], value: u[2], passwordLike: pw };
    }
  }
  return null;
}

// ── A literal that BECOMES a credential by how it is used ─────────────────────────────────────────────────────
// The name-based rule above refuses weak and placeholder-looking values (`password123`, `dev-secret`), because beside a
// documentation example those are not secrets. These three uses are different: the code itself says the literal IS the
// credential, whatever it looks like --
//   process.env.JWT_SECRET ?? "dev-secret"         the fallback every deployment that forgets the variable will run with
//   bcrypt.hash("Password123!", 10)                the password of an account created by the code
//   const DEMO_PASSWORD = "Password123!"           a password constant (a seed script's default account)
// They were the largest group of credentials the RealVuln benchmark labelled and we missed: 100+ cases in 140 repositories.

export interface LiteralCredentialUse { label: string; severity: "high"; detail: string }

const SECRET_ENV_NAME = "\\w*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|CREDENTIAL)\\w*";
const ENV_FALLBACK_JS_RE = new RegExp(String.raw`\bprocess\.env\.(${SECRET_ENV_NAME})\s*(?:\|\||\?\?)\s*(["'\x60])([^"'\x60\n$]{6,200})\2`);
const ENV_FALLBACK_PY_RE = new RegExp(String.raw`\bos\.(?:environ\.get|getenv)\(\s*["'](${SECRET_ENV_NAME})["']\s*,\s*(["'])([^"'\n]{6,200})\2\s*\)|\bos\.environ\.get\(\s*["'](${SECRET_ENV_NAME})["']\s*\)\s*or\s*(["'])([^"'\n]{6,200})\5|\benv(?:\.str)?\(\s*["'](${SECRET_ENV_NAME})["']\s*,\s*default\s*=\s*(["'])([^"'\n]{6,200})\8`);
const PASSWORD_HASH_LITERAL_RE = /\b(?:bcrypt(?:js)?\.hash(?:Sync)?|argon2\.hash|hashPassword|hash_password|generate_password_hash|make_password|encodePassword|passwordEncoder\.encode)\s*\(\s*(["'`])([^"'`\n$]{4,100})\1/;
const PASSWORD_CONSTANT_RE = /^\s*(?:export\s+)?(?:(?:const|let|var)\s+)?(\w*(?:password|passwd|pwd)\w*)\s*(?::\s*[\w.]+\s*)?=\s*(["'])([^"'\n$]{6,100})\2\s*;?\s*(?:\/\/.*|#.*)?$/i;
/** A password-named constant that holds wording, a rule or a field name rather than a password. */
/** Words that make a password-named constant wording, a rule or a field name rather than a password (whole words of the name: "ADMIN" is not "min"). */
const PASSWORD_TEXT_WORDS = new Set(["message", "messages", "error", "errors", "label", "labels", "text", "placeholder", "prompt", "title", "hint", "regex", "pattern", "rule", "rules", "policy", "requirement", "requirements", "min", "max", "minimum", "maximum", "field", "fields", "input", "type", "mode", "status", "msg", "help", "description", "invalid", "required", "mismatch", "header", "param", "params", "selector", "class", "route", "url", "path", "reset", "forgot", "change", "strength", "length", "key"]);
const passwordNameIsText = (name: string) => name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").split(/[^A-Za-z0-9]+/).some(w => PASSWORD_TEXT_WORDS.has(w.toLowerCase()));
const NOT_A_VALUE_RE = /^(?:true|false|none|null|undefined|production|development|staging|prod|dev|test|local|localhost|default|info|debug|warn|error)$/i;

function plausibleLiteral(value: string, o: CredentialOptions): boolean {
  if (/\s/.test(value) || /\$\{|\{\{|%\(|^[$@%<{(\[/~.]|;$/.test(value)) return false;
  if (/^(?:https?|file|ftp):/i.test(value) || NOT_A_VALUE_RE.test(value) || ENV_VAR_NAME_RE.test(value)) return false;
  if (/^(?:\*+|x{4,}|\.{3,})$/i.test(value) || /<[^>]*>|your[-_ ]|insert|replace|redacted/i.test(value)) return false;
  return !o.isPlaceholder?.(value);
}

/** The credential a line hard-codes by how it uses a literal, or null. */
export function findLiteralCredentialUse(line: string, o: CredentialOptions = {}): LiteralCredentialUse | null {
  if (line.length > MAX_LINE) return null;
  const env = ENV_FALLBACK_JS_RE.exec(line) ?? ENV_FALLBACK_PY_RE.exec(line);
  if (env) {
    const name = env[1] ?? env[4] ?? env[7] ?? "", value = env[3] ?? env[6] ?? env[9] ?? "";
    if (name && !NOT_A_CREDENTIAL_KEY_RE.test(name) && plausibleLiteral(value, o)) {
      return { label: "Hardcoded fallback secret", severity: "high",
        detail: `${name} falls back to a literal when the variable is unset, so every deployment that misses the setting runs with this publicly visible value — fail at startup instead of using a default` };
    }
  }
  const hashed = PASSWORD_HASH_LITERAL_RE.exec(line);
  if (hashed && plausibleLiteral(hashed[2], { ...o, isPlaceholder: undefined })) {
    return { label: "Hardcoded password", severity: "high",
      detail: "A literal is hashed as the password of an account the code creates — a default login that ships in the source; generate it at install time or read it from the environment" };
  }
  const c = PASSWORD_CONSTANT_RE.exec(line);
  if (c && !passwordNameIsText(c[1]) && !NOT_A_CREDENTIAL_KEY_RE.test(c[1]) && plausibleLiteral(c[3], { ...o, isPlaceholder: undefined })) {
    return { label: "Hardcoded password", severity: "high", detail: `Password constant "${c[1]}" holds a literal — move it to an environment variable or secrets manager` };
  }
  return null;
}
