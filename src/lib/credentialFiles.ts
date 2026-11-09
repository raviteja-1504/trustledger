/**
 * Credentials in the file formats that exist to hold them: `.netrc`, `.pgpass`, `.git-credentials`, `.npmrc`,
 * htpasswd / shadow, Rails `master.key`, PuTTY keys, Docker `config.json`, XML `<Password>` elements, password hashes.
 *
 * Here the FORMAT is the evidence, so even a weak-looking value counts (`password pass123` in a .netrc is a credential
 * however short): the generic name=value rules cannot say that, because they have to tell secrets from ordinary text.
 * Pure: lines in, findings out.
 */

export interface FileFormatFinding { line: number; label: string; severity: "critical" | "high" | "medium" }

const base = (p: string) => (p.split(/[\\/]/).pop() ?? p).toLowerCase();

/** A value that is only a reference or a template: the secret, if any, is elsewhere. */
const REFERENCE_RE = /^(?:\$\{|\$\(|\{\{|%\(|<|\$[A-Z_]+$|%[A-Z_]+%$)/;

const SHADOW_HASH_RE = /^[A-Za-z0-9._@-]{1,64}:(?:\$apr1\$|\$2[aby]\$|\$[156y7]\$|\{SHA\}|\{SSHA\})[^:\s]{6,}/;
const BCRYPT_RE = /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/;
const NPM_AUTH_RE = /(?:^|[\s/:])_(?:authToken|auth|password)\s*=\s*([^\s]{8,})/;
const DOCKER_AUTH_RE = /"(?:auth|identitytoken)"\s*:\s*"([A-Za-z0-9+/_-]{12,}={0,2})"/;
const XML_SECRET_RE = /<(Pass|Password|Pwd|Passwd|Secret|ClientSecret|ApiKey|Token|AccessKey)\b[^>]*>([^<]{6,200})<\/\1>/i;
const LOGIN_CALL_RE = /\.(?:login|authenticate|signIn)\s*\(\s*["'][^"']+["']\s*,\s*["']([^"'\s]{6,})["']/;

/** A Docker `auth` value is base64 of `user:password`; anything else is not a credential. */
function decodesToUserPassword(b64: string): boolean {
  try { return /^[^:\s]{1,64}:[^\s]{1,256}$/.test(Buffer.from(b64, "base64").toString("utf8")); } catch { return false; }
}

export function findCredentialFileFormats(lines: readonly string[], filePath: string): FileFormatFinding[] {
  const out: FileFormatFinding[] = [];
  const name = base(filePath);
  const isNetrc = /^[._]?netrc$/.test(name);
  const isPgpass = name === ".pgpass" || name === "pgpass";
  const isGitCredentials = name === ".git-credentials";
  const isNpmrc = name === ".npmrc";
  const isMasterKey = name === "master.key" || name === "credentials.yml.key" || name === ".master_key";
  const isXml = /\.(?:xml|config|plist|csproj|settings)$/.test(name);
  const text = lines.join("\n");
  const ppk = /^PuTTY-User-Key-File-\d+:/m.test(text) && /^Private-Lines:/m.test(text) && /^Encryption:\s*none/m.test(text);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const t = line.trim();
    if (!t) continue;
    const add = (label: string, severity: FileFormatFinding["severity"] = "critical") => out.push({ line: i + 1, label, severity });
    if (ppk && /^PuTTY-User-Key-File-\d+:/.test(t)) { add("Unencrypted PuTTY private key"); continue; }
    if (isNetrc) { const m = /\bpassword\s+(\S+)/.exec(t); if (m && !REFERENCE_RE.test(m[1])) add("Hardcoded password in .netrc"); continue; }
    if (isPgpass) { if (!t.startsWith("#") && /^[^:\s]+:[^:\s]+:[^:\s]+:[^:\s]+:\S+$/.test(t)) add("Hardcoded password in .pgpass"); continue; }
    if (isGitCredentials) { if (/^[A-Za-z][\w+.-]*:\/\/\S+:\S+@\S+/.test(t)) add("Stored Git credentials"); continue; }
    if (isMasterKey) { if (/^[0-9a-f]{32,128}$/i.test(t)) add("Rails master key"); continue; }
    if (isNpmrc) { const m = NPM_AUTH_RE.exec(t); if (m && !REFERENCE_RE.test(m[1])) add("npm auth token in .npmrc"); continue; }
    if (t.startsWith("#") || t.startsWith("//")) continue;
    if (SHADOW_HASH_RE.test(t)) { add("Password hash (htpasswd / shadow)", "high"); continue; }
    const d = DOCKER_AUTH_RE.exec(t);
    if (d && decodesToUserPassword(d[1])) { add("Docker registry credentials"); continue; }
    if (isXml) { const x = XML_SECRET_RE.exec(t); if (x && !REFERENCE_RE.test(x[2].trim())) { add("Password in XML configuration", "high"); continue; } }
    if (LOGIN_CALL_RE.test(t) && !REFERENCE_RE.test(LOGIN_CALL_RE.exec(t)![1])) { add("Credentials passed to login()", "high"); continue; }
    if (BCRYPT_RE.test(t)) add("bcrypt password hash", "medium");
  }
  return out;
}
