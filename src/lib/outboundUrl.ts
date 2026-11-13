/**
 * Where the server may send a request on a customer's behalf (a webhook URL, a Slack / Teams alert URL).
 *
 * The URL is typed in by a user, and the server fetches it. Without a check, "https://169.254.169.254/latest/meta-data/",
 * "http://localhost:6379" or "http://10.0.0.5/admin" makes the server call its own network, and the test-webhook endpoint
 * even reports the HTTP status back. Only http(s) to a public-looking host is allowed.
 *
 * This is a HOST-NAME check. It does not resolve DNS, so a public name that points at a private address still passes; closing that
 * needs a resolve-then-connect check (pin the resolved address for the request), which is a separate change.
 */

const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".intranet", ".lan", ".home", ".corp", ".private"];

function ipv4Octets(host: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every(n => n <= 255) ? o : null;
}

function privateIpv4(o: number[]): boolean {
  const [a, b] = o;
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
    || (a === 100 && b >= 64 && b <= 127) || a >= 224;       // 0/8, RFC1918, loopback, link-local (cloud metadata), CGNAT, multicast / reserved
}

function privateIpv6(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "::" || h === "::1") return true;
  if (/^f[cd][0-9a-f]{2}:/.test(h) || /^fe[89ab][0-9a-f]:/.test(h)) return true;     // unique-local fc00::/7, link-local fe80::/10
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h);                            // IPv4-mapped
  if (mapped) { const o = ipv4Octets(mapped[1]); return !o || privateIpv4(o); }
  return /^::ffff:[0-9a-f]+:[0-9a-f]+$/.test(h);                                      // hex-form mapped: treat as private
}

/** True when `raw` is an http(s) URL whose host is not obviously local or private. */
export function isPublicHttpUrl(raw: string): boolean {
  let u: URL;
  try { u = new URL(raw); } catch { return false; }
  if (u.protocol !== "https:" && u.protocol !== "http:") return false;
  if (u.username || u.password) return false;
  let host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!host) return false;
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host.includes(":")) return !privateIpv6(host);
  const octets = ipv4Octets(host);
  if (octets) return !privateIpv4(octets);
  // 0x7f.1, 2130706433, 017700000001: the URL parser normalises these to dotted decimal already; a host whose last label is still a number
  // (no real top-level domain is numeric) is an address in disguise
  if (/(?:^|\.)(?:0x[0-9a-f]+|\d+)$/.test(host)) return false;
  if (host === "localhost" || !host.includes(".")) return false;
  return !BLOCKED_SUFFIXES.some(s => host.endsWith(s));
}
