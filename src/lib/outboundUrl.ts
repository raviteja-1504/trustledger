/**
 * Where the server may send a request on a customer's behalf (a webhook URL, a Slack / Teams alert URL).
 *
 * The URL is typed in by a user, and the server fetches it. Without a check, "https://169.254.169.254/latest/meta-data/",
 * "http://localhost:6379" or "http://10.0.0.5/admin" makes the server call its own network, and the test-webhook endpoint
 * even reports the HTTP status back. Only http(s) to a public-looking host is allowed.
 *
 * isPublicHttpUrl() is a HOST-NAME check: it does not resolve DNS, so a public name that points at a private address passes it
 * (and a name that resolves public now can resolve private a moment later: DNS rebinding). The address a request really
 * connects to is checked where the connection is made: lib/safeFetch.ts resolves the name once, refuses it if ANY answer is
 * private (isPrivateAddress below), and connects to exactly that vetted address. Every request to a user-supplied URL must go
 * through safeFetch(), which also never follows a redirect (a public host could answer 302 to a private address).
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

// ── The addresses a name resolves to ──────────────────────────────────────────

/** Address blocks that are never a customer's public server: documentation, benchmarking, IETF protocol assignments, 6to4 relay. */
function reservedIpv4(o: number[]): boolean {
  const [a, b, c] = o;
  return (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113) || (a === 192 && b === 88 && c === 99);
}
const blockedIpv4 = (o: number[]) => privateIpv4(o) || reservedIpv4(o);

/** "2001:db8::1", "::ffff:10.0.0.1", "fe80::1%eth0" as eight 16-bit groups; null when it isn't an IPv6 address. */
function parseIpv6(raw: string): number[] | null {
  let s = raw.toLowerCase();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);                    // an embedded IPv4 tail: ::ffff:10.0.0.1
  if (tail) {
    const o = ipv4Octets(tail[1]);
    if (!o) return null;
    s = s.slice(0, -tail[1].length) + ((o[0] << 8) | o[1]).toString(16) + ":" + ((o[2] << 8) | o[3]).toString(16);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let groups: string[];
  if (halves.length === 1) groups = head;
  else {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...Array<string>(fill).fill("0"), ...rest];
  }
  if (groups.length !== 8) return null;
  const nums = groups.map(g => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  return nums.some(Number.isNaN) ? null : nums;
}

const v4Of = (hi: number, lo: number) => [hi >> 8, hi & 255, lo >> 8, lo & 255];

function blockedIpv6(g: number[]): boolean {
  const zeros = (from: number, to: number) => g.slice(from, to).every(x => x === 0);
  if (zeros(0, 7) && (g[7] === 0 || g[7] === 1)) return true;                       // :: and ::1
  if (zeros(0, 5) && g[5] === 0xffff) return blockedIpv4(v4Of(g[6], g[7]));         // IPv4-mapped ::ffff:a.b.c.d
  if (zeros(0, 6)) return true;                                                     // IPv4-compatible ::a.b.c.d (deprecated)
  if ((g[0] & 0xfe00) === 0xfc00) return true;                                      // unique-local fc00::/7
  if ((g[0] & 0xffc0) === 0xfe80 || (g[0] & 0xffc0) === 0xfec0) return true;        // link-local fe80::/10, site-local fec0::/10
  if ((g[0] & 0xff00) === 0xff00) return true;                                      // multicast
  if (g[0] === 0x64 && g[1] === 0xff9b) return g[2] === 0 && zeros(2, 6) ? blockedIpv4(v4Of(g[6], g[7])) : true;   // NAT64: judge the IPv4 inside
  if (g[0] === 0x2002) return blockedIpv4(v4Of(g[1], g[2]));                        // 6to4: judge the IPv4 inside
  if (g[0] === 0x2001 && g[1] === 0) return true;                                   // Teredo
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true;                              // documentation
  if (g[0] === 0x0100 && zeros(1, 4)) return true;                                  // discard-only 100::/64
  return false;
}

/**
 * True when connecting to this address would reach the server's own network or somewhere reserved. `ip` is an address (what
 * DNS returned), not a name. IPv4 hidden inside an IPv6 form (mapped, NAT64, 6to4) is judged by the IPv4 inside. Anything that
 * isn't a recognisable address counts as blocked.
 */
export function isPrivateAddress(ip: string): boolean {
  const s = ip.trim();
  const v4 = ipv4Octets(s);
  if (v4) return blockedIpv4(v4);
  const v6 = parseIpv6(s);
  return v6 ? blockedIpv6(v6) : true;
}
