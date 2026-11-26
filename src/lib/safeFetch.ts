/**
 * The only way the server sends a request to a URL a customer typed in (a webhook, a Slack / Teams alert URL, the
 * audit-checkpoint sink). Server-only: it uses Node's http / https / dns.
 *
 * What it protects against: SSRF into the server's own network (cloud metadata at 169.254.169.254, localhost, private
 * ranges). Checking the URL's host NAME is not enough (outboundUrl.ts isPublicHttpUrl):
 *   - a public name can point at a private address;
 *   - DNS rebinding: a name answers with a public address when it is checked and a private one when fetch() connects a
 *     moment later (a record with TTL 0). Checking and then calling fetch() resolves the name twice, and the second answer
 *     is never checked.
 *
 * How it closes that: the name is resolved ONCE, inside the connection itself (the `lookup` hook of http.request), the
 * answer is judged right there, and the socket connects to exactly the address that was judged. There is no second
 * resolution to attack. A name with ANY private answer is refused (a rebinding service answers with both), as is an IP
 * literal that is private. TLS still validates the certificate against the original host name.
 *
 * Also: redirects are never followed (a 3xx comes back as an ordinary response), every request opens a fresh connection (no
 * pooled socket to an earlier address), there is a timeout, and the response body is read only up to a cap.
 */
import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import net from "node:net";
import { isPrivateAddress, isPublicHttpUrl } from "./outboundUrl";

export class OutboundBlockedError extends Error {
  constructor(readonly code: "url_not_allowed" | "address_not_allowed" | "no_address" | "timeout", message: string) {
    super(message);
    this.name = "OutboundBlockedError";
  }
}

export interface SafeFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  /** Whole-request limit, connection included. Default 10 s. */
  timeoutMs?: number;
  /** The most response body read; beyond it the connection is dropped and the body is cut. Default 1 MiB. */
  maxResponseBytes?: number;
}

/** Test seams: production never passes these. */
export interface SafeFetchDeps {
  lookup?: (hostname: string, options: dns.LookupAllOptions, callback: (err: NodeJS.ErrnoException | null, addresses: dns.LookupAddress[]) => void) => void;
  isPrivate?: (address: string) => boolean;
}

const NO_BODY_STATUS = new Set([101, 204, 205, 304]);

/** The `lookup` option for http.request: resolve, judge every answer, hand back only addresses that passed. */
function vettedLookup(deps: SafeFetchDeps) {
  const resolve = deps.lookup ?? ((h: string, o: dns.LookupAllOptions, cb: (err: NodeJS.ErrnoException | null, a: dns.LookupAddress[]) => void) => dns.lookup(h, o, cb as never));
  const isPrivate = deps.isPrivate ?? isPrivateAddress;
  // net passes either { all: true } (it wants a list) or not (it wants one address); both are answered from the same vetted list
  return (hostname: string, options: dns.LookupOptions, callback: (...args: unknown[]) => void) => {
    resolve(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err);
      const list = addresses ?? [];
      if (list.length === 0) return callback(new OutboundBlockedError("no_address", `${hostname} did not resolve to an address`));
      const bad = list.find(a => isPrivate(a.address));
      if (bad) return callback(new OutboundBlockedError("address_not_allowed", `${hostname} resolves to a private address (${bad.address}), so the request was not sent`));
      if (options.all) return callback(null, list);
      return callback(null, list[0].address, list[0].family);
    });
  };
}

/**
 * fetch() for a URL a customer supplied. Resolves with a standard Response (any status, a redirect included).
 * Rejects with OutboundBlockedError when the URL or the address it resolves to is not allowed, or on timeout / network error.
 */
export function safeFetch(rawUrl: string, init: SafeFetchInit = {}, deps: SafeFetchDeps = {}): Promise<Response> {
  return new Promise<Response>((resolve, reject) => {
    if (!isPublicHttpUrl(rawUrl)) return reject(new OutboundBlockedError("url_not_allowed", "That URL is not allowed: only public http(s) addresses can be called."));
    const url = new URL(rawUrl);
    const host = url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
    const isPrivate = deps.isPrivate ?? isPrivateAddress;
    // an IP literal never reaches the lookup hook, so it is judged here
    if (net.isIP(host) && isPrivate(host)) return reject(new OutboundBlockedError("address_not_allowed", "That address is private, so the request was not sent."));

    const body = init.body == null ? null : Buffer.from(init.body, "utf8");
    const maxBytes = init.maxResponseBytes ?? 1024 * 1024;
    const headers: Record<string, string> = { ...(init.headers ?? {}) };
    if (body) headers["Content-Length"] = String(body.length);

    let settled = false;
    const done = (fn: () => void) => { if (!settled) { settled = true; clearTimeout(timer); fn(); } };
    const lib = url.protocol === "https:" ? https : http;
    const req = lib.request({
      protocol: url.protocol, hostname: host, port: url.port || undefined, path: url.pathname + url.search,
      method: init.method ?? "GET", headers,
      agent: false,                                           // a new connection every time: nothing pooled to an earlier address
      lookup: vettedLookup(deps) as never,
    }, res => {
      const chunks: Buffer[] = [];
      let total = 0;
      const finish = () => done(() => {
        const h = new Headers();
        for (const [k, v] of Object.entries(res.headers)) {
          if (Array.isArray(v)) v.forEach(x => h.append(k, x));
          else if (v != null) h.set(k, v);
        }
        const status = res.statusCode ?? 0;
        try {
          resolve(new Response(NO_BODY_STATUS.has(status) ? null : Buffer.concat(chunks), { status, statusText: res.statusMessage ?? "", headers: h }));
        } catch (e) { reject(e); }
      });
      res.on("data", (c: Buffer) => {
        total += c.length;
        if (total > maxBytes) { chunks.push(c.subarray(0, Math.max(0, c.length - (total - maxBytes)))); res.destroy(); finish(); return; }
        chunks.push(c);
      });
      res.on("end", finish);
      res.on("error", e => done(() => reject(e)));       // also how a connection dropped or timed out mid-body is reported
    });
    const timer = setTimeout(() => { req.destroy(new OutboundBlockedError("timeout", "The request timed out.")); }, init.timeoutMs ?? 10_000);
    req.on("error", e => done(() => reject(e)));
    if (body) req.write(body);
    req.end();
  });
}
