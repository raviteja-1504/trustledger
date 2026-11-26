/**
 * @jest-environment node
 *
 * safeFetch: the only way the server calls a URL a customer typed in. Real HTTP servers on 127.0.0.1 stand in for "the
 * remote host" and "the server's own network"; the DNS answer and the address policy are injected, so a name can be
 * made to resolve to anything, once or differently each time.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";
import { safeFetch, OutboundBlockedError, type SafeFetchDeps } from "@/lib/safeFetch";
import { isPrivateAddress } from "@/lib/outboundUrl";

type Hit = { method?: string; url?: string; host?: string; headers: http.IncomingHttpHeaders; body: string };
function startServer(handler: (req: http.IncomingMessage, res: http.ServerResponse, hit: Hit) => void) {
  const hits: Hit[] = [];
  const sockets = new Set<import("node:net").Socket>();
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", c => chunks.push(c));
    req.on("end", () => {
      const hit: Hit = { method: req.method, url: req.url, host: req.headers.host, headers: req.headers, body: Buffer.concat(chunks).toString("utf8") };
      hits.push(hit);
      handler(req, res, hit);
    });
  });
  server.on("connection", s => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  return new Promise<{ port: number; hits: Hit[]; close: () => Promise<void> }>(resolve => {
    server.listen(0, "127.0.0.1", () => resolve({
      port: (server.address() as AddressInfo).port, hits,
      close: () => new Promise(r => { sockets.forEach(s => s.destroy()); server.close(() => r()); }),
    }));
  });
}
const ok = (_req: http.IncomingMessage, res: http.ServerResponse) => { res.writeHead(200, { "Content-Type": "text/plain" }); res.end("fine"); };

/** A resolver that answers from `answers(callNumber)` and counts how often it was asked. */
function resolver(answers: (call: number) => Array<{ address: string; family: number }>) {
  const calls: string[] = [];
  const lookup: NonNullable<SafeFetchDeps["lookup"]> = (hostname, _opts, cb) => { calls.push(hostname); cb(null, answers(calls.length)); };
  return { lookup, calls };
}
const v4 = (address: string) => ({ address, family: 4 });

const servers: Array<{ close: () => Promise<void> }> = [];
const serve = async (h = ok) => { const s = await startServer(h); servers.push(s); return s; };
afterEach(async () => { await Promise.all(servers.splice(0).map(s => s.close())); });

describe("isPrivateAddress", () => {
  it.each([
    "10.0.0.1", "127.0.0.1", "127.255.255.254", "169.254.169.254", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "0.0.0.0",
    "224.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.2.5", "198.51.100.7", "203.0.113.9",
    "::", "::1", "fc00::1", "fd12:3456::1", "fe80::1", "fe80::1%eth0", "FE80::ABCD", "fec0::1", "ff02::1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:7f00:1", "::ffff:a00:1",
    "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "2002:7f00:1::", "2002:a9fe:a9fe::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:db8::1",
    "100::1", "::7f00:1", "not an address", "", "999.1.1.1",
  ])("treats %j as private", ip => expect(isPrivateAddress(ip)).toBe(true));

  it.each([
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1", "198.17.255.255", "198.20.0.1", "192.0.3.1",
    "2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450:4009:81f::200e", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1",
  ])("treats %j as public", ip => expect(isPrivateAddress(ip)).toBe(false));
});

describe("safeFetch: what it refuses, and that nothing is sent", () => {
  it("a private IP literal is refused before any connection", async () => {
    const s = await serve();
    await expect(safeFetch(`http://127.0.0.1:${s.port}/`)).rejects.toMatchObject({ name: "OutboundBlockedError", code: "url_not_allowed" });
    expect(s.hits).toHaveLength(0);
  });

  it.each(["http://localhost:1/", "http://[::1]:1/", "http://169.254.169.254/latest/meta-data/", "ftp://example.com/", "http://user:pw@example.com/", "nonsense"])(
    "%s is refused as a URL", async url => {
      await expect(safeFetch(url)).rejects.toBeInstanceOf(OutboundBlockedError);
    });

  it("a public-looking NAME that resolves to a private address is refused, and the server there sees nothing", async () => {
    const s = await serve();
    const dns = resolver(() => [v4("127.0.0.1")]);                      // the real address policy: loopback is private
    await expect(safeFetch(`http://hooks.example.test:${s.port}/x`, {}, { lookup: dns.lookup })).rejects.toMatchObject({ code: "address_not_allowed" });
    expect(s.hits).toHaveLength(0);
  });

  it("a name with ANY private answer is refused, even when another answer is public (a rebinding service answers both)", async () => {
    const s = await serve();
    const dns = resolver(() => [v4("93.184.216.34"), v4("127.0.0.1")]);
    await expect(safeFetch(`http://mixed.example.test:${s.port}/`, {}, { lookup: dns.lookup })).rejects.toMatchObject({ code: "address_not_allowed" });
    expect(s.hits).toHaveLength(0);
  });

  it("the cloud-metadata address is refused when a name resolves to it", async () => {
    const dns = resolver(() => [v4("169.254.169.254")]);
    await expect(safeFetch("http://metadata.example.test/latest/meta-data/", {}, { lookup: dns.lookup })).rejects.toMatchObject({ code: "address_not_allowed" });
  });

  it("IPv4 hidden in an IPv6 answer is judged by the IPv4 inside", async () => {
    for (const address of ["::ffff:10.0.0.1", "::ffff:7f00:1", "64:ff9b::7f00:1", "2002:a9fe:a9fe::1"]) {
      const dns = resolver(() => [{ address, family: 6 }]);
      await expect(safeFetch("http://v6.example.test/", {}, { lookup: dns.lookup })).rejects.toMatchObject({ code: "address_not_allowed" });
    }
  });

  it("a name that does not resolve, or resolves to nothing, fails cleanly", async () => {
    await expect(safeFetch("http://empty.example.test/", {}, { lookup: resolver(() => []).lookup })).rejects.toMatchObject({ code: "no_address" });
    const failing: NonNullable<SafeFetchDeps["lookup"]> = (_h, _o, cb) => cb(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }), []);
    await expect(safeFetch("http://nx.example.test/", {}, { lookup: failing })).rejects.toThrow(/ENOTFOUND/);
  });
});

describe("safeFetch: DNS rebinding", () => {
  // "Public" and "private" here are the test's own words: 127.0.0.1 (the test server) is declared public, 10.9.9.9 private.
  const isPrivate = (a: string) => a === "10.9.9.9";

  it("resolves the name once and connects to the address it vetted, even if the next answer would be private", async () => {
    const s = await serve();
    const dns = resolver(call => [v4(call === 1 ? "127.0.0.1" : "10.9.9.9")]);     // public at the check, private afterwards
    const res = await safeFetch(`http://rebind.example.test:${s.port}/hook`, { method: "POST", body: "{}" }, { lookup: dns.lookup, isPrivate });
    expect(res.status).toBe(200);
    expect(dns.calls).toEqual(["rebind.example.test"]);                           // exactly one resolution: nothing left to rebind
    expect(s.hits).toHaveLength(1);
  });

  it("an answer that is private at the moment of connecting is refused, whatever it said before", async () => {
    const s = await serve();
    const dns = resolver(call => [v4(call === 1 ? "10.9.9.9" : "127.0.0.1")]);     // the reverse order: private first
    await expect(safeFetch(`http://rebind.example.test:${s.port}/`, {}, { lookup: dns.lookup, isPrivate })).rejects.toMatchObject({ code: "address_not_allowed" });
    expect(s.hits).toHaveLength(0);
  });

  it("every request resolves afresh: a second request to the same name is vetted again, not served from a pooled socket", async () => {
    const s = await serve();
    const dns = resolver(call => [v4(call === 1 ? "127.0.0.1" : "10.9.9.9")]);
    const first = await safeFetch(`http://rebind.example.test:${s.port}/`, {}, { lookup: dns.lookup, isPrivate });
    expect(first.status).toBe(200);
    await expect(safeFetch(`http://rebind.example.test:${s.port}/`, {}, { lookup: dns.lookup, isPrivate })).rejects.toMatchObject({ code: "address_not_allowed" });
    expect(dns.calls).toHaveLength(2);
    expect(s.hits).toHaveLength(1);
  });
});

describe("safeFetch: the request itself", () => {
  const allowAll = { isPrivate: () => false };

  it("sends the method, path, query, headers and body to the vetted address, keeping the original Host", async () => {
    const s = await serve();
    const dns = resolver(() => [v4("127.0.0.1")]);
    const res = await safeFetch(`http://hooks.example.test:${s.port}/a/b?q=1&r=2`, { method: "POST", headers: { "Content-Type": "application/json", "X-TrustLedger-Event": "scan.completed" }, body: '{"n":"é"}' }, { lookup: dns.lookup, ...allowAll });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("fine");
    const hit = s.hits[0];
    expect(hit).toMatchObject({ method: "POST", url: "/a/b?q=1&r=2", host: `hooks.example.test:${s.port}`, body: '{"n":"é"}' });
    expect(hit.headers["x-trustledger-event"]).toBe("scan.completed");
    expect(hit.headers["content-length"]).toBe(String(Buffer.byteLength('{"n":"é"}')));
  });

  it("never follows a redirect: a 302 to the server's own network comes back as a 302, and nothing there is called", async () => {
    const internal = await serve();
    const edge = await serve((_req, res) => { res.writeHead(302, { Location: `http://127.0.0.1:${internal.port}/secret` }); res.end(); });
    const dns = resolver(() => [v4("127.0.0.1")]);
    const res = await safeFetch(`http://hooks.example.test:${edge.port}/x`, { method: "POST", body: "{}" }, { lookup: dns.lookup, ...allowAll });
    expect(res.status).toBe(302);
    expect(res.ok).toBe(false);
    expect(res.headers.get("location")).toBe(`http://127.0.0.1:${internal.port}/secret`);
    expect(internal.hits).toHaveLength(0);
    expect(edge.hits).toHaveLength(1);
    expect(dns.calls).toHaveLength(1);
  });

  it("reports an error status as an ordinary response", async () => {
    const s = await serve((_req, res) => { res.writeHead(503); res.end("down"); });
    const res = await safeFetch(`http://hooks.example.test:${s.port}/`, {}, { lookup: resolver(() => [v4("127.0.0.1")]).lookup, ...allowAll });
    expect(res.status).toBe(503);
    expect(res.ok).toBe(false);
  });

  it("rejects when the server drops the connection halfway through the body", async () => {
    const s = await serve((_req, res) => { res.writeHead(200, { "Content-Length": "1000" }); res.write("partial"); setTimeout(() => res.socket?.destroy(), 20); });
    await expect(safeFetch(`http://drop.example.test:${s.port}/`, { timeoutMs: 3000 }, { lookup: resolver(() => [v4("127.0.0.1")]).lookup, ...allowAll })).rejects.toThrow();
  });

  it("handles a 204 (no body)", async () => {
    const s = await serve((_req, res) => { res.writeHead(204); res.end(); });
    const res = await safeFetch(`http://hooks.example.test:${s.port}/`, { method: "POST", body: "x" }, { lookup: resolver(() => [v4("127.0.0.1")]).lookup, ...allowAll });
    expect(res.status).toBe(204);
    expect(res.ok).toBe(true);
  });

  it("times out when the remote never answers, and does not hang", async () => {
    const s = await serve(() => { /* never respond */ });
    const t0 = Date.now();
    await expect(safeFetch(`http://slow.example.test:${s.port}/`, { timeoutMs: 150 }, { lookup: resolver(() => [v4("127.0.0.1")]).lookup, ...allowAll }))
      .rejects.toMatchObject({ name: "OutboundBlockedError", code: "timeout" });
    expect(Date.now() - t0).toBeLessThan(3000);
  });

  it("rejects, instead of hanging, when the connection stalls halfway through the body", async () => {
    const s = await serve((_req, res) => { res.writeHead(200, { "Content-Length": "1000" }); res.write("partial"); /* then stall */ });
    await expect(safeFetch(`http://stall.example.test:${s.port}/`, { timeoutMs: 200 }, { lookup: resolver(() => [v4("127.0.0.1")]).lookup, ...allowAll })).rejects.toThrow();
  });

  it("reads no more than the cap from a huge response", async () => {
    const big = Buffer.alloc(3 * 1024 * 1024, "a");
    const s = await serve((_req, res) => { res.writeHead(200); res.end(big); });
    const res = await safeFetch(`http://big.example.test:${s.port}/`, { maxResponseBytes: 1000 }, { lookup: resolver(() => [v4("127.0.0.1")]).lookup, ...allowAll });
    expect(res.status).toBe(200);
    expect((await res.text()).length).toBe(1000);
  });

  it("a refused connection is an error, not a hang", async () => {
    const s = await serve(); const port = s.port; await s.close();
    await expect(safeFetch(`http://gone.example.test:${port}/`, { timeoutMs: 2000 }, { lookup: resolver(() => [v4("127.0.0.1")]).lookup, ...allowAll })).rejects.toThrow();
  });
});
