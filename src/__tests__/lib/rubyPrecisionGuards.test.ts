/**
 * @jest-environment node
 *
 * Ruby engine coverage found scoring the 0llino sast-benchmark Ruby suite and checked against railsgoat: Rack-style
 * request objects as sources, response factories and Rack `'Location' =>` headers as sinks, LDAP filters, the
 * weak-crypto rules, and guards ported from the other engines (resolved-path prefixes, anchored regexes, allowlisted
 * parsed hosts kept through variable resolution, a bare `raise` ending the path).
 */
import { analyzeFile } from "@/lib/scanner";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";

beforeAll(async () => { await warmRubyTaintEngine(); }, 120000);

const handler = (body: string, param = "req", decls = "") => `${decls}\ndef handle(${param})\n${body}\nend\n`;
const ids = (code: string) => analyzeFile("app/handlers/h.rb", code).indicators.map(i => i.id);
const has = (code: string, id: string) => ids(code).includes(id);

describe("sources and sinks", () => {
  it("a handler's req/request parameter (and a Rack::Request) is request input", () => {
    expect(has(handler(`  name = req.param('name')\n  File.read("/data/#{name}")`), "path-traversal")).toBe(true);
    expect(has(handler(`  r = Rack::Request.new(env)\n  File.read("/data/#{r.params['f']}")`, "env"), "path-traversal")).toBe(true);
    // any other parameter name, or a req local bound to something else, is not
    expect(has(handler(`  name = opts.param('name')\n  File.read("/data/#{name}")`, "opts"), "path-traversal")).toBe(false);
    expect(has(handler(`  req = Config.new\n  File.read("/data/#{req.param('f')}")`, "x"), "path-traversal")).toBe(false);
    // a req parameter rebound to something else, or a bare `req` that is neither a parameter nor a local
    expect(has(handler(`  req = Config.new\n  File.read("/data/#{req.param('f')}")`), "path-traversal")).toBe(false);
    expect(has(handler(`  File.read("/data/#{req.param('f')}")`, "x"), "path-traversal")).toBe(false);
  });

  it("Response.html is an HTML body; Response.redirect and a Rack Location header are redirects", () => {
    expect(has(handler(`  n = req.param('n')\n  BenchmarkResponse.html("<p>#{n}</p>")`), "xss")).toBe(true);
    expect(has(handler(`  n = req.param('n')\n  BenchmarkResponse.html("<p>#{ERB::Util.html_escape(n)}</p>")`), "xss")).toBe(false);
    expect(has(handler(`  BenchmarkResponse.redirect(req.param('next'))`), "open-redirect")).toBe(true);
    // .html / .redirect on something that isn't a response
    expect(has(handler(`  n = req.param('n')\n  Formatter.html("<p>#{n}</p>")`), "xss")).toBe(false);
    expect(has(handler(`  [302, { 'Location' => req.param('url') }, ['']]`), "open-redirect")).toBe(true);
    expect(has(handler(`  url = req.param('u')\n  BenchmarkResponse.new(302, '', { 'Location' => url })`), "open-redirect")).toBe(true);
    // a fixed host, or a non-Location header, is not a redirect
    expect(has(handler(`  [302, { 'Location' => "https://app.example.com/#{req.param('p')}" }, ['']]`), "open-redirect")).toBe(false);
    expect(has(handler(`  [200, { 'X-Trace' => req.param('t') }, ['']]`), "open-redirect")).toBe(false);
  });

  it("an LDAP filter built from input; Filter.escape neutralizes it", () => {
    expect(has(handler(`  g = req.param('g')\n  ldap = Net::LDAP.new(host: 'h')\n  ldap.search(filter: "(&(cn=#{g})(objectClass=group))")`), "ldap-injection")).toBe(true);
    expect(has(handler(`  g = Net::LDAP::Filter.escape(req.param('g'))\n  ldap = Net::LDAP.new(host: 'h')\n  ldap.search(filter: "(cn=#{g})")`), "ldap-injection")).toBe(false);
    expect(has(handler(`  f = Net::LDAP::Filter.construct(req.param('f'))`), "ldap-injection")).toBe(true);
  });
});

describe("weak crypto", () => {
  const crypto = (line: string) => analyzeFile("app/c.rb", `def f(data, password)\n  ${line}\nend\n`).indicators.filter(i => i.id === "weak-crypto").length;
  it("MD5/SHA-1 digests, fast password digests, ECB/DES/RC4/Blowfish ciphers", () => {
    expect(crypto(`Digest::MD5.hexdigest(data)`)).toBe(1);
    expect(crypto(`OpenSSL::Digest.new('SHA1').hexdigest(data)`)).toBe(1);
    expect(crypto(`Digest::SHA256.hexdigest(password)`)).toBe(1);
    expect(crypto(`OpenSSL::Cipher.new('AES-128-ECB')`)).toBe(1);
    expect(crypto(`OpenSSL::Cipher.new('DES-EDE3-CBC')`)).toBe(1);
    expect(crypto(`OpenSSL::Cipher.new('RC4')`)).toBe(1);
  });
  it("SHA-256 of data, AES-GCM/CBC and bcrypt are fine", () => {
    expect(crypto(`Digest::SHA256.hexdigest(data)`)).toBe(0);
    expect(crypto(`OpenSSL::Cipher.new('AES-256-GCM')`)).toBe(0);
    expect(crypto(`OpenSSL::Cipher.new('AES-256-CBC')`)).toBe(0);
    expect(crypto(`BCrypt::Password.create(password)`)).toBe(0);
  });
});

describe("guards", () => {
  it("start_with?(base) on a resolved path confines it", () => {
    const body = (resolve: string) => handler(`  base = '/data/reports'\n  resolved = ${resolve}\n  return BenchmarkResponse.bad_request('no') unless resolved.start_with?(base + '/')\n  File.read(resolved)`);
    expect(has(body(`File.expand_path(req.param('p'), base)`), "path-traversal")).toBe(false);
    expect(has(body(`Pathname.new(File.join(base, req.param('p'))).cleanpath.to_s`), "path-traversal")).toBe(false);
    expect(has(body(`File.join(base, req.param('p'))`), "path-traversal")).toBe(true);
  });

  it("a bare `raise unless` ends the rejected path", () => {
    const decls = `ALLOWED = %w[report.pdf invoice.pdf].freeze`;
    expect(has(handler(`  f = req.param('f')\n  raise unless ALLOWED.include?(f)\n  File.read(File.join('/app/files', f))`, "req", decls), "path-traversal")).toBe(false);
    expect(has(handler(`  f = req.param('f')\n  warn unless ALLOWED.include?(f)\n  File.read(File.join('/app/files', f))`, "req", decls), "path-traversal")).toBe(true);
  });

  it("an anchored regex validates (=~ and match?)", () => {
    const body = (check: string) => handler(`  f = req.param('f')\n  raise 'bad' unless ${check}\n  File.read(File.join('/app/files', f))`);
    expect(has(body(`f =~ /\\A[a-z0-9_\\-]+\\.(pdf|csv)\\z/`), "path-traversal")).toBe(false);
    expect(has(body(`f.match?(/\\A[a-z0-9_]+\\z/)`), "path-traversal")).toBe(false);
    expect(has(body(`f =~ /[a-z]+/`), "path-traversal")).toBe(true);
    expect(has(body(`f =~ /\\A[a-z\\/.]+\\z/`), "path-traversal")).toBe(true);
  });

  it("an allowlisted parsed host vets the URI and the URL it came from (also via a host local)", () => {
    const decls = `ALLOWED_HOSTS = %w[api.example.com].freeze`;
    expect(has(handler(`  uri = URI.parse(req.param('url'))\n  raise 'blocked' unless ALLOWED_HOSTS.include?(uri.host)\n  Net::HTTP.get(uri)`, "req", decls), "ssrf")).toBe(false);
    expect(has(handler(`  url = req.param('url')\n  host = URI.parse(url).host rescue nil\n  return BenchmarkResponse.bad_request('no') unless ALLOWED_HOSTS.include?(host)\n  BenchmarkResponse.redirect(url)`, "req", decls), "open-redirect")).toBe(false);
    expect(has(handler(`  uri = URI.parse(req.param('url'))\n  raise 'blocked' unless uri.scheme == 'https'\n  Net::HTTP.get(uri)`, "req", decls), "ssrf")).toBe(true);
  });
});
