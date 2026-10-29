/**
 * @jest-environment node
 *
 * "Relative URLs only" checks found scoring the sast-benchmark redirect cases: partial facts (starts with "/", does
 * not start with "//", has no "://", a parsed URI with no host and no scheme) that prove a same-site destination
 * only in combination -- combineUrlFacets. Each proof has a twin missing one half that must still report.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";
import { warmGoTaintEngine } from "@/lib/astTaintGo";
import { combineUrlFacets, urlPrefixFacets, urlPartFacet, SinkClass } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmRubyTaintEngine(); await warmGoTaintEngine(); }, 120000);

describe("combineUrlFacets", () => {
  it("a slash prefix without a double slash, or no host and no scheme, clears redirect and SSRF", () => {
    const g = [...urlPrefixFacets("u", "/", "starts"), ...urlPrefixFacets("u", "//", "starts").map(x => ({ ...x, holds: x.holds === "true" ? "false" as const : "true" as const }))];
    expect(combineUrlFacets(g, "true")).toEqual([{ name: "u", holds: "true", clears: SinkClass.REDIRECT | SinkClass.SSRF }]);
    expect(combineUrlFacets([...urlPartFacet("u", "host", "true"), ...urlPartFacet("u", "scheme", "true")], "true")[0].clears).toBe(SinkClass.REDIRECT | SinkClass.SSRF);
  });
  it("no '://' and no leading '//' clears redirects only (file:/etc/passwd is still a local read)", () => {
    const g = [...urlPrefixFacets("u", "://", "contains"), ...urlPrefixFacets("u", "//", "starts")];
    expect(combineUrlFacets(g, "false")).toEqual([{ name: "u", holds: "false", clears: SinkClass.REDIRECT }]);
  });
  it("one half alone proves nothing; facets of different names don't combine", () => {
    expect(combineUrlFacets(urlPrefixFacets("u", "/", "starts"), "true")).toEqual([]);
    expect(combineUrlFacets([...urlPrefixFacets("a", "/", "starts"), ...urlPrefixFacets("b", "//", "starts")], "true")).toEqual([]);
  });
  it("a prefix that fixes the host is a full guard; one without a path after the host is not", () => {
    expect(urlPrefixFacets("u", "https://example.com/", "starts")).toEqual([{ name: "u", holds: "true", clears: SinkClass.REDIRECT | SinkClass.SSRF }]);
    expect(urlPrefixFacets("u", "https://example.com", "starts")).toEqual([]);
  });
});

describe("Go", () => {
  const goH = (body: string) => `package main\n\nimport (\n\t"net"\n\t"net/http"\n\t"net/url"\n\t"strings"\n)\n\nfunc H(w http.ResponseWriter, r *http.Request) {\n\tinput := r.URL.Query().Get("next")\n${body}\n}\n`;
  const has = (code: string, id: string) => analyzeFile("handlers/h.go", code).indicators.some(i => i.id === id && !!i.sourceExpr);
  it("redirect to u.Path of the parsed input; to the whole parsed URL still reports", () => {
    expect(has(goH(`\tu, err := url.Parse(input)\n\tif err != nil {\n\t\treturn\n\t}\n\thttp.Redirect(w, r, u.Path, http.StatusFound)`), "open-redirect")).toBe(false);
    expect(has(goH(`\tu, err := url.Parse(input)\n\tif err != nil {\n\t\treturn\n\t}\n\thttp.Redirect(w, r, u.String(), http.StatusFound)`), "open-redirect")).toBe(true);
  });
  it("HasPrefix '/' and not '//'; Host and Scheme empty; one half alone still reports", () => {
    expect(has(goH(`\tif strings.HasPrefix(input, "/") && !strings.HasPrefix(input, "//") {\n\t\thttp.Redirect(w, r, input, http.StatusFound)\n\t}`), "open-redirect")).toBe(false);
    expect(has(goH(`\tif strings.HasPrefix(input, "/") {\n\t\thttp.Redirect(w, r, input, http.StatusFound)\n\t}`), "open-redirect")).toBe(true);
    expect(has(goH(`\tu, err := url.Parse(input)\n\tif err != nil {\n\t\treturn\n\t}\n\tif u.Host == "" && u.Scheme == "" {\n\t\thttp.Redirect(w, r, input, http.StatusFound)\n\t}`), "open-redirect")).toBe(false);
    expect(has(goH(`\tu, err := url.Parse(input)\n\tif err != nil {\n\t\treturn\n\t}\n\tif u.Scheme == "" {\n\t\thttp.Redirect(w, r, input, http.StatusFound)\n\t}`), "open-redirect")).toBe(true);
  });
  it("an early return on a loopback / private / link-local IP clears SSRF; missing link-local does not", () => {
    const ssrf = (checks: string) => goH(`\tu, err := url.Parse(input)\n\tif err != nil {\n\t\treturn\n\t}\n\tip := net.ParseIP(u.Hostname())\n\tif ip == nil {\n\t\treturn\n\t}\n\tif ${checks} {\n\t\treturn\n\t}\n\tresp, _ := http.Get(input)\n\t_ = resp`);
    expect(has(ssrf(`ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()`), "ssrf")).toBe(false);
    expect(has(ssrf(`ip.IsLoopback() || ip.IsPrivate()`), "ssrf")).toBe(true);
  });
});

describe("Ruby redirects", () => {
  const bench = (body: string) => `require_relative 'shared'\ndef handler(req)\n  url = req.param('url')\n${body}\nend\n`;
  const red = (code: string) => analyzeFile("testcode/r.rb", code).indicators.some(i => i.id === "open-redirect" && !!i.sourceExpr);
  it("starts with '/' and not '//'; either half alone still reports", () => {
    expect(red(bench(`  if url.start_with?('/') && !url.start_with?('//')\n    BenchmarkResponse.redirect(url)\n  else\n    BenchmarkResponse.bad_request('no')\n  end`))).toBe(false);
    expect(red(bench(`  if url.start_with?('/')\n    BenchmarkResponse.redirect(url)\n  else\n    BenchmarkResponse.bad_request('no')\n  end`))).toBe(true);
    expect(red(bench(`  if !url.start_with?('//')\n    BenchmarkResponse.redirect(url)\n  else\n    BenchmarkResponse.bad_request('no')\n  end`))).toBe(true);
  });
  it("an early return on '://' or '//'", () => {
    expect(red(bench(`  return BenchmarkResponse.bad_request('no') if url.include?('://') || url.start_with?('//')\n  BenchmarkResponse.redirect(url)`))).toBe(false);
    expect(red(bench(`  return BenchmarkResponse.bad_request('no') if url.include?('://')\n  BenchmarkResponse.redirect(url)`))).toBe(true);
  });
  it("a parsed URI with no host and no scheme; only one of them still reports", () => {
    expect(red(bench(`  parsed = URI.parse(url) rescue nil\n  if parsed && parsed.host.nil? && parsed.scheme.nil?\n    BenchmarkResponse.redirect(url)\n  else\n    BenchmarkResponse.bad_request('no')\n  end`))).toBe(false);
    expect(red(bench(`  parsed = URI.parse(url) rescue nil\n  if parsed && parsed.scheme.nil?\n    BenchmarkResponse.redirect(url)\n  else\n    BenchmarkResponse.bad_request('no')\n  end`))).toBe(true);
  });
  it("a guarded ternary: the checked arm is safe, an unchecked value in it is not", () => {
    expect(red(bench(`  dest = url.start_with?('/') && !url.start_with?('//') ? url : '/'\n  BenchmarkResponse.redirect(dest)`))).toBe(false);
    expect(red(bench(`  dest = url.start_with?('/') ? url : '/'\n  BenchmarkResponse.redirect(dest)`))).toBe(true);
  });
  it("URI.parse(url).path is the path only", () => {
    expect(red(bench(`  parsed = URI.parse(url) rescue nil\n  safe_path = parsed&.path || '/'\n  BenchmarkResponse.redirect(safe_path)`))).toBe(false);
    expect(red(`require_relative 'shared'\ndef h(req)\n  uri = URI.parse(req.param('next'))\n  BenchmarkResponse.redirect(uri.path || '/')\nend\n`)).toBe(false);
    expect(red(`require_relative 'shared'\ndef h(req)\n  uri = URI.parse(req.param('next'))\n  BenchmarkResponse.redirect(uri.to_s)\nend\n`)).toBe(true);
    expect(red(bench(`  parsed = URI.parse(url) rescue nil\n  BenchmarkResponse.redirect(parsed.to_s)`))).toBe(true);
  });
  it("the same in a Rails controller", () => {
    const rails = (cond: string) => `class SessionsController < ApplicationController\n  def create\n    target = params[:return_to]\n    if ${cond}\n      redirect_to target\n    else\n      redirect_to root_path\n    end\n  end\nend\n`;
    const r = (cond: string) => analyzeFile("app/controllers/sessions_controller.rb", rails(cond)).indicators.some(i => i.id === "open-redirect" && !!i.sourceExpr);
    expect(r(`target.start_with?('/') && !target.start_with?('//')`)).toBe(false);
    expect(r(`target.start_with?('/')`)).toBe(true);
  });
});
