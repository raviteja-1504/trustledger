/**
 * @jest-environment node
 *
 * The SSRF sink models (taint/models/sinks.ts) as the Go and Python engines apply them: the judged argument is the
 * URL / address -- by position, or by keyword in Python -- plus Python's `proxies`; what is sent TO the URL is not.
 */
import { analyzeFile } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

beforeAll(async () => { await ensureTaintEngines(); }, 120_000);
const ssrf = (path: string, src: string) => analyzeFile(path, src).indicators.filter(i => i.id === "ssrf" && i.sourceExpr).map(i => i.line);

const py = (call: string) => ["from flask import request", "import requests", "def view():", "    u = request.args.get('u')", `    return ${call}`].join("\n");

describe("Python requests / httpx", () => {
  it("the URL by keyword", () => expect(ssrf("v.py", py("requests.get(url=u)"))).toEqual([5]));
  it("the proxy the request is routed through", () => expect(ssrf("v.py", py("requests.get('https://api.example.com', proxies={'https': u})"))).toEqual([5]));
  it("request(method, url): the second argument", () => expect(ssrf("v.py", py("requests.request('GET', u)"))).toEqual([5]));
  it("data sent to a fixed URL is not a request forgery", () => expect(ssrf("v.py", py("requests.post('https://api.example.com', data=u)"))).toEqual([]));
});

describe("Python urllib", () => {
  const u = (call: string) => ["from flask import request", "import urllib.request", "def view():", "    u = request.args.get('u')", `    return ${call}`].join("\n");
  it("urlopen(url)", () => expect(ssrf("v.py", u("urllib.request.urlopen(u)"))).toEqual([5]));
  it("urlopen(url=...) when no positional URL", () => expect(ssrf("v.py", u("urllib.request.urlopen(url=u)"))).toEqual([5]));
  it("a fixed URL with request data as the body is not a request forgery", () => expect(ssrf("v.py", u("urllib.request.urlopen('https://api.example.com', data=u)"))).toEqual([]));
});

describe("JS/TS clients", () => {
  const js = (lines: string[]) => ["app.get('/p', async (req, res) => {", "  const u = req.query.u;", ...lines, "});"].join("\n");
  it("fetch(url)", () => expect(ssrf("a.js", js(["  await fetch(u);"]))).toEqual([3]));
  it("an options object's host", () => expect(ssrf("a.js", ["const https = require('https');", js(["  https.request({ host: u, path: '/' });"])].join("\n"))).toEqual([4]));
  it("got(url), a package called directly", () => expect(ssrf("a.js", ["const got = require('got');", js(["  await got(u);"])].join("\n"))).toEqual([4]));
  it("needle('get', url): the method first, the URL second", () => expect(ssrf("a.js", ["const needle = require('needle');", js(["  needle('get', u);"])].join("\n"))).toEqual([4]));
  it("a fixed URL with request data as the body is not a request forgery", () => expect(ssrf("a.js", js(["  await fetch('https://api.example.com/x', { method: 'POST', body: u });"]))).toEqual([]));
});

const go = (call: string) => ["package main", 'import ("net"; "net/http")', "func h(w http.ResponseWriter, r *http.Request) {",
  '  u := r.URL.Query().Get("u")', `  ${call}`, "}"].join("\n");

describe("Go net/http and net.Dial", () => {
  it("net.Dial(network, address): the address", () => expect(ssrf("h.go", go(`net.Dial("tcp", u)`))).toEqual([5]));
  it("the network name is not where it connects", () => expect(ssrf("h.go", go(`net.Dial(u, "10.0.0.1:80")`))).toEqual([]));
  it("http.Post's body is sent to the URL, not where it goes", () => expect(ssrf("h.go", go(`http.Post("https://api.example.com", "text/plain", strings.NewReader(u))`))).toEqual([]));
  it("http.Get(url)", () => expect(ssrf("h.go", go(`http.Get(u)`))).toEqual([5]));
});

const java = (lines: string[]) => ["import javax.servlet.http.*;", "import java.net.*;", "public class C {",
  "  public void h(HttpServletRequest request) throws Exception {", '    String u = request.getParameter("u");', ...lines.map(l => `    ${l}`), "  }", "}"].join("\n");

describe("Java", () => {
  it("RestTemplate.getForObject(url, type)", () => expect(ssrf("C.java", java(["restTemplate.getForObject(u, String.class);"]))).toEqual([6]));
  it("the request variables of a fixed URL are not where it goes", () =>
    expect(ssrf("C.java", java(['restTemplate.getForObject("https://api.example.com/{q}", String.class, u);']))).toEqual([]));
  it("new URL(x).openConnection()", () => expect(ssrf("C.java", java(["new URL(u).openConnection();"]))).toEqual([6]));
  it("openStream() on a URL variable", () => expect(ssrf("C.java", java(["URL url = new URL(u);", "url.openStream();"]))).toEqual([7]));
  it("InetAddress.getByName(host)", () => expect(ssrf("C.java", java(["InetAddress.getByName(u);"]))).toEqual([6]));
  it("new Socket(host, port): the host", () => expect(ssrf("C.java", java(["new Socket(u, 80);"]))).toEqual([6]));
  it("new Socket's local bind address is not where it connects", () =>
    expect(ssrf("C.java", ["import org.springframework.web.bind.annotation.*;", "import java.net.*;", "@RestController", "public class C {",
      '  @GetMapping("/s")', "  public void s(@RequestParam InetAddress bind) throws Exception {", '    new Socket("10.0.0.1", 80, bind, 0);', "  }", "}"].join("\n"))).toEqual([]));
});

const kt = (params: string, lines: string[]) => ["import org.springframework.web.bind.annotation.*", "@RestController", "class C {",
  `  @GetMapping("/k") fun k(@RequestParam u: String${params}) {`, ...lines.map(l => `    ${l}`), "  }", "}"].join("\n");
const ktSinks = (src: string) => analyzeFile("C.kt", src).indicators.filter(i => i.id === "ssrf" && i.sourceExpr).map(i => `${i.line} ${i.sinkExpr ?? ""}`.trim());

describe("Kotlin", () => {
  it("RestTemplate, named as such", () => expect(ktSinks(kt("", ["rt.getForEntity(u, String::class.java)"]))).toEqual(["5 RestTemplate.getForEntity"]));
  it("a URL object read", () => expect(ktSinks(kt("", ["val url = URL(u)", "url.readBytes()"]))).toEqual(["6 URL.readBytes"]));
  it("uri() on a client chain", () => expect(ssrf("C.kt", kt(", webClient: WebClient", ["webClient.post().uri(u)"]))).toEqual([5]));
  it("uri() on a client by name, any case", () => expect(ssrf("C.kt", kt("", ["apiClient.uri(u)"]))).toEqual([5]));
  it("uri() after a request verb", () => expect(ssrf("C.kt", kt("", ["spec.get().uri(u)"]))).toEqual([5]));
  it("a URL-typed request value read", () => expect(ssrf("C.kt", ["import org.springframework.web.bind.annotation.*", "import java.net.URL", "@RestController", "class C {",
    '  @GetMapping("/k") fun k(@RequestParam link: URL) = link.readText()', "}"].join("\n"))).toEqual([5]));
  it("a client call's request-builder lambda is not its URL", () => expect(ssrf("C.kt", kt(", client: HttpClient", ['client.get({ header("X-Trace", u) })']))).toEqual([]));
  it("uri() on something that isn't a client", () => expect(ssrf("C.kt", kt("", ["builder.uri(u)"]))).toEqual([]));
  it("a client builder's baseUrl", () => expect(ssrf("C.kt", kt("", ["WebClient.builder().baseUrl(u)"]))).toEqual([5]));
  it("url(...) inside a client's request lambda", () => expect(ssrf("C.kt", kt(", client: HttpClient", ["client.request { url(u) }"]))).toEqual([5]));
  it("url(...) outside one", () => expect(ssrf("C.kt", kt("", ["run { url(u) }"]))).toEqual([]));
  it("a Ktor client's urlString", () => expect(ssrf("C.kt", kt(", client: HttpClient", ["client.get(urlString = u)"]))).toEqual([5]));
  it("get() on a map is not a request", () => expect(ssrf("C.kt", kt(", cache: Map<String, String>", ["cache.get(u)"]))).toEqual([]));
  it("Jsoup.connect / InetAddress.getByName", () => expect(ssrf("C.kt", kt("", ["Jsoup.connect(u)", "InetAddress.getByName(u)"]))).toEqual([5, 6]));
  it("Fuel's String.httpGet(): the string is the URL", () => expect(ssrf("C.kt", kt("", ["u.httpGet()"]))).toEqual([5]));
  it("Socket(host, port): the host, not URL-shaped", () => expect(ktSinks(kt("", ['Socket("$u.internal", 80)']))).toEqual(["5 Socket"]));
  it("a fixed scheme and host with input in the path is not a forgery", () =>
    expect(ssrf("C.kt", kt(", client: HttpClient", ['client.get("https://api.example.com/items/$u")']))).toEqual([]));
});

const labelled = (path: string, src: string) => analyzeFile(path, src).indicators.filter(i => i.id === "ssrf" && i.sourceExpr).map(i => `${i.line} ${i.sinkExpr ?? ""}`.trim());
const php = (lines: string[]) => ["<?php", "function f() {", "  $u = $_GET['u'];", ...lines.map(l => `  ${l}`), "}"].join("\n");

describe("PHP", () => {
  it("curl_setopt with a destination option", () => expect(ssrf("f.php", php(["curl_setopt($ch, CURLOPT_URL, $u);"]))).toEqual([4]));
  it("curl_setopt with a body option is sent to the destination, not where it goes", () =>
    expect(ssrf("f.php", php(["curl_setopt($ch, CURLOPT_POSTFIELDS, $u);"]))).toEqual([]));
  it("$curl->setopt(CURLOPT_PROXY, ...), named as curl_setopt", () => expect(labelled("f.php", php(["$curl->setopt(CURLOPT_PROXY, $u);"]))).toEqual(["4 curl_setopt"]));
  it("$curl->setopt with a header option", () => expect(ssrf("f.php", php(["$curl->setopt(CURLOPT_USERAGENT, $u);"]))).toEqual([]));
  it("a free function named setopt is not curl's", () => expect(ssrf("f.php", php(["setopt(CURLOPT_URL, $u);"]))).toEqual([]));
  it("curl_init(url)", () => expect(ssrf("f.php", php(["$ch = curl_init($u);"]))).toEqual([4]));
  it("fsockopen(host, port): the host", () => expect(ssrf("f.php", php(["$fp = fsockopen($u, 80);"]))).toEqual([4]));
  it("fsockopen's port is not where it connects", () => expect(ssrf("f.php", php(["$fp = fsockopen('10.0.0.1', $u);"]))).toEqual([]));
  it("a stream read after a URL scheme", () => expect(ssrf("f.php", php(["$c = file_get_contents('http://169.254.169.254/' . $u);"]))).toEqual([4]));
  it("a stream read under a local directory is a file, not a request", () => expect(ssrf("f.php", php(["$c = readfile('/var/data/' . $u);"]))).toEqual([]));
});

const rb = (lines: string[]) => ["class UsersController < ApplicationController", "  def show", ...lines.map(l => `    ${l}`), "  end", "end"].join("\n");

describe("Ruby", () => {
  it("a socket to a request-chosen host", () => expect(ssrf("users_controller.rb", rb(["TCPSocket.new(params[:h], 80)"]))).toEqual([3]));
  it("host: given by keyword", () => expect(ssrf("users_controller.rb", rb(["Redis.new(host: params[:h])"]))).toEqual([3]));
  it("a keyword that isn't the host", () => expect(ssrf("users_controller.rb", rb(["Redis.new(password: params[:p])"]))).toEqual([]));
  it("HTTParty.get(url)", () => expect(ssrf("users_controller.rb", rb(["HTTParty.get(params[:u])"]))).toEqual([3]));
  it("Faraday.new(url: ...)", () => expect(ssrf("users_controller.rb", rb(["Faraday.new(url: params[:u])"]))).toEqual([3]));
  it("a fixed host with input in the query", () => expect(ssrf("users_controller.rb", rb(['HTTParty.get("https://api.example.com/x?q=#{params[:q]}")']))).toEqual([]));
  it("a client instance's request", () => expect(ssrf("users_controller.rb", rb(["sess = Patron::Session.new", "sess.get(params[:u])"]))).toEqual([4]));
  it("get on something that isn't a client", () => expect(ssrf("users_controller.rb", rb(["cache = Hash.new", "cache.get(params[:u])"]))).toEqual([]));
  it("a URL-fetching image open", () => expect(ssrf("users_controller.rb", rb(["MiniMagick::Image.open(params[:u])"]))).toEqual([3]));
});

const rs = (lines: string[]) => ["use std::collections::HashMap;", "async fn h(Query(p): Query<HashMap<String, String>>) -> impl IntoResponse {",
  '    let u = p.get("url").unwrap();', ...lines.map(l => `    ${l}`), "}"].join("\n");

describe("Rust", () => {
  it("ureq::get(url)", () => expect(labelled("h.rs", rs(["ureq::get(u).call();"]))).toEqual(["4 ureq::get"]));
  it("std::net::TcpStream::connect(addr)", () => expect(ssrf("h.rs", rs(["std::net::TcpStream::connect(u);"]))).toEqual([4]));
  it("a client's request(method, url): the URL, named by the client", () =>
    expect(labelled("h.rs", rs(["let client = reqwest::Client::new();", "client.request(Method::GET, u).send();"]))).toEqual(["5 client.request"]));
  it("a client's request method is not where it goes", () =>
    expect(ssrf("h.rs", rs(["let client = reqwest::Client::new();", 'client.request(u, "https://api.example.com/x").send();']))).toEqual([]));
  it("get() on something that isn't a client", () => expect(ssrf("h.rs", rs(["let cache: HashMap<String, String> = HashMap::new();", "cache.get(u);"]))).toEqual([]));
  it("uri() on a builder a helper returns", () => expect(ssrf("h.rs", rs(["let r = request_builder().uri(u).body(());"]))).toEqual([4]));
  it("http::Request::builder().uri(url)", () => expect(labelled("h.rs", rs(["let r = http::Request::builder().uri(u).body(());"]))).toEqual(["4 Request::builder().uri"]));
});

const cs = (lines: string[]) => ["using System.Net.Http;", "public class C : Controller {", '  [HttpGet("h")]', "  public async Task<IActionResult> H(string u) {",
  ...lines.map(l => `    ${l}`), "    return Ok();", "  }", "}"].join("\n");

describe("C#", () => {
  it("HttpClient.GetStringAsync(url)", () => expect(ssrf("C.cs", cs(["await client.GetStringAsync(u);"]))).toEqual([5]));
  it("content posted to a fixed URL is not where it goes", () =>
    expect(ssrf("C.cs", cs(['await client.PostAsync("https://api.example.com", new StringContent(u));']))).toEqual([]));
  it("WebClient.OpenRead(url)", () => expect(ssrf("C.cs", cs(["webClient.OpenRead(u);"]))).toEqual([5]));
  it("File.OpenRead is a file, not a request", () => expect(ssrf("C.cs", cs(["File.OpenRead(u);"]))).toEqual([]));
  it("WebRequest.Create(url)", () => expect(ssrf("C.cs", cs(["WebRequest.Create(u);"]))).toEqual([5]));
  it("new HttpRequestMessage(method, url): the URL", () => expect(ssrf("C.cs", cs(["var m = new HttpRequestMessage(HttpMethod.Get, u);"]))).toEqual([5]));
  it("new HttpRequestMessage's method is not where it goes", () =>
    expect(ssrf("C.cs", cs(['var m = new HttpRequestMessage(new HttpMethod(u), "https://api.example.com");']))).toEqual([]));
});
