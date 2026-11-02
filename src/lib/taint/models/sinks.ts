/**
 * Sink models: calls where a value becomes dangerous, which rule they report, and which argument matters
 * (Universal Taint Model, docs/taint/utm-gap-report.md §6.2). An engine asks sinkModelFor(...) with the call as it
 * sees it; the model answers with the rule and the argument positions / keywords to judge, and the engine extracts
 * those arguments with its own parser.
 *
 * Migrated so far: SSRF, in every engine. Each entry reproduces what the
 * engine matched before the move; the golden snapshot keeps it that way.
 */
import type { ModelLang } from "./types";

export interface SinkModel {
  id: string;
  langs: ModelLang[];
  framework: string;
  rule: string;
  /** What the judged argument is, in words (shown as the sink's role in evidence). */
  role: string;
  /** `callee`: the whole callee text; `prefix`: any callee text starting with it (`axios`, `axios.get`, `axiosInstance.post`);
   * `module`: a method of an imported module (`requests.get`, or `get` imported from it) -- `importedOnly` when the
   * name alone, unresolved, doesn't count; `bare` when calling the imported binding itself counts too (`got(url)`);
   * `receiver`: a method on a receiver whose text matches the pattern (`client.Get`). */
  match:
    | { kind: "callee"; names: string[] }
    | { kind: "prefix"; prefix: string }
    | { kind: "module"; module: string; methods: string[]; importedOnly?: boolean; bare?: boolean }
    | { kind: "receiver"; receiver: string; methods: string[] }
    /** a method by name on any receiver (`restTemplate.getForObject`, `client.GetAsync`) */
    | { kind: "method"; methods: string[] }
    /** a constructor (`new Socket(host, port)`); the engine asks with the callee `new <Class>` */
    | { kind: "constructor"; classes: string[] }
    /** the whole callee text against a pattern (`Net::HTTP.get`, `reqwest::get`) -- for families too regular to list */
    | { kind: "pattern"; pattern: string };
  /** Which arguments carry the danger: positions (0-based), by method when it differs, and keyword names (Python)
   * tried before the position -- or after it with `keywordFallback`. `extraKeywords` are judged as well when present
   * (`proxies`: the request is routed through that host). `select` names an engine-side selector for arguments a
   * position can't describe (a JS options object's `url`/`host`/`proxy`). */
  args: {
    positions: number[]; byMethod?: Record<string, number[]>; keywords?: string[]; keywordFallback?: boolean; extraKeywords?: string[];
    select?: SinkArgSelector;
    /** Judged only when argument `index`'s text matches `pattern` (libcurl's `CURLOPT_URL` option). */
    whenArg?: { index: number; pattern: string };
  };
  /** The judged value is a host / address rather than a URL, so a URL's fixed scheme-and-host prefix can't make it
   * safe (Kotlin judges URLs by shape, hosts by taint alone). */
  target?: "host";
  /** How the sink is named in evidence, when not the callee text: `{callee}`, `{method}`, `{receiver}`, and
   * `{receiverRoot}` (the receiver's first segment). */
  label?: string;
}

/** Engine-implemented argument selectors: a JS options object's target (astTaint.ts requestTargetArgs, optionally
 * after a leading method name); the URL object the call is made on (`new URL(x).openConnection()`); the whole call,
 * receiver chain included (`HttpRequest.newBuilder().uri(x)`, Java); the receiver must be an HTTP client by its
 * declared type or name (Kotlin); `url(x)` inside a client's request lambda (Ktor, Kotlin); the receiver itself is
 * the URL (`"…".httpGet()`, Fuel); a PHP stream read, which fetches only when the value can start a URL (it is a
 * file path otherwise); a curl option value, judged only when the option (the argument before it) picks the
 * destination (CURLOPT_URL, _PROXY, ...). */
export type SinkArgSelector = "request-target" | "request-target-method-first" | "url-receiver" | "all-arguments"
  | "http-client-receiver" | "client-request-lambda" | "receiver-value" | "url-wrapper" | "curl-option";

const HTTP_URL = "the request URL";
/** A case-insensitive regex fragment for a literal word. */
const ci = (word: string) => [...word].map(c => /[a-z]/i.test(c) ? `[${c.toUpperCase()}${c.toLowerCase()}]` : c).join("");
const ANY_RECEIVER = "^.";

export const SINK_MODELS: readonly SinkModel[] = [
  { id: "go:net/http:get", langs: ["go"], framework: "net/http", rule: "ssrf", role: HTTP_URL,
    match: { kind: "callee", names: ["http.Get", "http.Post", "http.Head", "http.PostForm"] }, args: { positions: [0] } },
  { id: "go:net/http:client", langs: ["go"], framework: "net/http", rule: "ssrf", role: HTTP_URL,
    match: { kind: "receiver", receiver: "(?:^|\\.)(?:client|Client|httpClient|http\\.DefaultClient)$", methods: ["Get", "Post", "Head", "PostForm"] }, args: { positions: [0] } },
  { id: "go:net:dial", langs: ["go"], framework: "net", rule: "ssrf", role: "the address dialled",
    match: { kind: "callee", names: ["net.Dial", "net.DialTimeout", "net.DialTCP", "net.DialUDP"] }, args: { positions: [1] } },

  // request()/stream() take (method, url); the params/data/json/headers/cookies are sent TO the URL, not where it goes
  { id: "py:requests", langs: ["py"], framework: "requests", rule: "ssrf", role: HTTP_URL,
    match: { kind: "module", module: "requests", methods: ["get", "post", "put", "delete", "patch", "request", "head"] },
    args: { positions: [0], byMethod: { request: [1] }, keywords: ["url"], extraKeywords: ["proxies", "proxy"] } },
  { id: "py:httpx", langs: ["py"], framework: "httpx", rule: "ssrf", role: HTTP_URL,
    match: { kind: "module", module: "httpx", methods: ["get", "post", "put", "delete", "patch", "request", "head", "stream"] },
    args: { positions: [0], byMethod: { request: [1], stream: [1] }, keywords: ["url"], extraKeywords: ["proxies", "proxy"] } },
  { id: "py:urllib", langs: ["py"], framework: "urllib", rule: "ssrf", role: HTTP_URL,
    match: { kind: "callee", names: ["urllib.request.urlopen", "urllib.request.Request"] }, args: { positions: [0], keywords: ["url"], keywordFallback: true } },
  { id: "py:urllib.request", langs: ["py"], framework: "urllib", rule: "ssrf", role: HTTP_URL,
    match: { kind: "module", module: "urllib.request", methods: ["urlopen", "Request"], importedOnly: true }, args: { positions: [0], keywords: ["url"], keywordFallback: true } },
  { id: "py:urllib.urlopen", langs: ["py"], framework: "urllib", rule: "ssrf", role: HTTP_URL,
    match: { kind: "module", module: "urllib", methods: ["urlopen"], importedOnly: true }, args: { positions: [0], keywords: ["url"], keywordFallback: true } },

  // JS/TS: fetch and Node's http/https, axios, and the HTTP client packages. The URL is the first argument, or an
  // options object's url / host / path / proxy (requestTargetArgs).
  { id: "js:fetch-http", langs: ["js"], framework: "node", rule: "ssrf", role: HTTP_URL,
    match: { kind: "callee", names: ["fetch", "http.get", "http.request", "https.get", "https.request"] }, args: { positions: [0], select: "request-target" } },
  { id: "js:axios", langs: ["js"], framework: "axios", rule: "ssrf", role: HTTP_URL,
    match: { kind: "prefix", prefix: "axios" }, args: { positions: [0], select: "request-target" } },
  ...(["http", "https"] as const).map((module): SinkModel => ({ id: `js:${module}-module`, langs: ["js"], framework: "node", rule: "ssrf", role: HTTP_URL,
    match: { kind: "module", module, methods: ["get", "post", "put", "delete", "patch", "request"], importedOnly: true }, args: { positions: [0], select: "request-target" } })),
  // needle("get", url) / superagent("GET", url): a method name may come first
  ...(["needle", "got", "request", "superagent", "node-fetch", "undici", "cross-fetch"] as const).map((module): SinkModel => ({ id: `js:${module}`, langs: ["js"], framework: module, rule: "ssrf", role: HTTP_URL,
    match: { kind: "module", module, methods: ["get", "post", "put", "delete", "patch", "request", "head", "fetch"], importedOnly: true, bare: true },
    args: { positions: [0], select: "request-target-method-first" } })),

  // Java: Spring RestTemplate, java.net.URL connections, java.net.http, name resolution, raw sockets, and auth0
  // jwks-rsa (fetches signing keys from the URL it is given -- fed from a token's own `jku`, the attacker picks the keys)
  { id: "java:resttemplate", langs: ["java"], framework: "spring", rule: "ssrf", role: HTTP_URL,
    match: { kind: "method", methods: ["getForObject", "postForObject", "exchange"] }, args: { positions: [0] } },
  { id: "java:url-connection", langs: ["java"], framework: "java.net", rule: "ssrf", role: "the URL the connection opens",
    match: { kind: "method", methods: ["openConnection", "openStream"] }, args: { positions: [0], select: "url-receiver" } },
  { id: "java:http-request", langs: ["java"], framework: "java.net.http", rule: "ssrf", role: HTTP_URL,
    match: { kind: "receiver", receiver: "^HttpRequest$", methods: ["uri", "newBuilder"] }, args: { positions: [0], select: "all-arguments" } },
  { id: "java:inetaddress", langs: ["java"], framework: "java.net", rule: "ssrf", role: "the host name resolved",
    match: { kind: "receiver", receiver: "^InetAddress$", methods: ["getByName"] }, args: { positions: [0], select: "all-arguments" } },
  { id: "java:socket", langs: ["java"], framework: "java.net", rule: "ssrf", role: "the host connected to",
    match: { kind: "constructor", classes: ["Socket"] }, args: { positions: [0] }, target: "host" },
  { id: "java:jwks", langs: ["java"], framework: "auth0", rule: "ssrf", role: "the URL signing keys are fetched from",
    match: { kind: "constructor", classes: ["JwkProviderBuilder", "UrlJwkProvider"] }, args: { positions: [0] } },

  // C#: HttpClient / WebClient methods, WebClient.OpenRead (not File.OpenRead), WebRequest.Create, new HttpRequestMessage(method, url)
  { id: "cs:http-client", langs: ["cs"], framework: "System.Net", rule: "ssrf", role: HTTP_URL,
    match: { kind: "method", methods: ["GetAsync", "PostAsync", "PutAsync", "DeleteAsync", "SendAsync", "GetStringAsync", "GetByteArrayAsync",
      "GetStreamAsync", "PostAsJsonAsync", "PutAsJsonAsync", "DownloadString", "DownloadStringAsync", "DownloadStringTaskAsync", "DownloadData",
      "DownloadFile", "DownloadFileAsync", "UploadString", "UploadData"] }, args: { positions: [0] } },
  { id: "cs:openread", langs: ["cs"], framework: "System.Net", rule: "ssrf", role: HTTP_URL,
    match: { kind: "receiver", receiver: "^(?!(?:Path|File|Directory|FileInfo|DirectoryInfo)$)", methods: ["OpenRead"] }, args: { positions: [0] } },
  { id: "cs:webrequest", langs: ["cs"], framework: "System.Net", rule: "ssrf", role: HTTP_URL,
    match: { kind: "receiver", receiver: "^(?:WebRequest|HttpWebRequest)$", methods: ["Create", "CreateHttp"] }, args: { positions: [0] } },
  { id: "cs:http-request-message", langs: ["cs"], framework: "System.Net.Http", rule: "ssrf", role: HTTP_URL,
    match: { kind: "constructor", classes: ["HttpRequestMessage"] }, args: { positions: [1] } },

  // Kotlin: every model that matches a call is judged (sinkModelsFor), in this order. URLs are judged by shape
  // (a fixed scheme-and-host prefix makes the rest a path); InetAddress lookups are judged the same way, as before.
  { id: "kt:resttemplate", langs: ["kt"], framework: "spring", rule: "ssrf", role: HTTP_URL, label: "RestTemplate.{method}",
    match: { kind: "receiver", receiver: ANY_RECEIVER, methods: ["getForObject", "getForEntity", "postForObject", "postForEntity", "exchange",
      "patchForObject", "postForLocation", "headForHeaders", "optionsForAllow"] }, args: { positions: [0] } },
  { id: "kt:url-read", langs: ["kt"], framework: "java.net", rule: "ssrf", role: "the URL read", label: "URL.{method}",
    match: { kind: "receiver", receiver: ANY_RECEIVER, methods: ["openConnection", "openStream", "readText", "readBytes", "getContent", "content"] },
    args: { positions: [0], select: "url-receiver" } },
  { id: "kt:uri", langs: ["kt"], framework: "webclient", rule: "ssrf", role: HTTP_URL, label: "{receiverRoot}.{method}",
    match: { kind: "receiver", receiver: `${ci("client")}|${ci("HttpRequest")}|${ci("newBuilder")}|\\.(?:get|post|put|delete|patch|head|method)$`, methods: ["uri"] },
    args: { positions: [0] } },
  { id: "kt:url-builder", langs: ["kt"], framework: "webclient", rule: "ssrf", role: HTTP_URL, label: "{method}",
    match: { kind: "receiver", receiver: "Builder|builder|WebClient|RestClient", methods: ["url", "baseUrl"] }, args: { positions: [0] } },
  { id: "kt:client-request-url", langs: ["kt"], framework: "ktor", rule: "ssrf", role: HTTP_URL, label: "client.request { url(...) }",
    match: { kind: "callee", names: ["url"] }, args: { positions: [0], select: "client-request-lambda" } },
  { id: "kt:http-client", langs: ["kt"], framework: "ktor", rule: "ssrf", role: HTTP_URL, label: "{receiver}.{method}",
    match: { kind: "receiver", receiver: ANY_RECEIVER, methods: ["get", "post", "put", "delete", "patch", "head", "options", "request",
      "prepareGet", "preparePost", "preparePut", "prepareDelete", "prepareRequest", "submitForm"] },
    args: { positions: [0], keywords: ["urlString"], select: "http-client-receiver" } },
  { id: "kt:clients", langs: ["kt"], framework: "jvm", rule: "ssrf", role: HTTP_URL,
    match: { kind: "callee", names: ["WebClient.create", "HttpRequest.newBuilder", "Jsoup.connect", "InetAddress.getByName", "InetAddress.getAllByName",
      "Fuel.get", "Fuel.post", "Fuel.put", "Fuel.delete"] }, args: { positions: [0] } },
  { id: "kt:fuel-string", langs: ["kt"], framework: "fuel", rule: "ssrf", role: HTTP_URL, label: ".{method}()",
    match: { kind: "receiver", receiver: ANY_RECEIVER, methods: ["httpGet", "httpPost", "httpPut", "httpDelete", "httpPatch", "httpHead"] },
    args: { positions: [0], select: "receiver-value" } },
  { id: "kt:socket", langs: ["kt"], framework: "java.net", rule: "ssrf", role: "the host connected to", label: "Socket",
    match: { kind: "constructor", classes: ["Socket"] }, args: { positions: [0] }, target: "host" },

  // PHP: the URL-wrapper reads (also the path-traversal sinks: a value starting the argument picks a file or a URL),
  // sockets, and curl -- curl_setopt($ch, OPT, $v) / $curl->setopt(OPT, $v) judged only for destination options
  { id: "php:url-wrapper-reads", langs: ["php"], framework: "php", rule: "ssrf", role: "the URL or path read",
    match: { kind: "callee", names: ["fopen", "file_get_contents", "readfile", "file", "parse_ini_file"] }, args: { positions: [0], select: "url-wrapper" } },
  { id: "php:sockets", langs: ["php"], framework: "php", rule: "ssrf", role: "the host connected to",
    match: { kind: "callee", names: ["fsockopen", "pfsockopen", "stream_socket_client"] }, args: { positions: [0] }, target: "host" },
  { id: "php:curl-init", langs: ["php"], framework: "curl", rule: "ssrf", role: HTTP_URL,
    match: { kind: "callee", names: ["curl_init"] }, args: { positions: [0] } },
  { id: "php:curl-setopt", langs: ["php"], framework: "curl", rule: "ssrf", role: "a destination option's value",
    match: { kind: "callee", names: ["curl_setopt"] }, args: { positions: [2], select: "curl-option" } },
  { id: "php:curl-object-setopt", langs: ["php"], framework: "curl", rule: "ssrf", role: "a destination option's value", label: "curl_setopt",
    match: { kind: "receiver", receiver: ANY_RECEIVER, methods: ["setopt"] }, args: { positions: [1], select: "curl-option" } },

  // Ruby: connections to a request-chosen host (sockets, mail, FTP, LDAP, Redis, Elasticsearch), then the HTTP
  // clients -- the first of these that applies is judged, once
  { id: "rb:host-connect", langs: ["rb"], framework: "ruby", rule: "ssrf", role: "the host connected to", target: "host",
    match: { kind: "pattern", pattern: "^(?:::)?(?:Socket\\.tcp|TCPSocket\\.(?:new|open)|Net::(?:SMTP|FTP|Telnet|POP3|IMAP)\\.(?:start|new|open)|Net::LDAP\\.new|Redis\\.new|Elasticsearch::Client\\.new)$" },
    args: { positions: [0], keywords: ["host", "url", "hosts"] } },
  { id: "rb:http", langs: ["rb"], framework: "ruby", rule: "ssrf", role: HTTP_URL,
    match: { kind: "pattern", pattern: "^(?:::)?(?:Net::HTTP\\.(?:get|get_response|get_print|post|post_form|start|new)|URI\\.open|(?:HTTParty|Faraday|RestClient|Excon|HTTP|Typhoeus|HTTPX|Curl)\\.(?:get|post|put|patch|delete|head|options|request|new|follow|via|stream_get)|RestClient::Request\\.(?:execute|new)|Typhoeus::Request\\.new|Faraday::Connection\\.new|OpenURI\\.open_uri)$" },
    args: { positions: [0], keywords: ["url"] } },
  { id: "rb:http-client", langs: ["rb"], framework: "ruby", rule: "ssrf", role: HTTP_URL,
    match: { kind: "receiver", receiver: ANY_RECEIVER, methods: ["get", "post", "put", "patch", "delete", "head", "request", "get_content", "post_content"] },
    args: { positions: [0], keywords: ["url"], select: "http-client-receiver" } },
  { id: "rb:url-fetch", langs: ["rb"], framework: "ruby", rule: "ssrf", role: "the URL or path fetched",
    match: { kind: "pattern", pattern: "^(?:::)?(?:MiniMagick::Image\\.open|WickedPdf\\.new\\.pdf_from_url)$" }, args: { positions: [0], keywords: ["url"] } },

  // Rust: free functions (reqwest/ureq/surf/isahc/attohttpc/minreq, std/tokio TcpStream), a client's methods
  // (request(method, url)), and an http::Request builder's uri
  { id: "rs:free-fns", langs: ["rs"], framework: "rust", rule: "ssrf", role: HTTP_URL,
    match: { kind: "pattern", pattern: "^(?:std::net::)?(?:reqwest::get|reqwest::blocking::get|ureq::get|ureq::post|ureq::put|ureq::delete|ureq::request|surf::get|surf::post|isahc::get|isahc::post|attohttpc::get|attohttpc::post|minreq::get|minreq::post|TcpStream::connect|UdpSocket::connect|tokio::net::TcpStream::connect)$" },
    args: { positions: [0] } },
  { id: "rs:http-client", langs: ["rs"], framework: "rust", rule: "ssrf", role: HTTP_URL, label: "{receiver}.{method}",
    match: { kind: "receiver", receiver: ANY_RECEIVER, methods: ["get", "post", "put", "delete", "patch", "head", "request"] },
    args: { positions: [0], byMethod: { request: [1] }, select: "http-client-receiver" } },
  { id: "rs:request-builder", langs: ["rs"], framework: "http", rule: "ssrf", role: HTTP_URL, label: "Request::builder().uri",
    match: { kind: "receiver", receiver: "Request::builder|Request::get|Request::post|builder\\(\\)", methods: ["uri"] }, args: { positions: [0] } },

  // C/C++: libcurl's URL option
  { id: "cpp:curl-url", langs: ["cpp"], framework: "libcurl", rule: "ssrf", role: HTTP_URL, label: "curl_easy_setopt(CURLOPT_URL)",
    match: { kind: "callee", names: ["curl_easy_setopt"] }, args: { positions: [2], whenArg: { index: 1, pattern: "CURLOPT_URL" } } },
];

export interface SinkLookup { model: SinkModel; positions: number[] }

/**
 * The sink model for a call, if any. `callee` is the callee text as the engine normalises it (`http.Get`,
 * `requests.get`); `module` the module a bare name was imported from (`from requests import get`), when known.
 */
export function sinkModelFor(lang: ModelLang, callee: string, module?: string | null): SinkLookup | null {
  return sinkModelsFor(lang, callee, module)[0] ?? null;
}

/** Every sink model for a call, in registry order -- for engines that judge each matching sink on its own. */
export function sinkModelsFor(lang: ModelLang, callee: string, module?: string | null): SinkLookup[] {
  const parts = callee.split(".");
  const tail = parts[parts.length - 1];
  const receiver = parts.slice(0, -1).join(".");
  const hits: SinkLookup[] = [];
  for (const model of SINK_MODELS) {
    if (!model.langs.includes(lang)) continue;
    const m = model.match;
    const isNew = callee.startsWith("new ");
    const hit = m.kind === "constructor" ? isNew && m.classes.includes(callee.slice(4).trim())
      : isNew ? false
        : m.kind === "callee" ? m.names.includes(callee)
          : m.kind === "prefix" ? callee.startsWith(m.prefix)
            : m.kind === "module" ? (module === m.module || (!m.importedOnly && parts[0] === m.module))
              && ((parts.length === 1 && !!m.bare) || m.methods.includes(tail))
              : m.kind === "method" ? m.methods.includes(tail)
                : m.kind === "pattern" ? new RegExp(m.pattern).test(callee)
                  : m.methods.includes(tail) && new RegExp(m.receiver).test(receiver);
    if (hit) hits.push({ model, positions: model.args.byMethod?.[tail] ?? model.args.positions });
  }
  return hits;
}

/** The sink's name in evidence for a call with this callee text (see SinkModel.label). */
export function sinkLabel(model: SinkModel, callee: string): string {
  const cut = callee.lastIndexOf(".");
  const receiver = cut < 0 ? "" : callee.slice(0, cut);
  return (model.label ?? "{callee}").replace(/\{(callee|method|receiver|receiverRoot)\}/g, (_, k: string) =>
    k === "callee" ? callee : k === "method" ? callee.slice(cut + 1) : k === "receiver" ? receiver : receiver.split(".")[0]);
}
