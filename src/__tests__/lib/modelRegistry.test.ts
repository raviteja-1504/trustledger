/**
 * @jest-environment node
 *
 * The Universal Taint Model registry (taint/models): built from the tables the engines use, consistent, and its
 * validator catches each kind of inconsistency.
 */
import { modelRegistry, validateRegistry, classNames } from "@/lib/taint/models/registry";
import { sanitizerClears } from "@/lib/taint/sanitizers";
import { SinkClass } from "@/lib/taint/taintCore";
import type { ModelRegistry } from "@/lib/taint/models/types";
import { sourceNames } from "@/lib/taint/models/sources";
import { sinkModelFor, sinkModelsFor } from "@/lib/taint/models/sinks";
import { propagatorNames } from "@/lib/taint/models/propagators";

const reg = modelRegistry();

describe("model registry", () => {
  it("is consistent: no duplicate ids, known classes and languages, every reported rule has a CWE", () => {
    expect(validateRegistry(reg)).toEqual([]);
  });

  it("lists every sanitizer the engines use, with the same effect sanitizerClears gives", () => {
    expect(reg.sanitizers.length).toBeGreaterThan(150);
    const html = reg.sanitizers.find(s => s.id === "py:exact:html.escape")!;
    expect(html.clears).toEqual(["XSS"]);
    expect(sanitizerClears("py", "html.escape")).toBe(SinkClass.XSS);
    const filterVar = reg.sanitizers.find(s => s.id === "php:exact:filter_var")!;
    expect(filterVar.clears).toBe("depends-on-arguments");
    for (const s of reg.sanitizers) {
      if (s.clears === "depends-on-arguments") continue;
      const lang = s.lang as Parameters<typeof sanitizerClears>[0];
      const callee = s.match.kind === "exact" ? s.match.name : `x.${s.match.name}`;
      expect([s.id, classNames(sanitizerClears(lang, callee) ?? 0)]).toEqual([s.id, s.clears]);
    }
  });

  it("every language has sanitizer models, C/C++ included (they used to be private to its engine)", () => {
    const langs = new Set(reg.sanitizers.map(s => s.lang));
    expect([...langs].sort()).toEqual(["cpp", "cs", "go", "java", "js", "kt", "php", "py", "rb", "rs"]);
    // a parsed number: every injection class cleared, still attacker-controlled
    expect(reg.sanitizers.find(s => s.id === "cpp:exact:stoi")!.clears).not.toContain("CONTROL");
    expect(reg.sanitizers.find(s => s.id === "cpp:exact:stoi")!.clears).toContain("CMD");
  });

  it("the taxonomy has every engine's rules, with their sink class and CWE", () => {
    const sql = reg.rules.find(r => r.id === "sql-injection")!;
    expect(sql).toMatchObject({ cwe: "CWE-89", sinkClass: "SQL" });
    expect(sql.languages).toEqual(expect.arrayContaining(["Java", "Python", "Go"]));
    expect(reg.rules.find(r => r.id === "xxe")).toMatchObject({ cwe: "CWE-611", sinkClass: "DESERIAL" });
    // a specialised analysis beside taint has no sink class
    expect(reg.rules.find(r => r.id === "weak-crypto")?.sinkClass).toBeNull();
  });
});

describe("JVM source models", () => {
  const sorted = (s: Set<string>) => [...s].sort();
  it("give each engine exactly the sources it had before the move (detection unchanged)", () => {
    const servlet = ["getCookies", "getHeader", "getHeaders", "getInputStream", "getParameter", "getParameterMap", "getParameterNames",
      "getParameterValues", "getPart", "getPathInfo", "getQueryString", "getReader", "getRequestURI", "getRequestURL"];
    expect(sorted(sourceNames("java", "request-call"))).toEqual(servlet);
    expect(sorted(sourceNames("kt", "request-call"))).toEqual([...servlet, "getParts", "getRemoteUser",
      "queryParam", "queryParams", "pathVariable", "pathVariables", "formData", "multipartData", "bodyToMono", "bodyToFlux",
      "awaitBody", "awaitBodyOrNull", "awaitFormData", "awaitMultipartData"].sort());
    expect(sorted(sourceNames("kt", "request-property"))).toEqual(["body", "cookies", "headerNames", "headers", "inputStream", "parameterMap",
      "parameterNames", "parts", "pathInfo", "queryParams", "queryString", "reader", "requestURI", "requestURL", "uri"]);
    const annotations = ["BeanParam", "CookieParam", "CookieValue", "FormParam", "HeaderParam", "MatrixParam", "MatrixVariable",
      "ModelAttribute", "PathParam", "PathVariable", "QueryParam", "RequestBody", "RequestHeader", "RequestParam", "RequestPart"];
    expect(sorted(sourceNames("java", "param-annotation"))).toEqual(annotations);
    expect(sorted(sourceNames("kt", "param-annotation"))).toEqual(annotations);
    expect(sourceNames("py", "request-call").size).toBe(0);   // not migrated yet
  });

  it("carry the kind of input and its trust: the logged-in user's name is not freely chosen", () => {
    const remoteUser = reg.sources.find(s => s.match.name === "getRemoteUser")!;
    expect(remoteUser).toMatchObject({ kind: "identity", trust: "semi-trusted" });
    expect(reg.sources.find(s => s.match.name === "getParameter")).toMatchObject({ kind: "http.query", trust: "untrusted", langs: ["java", "kt"] });
  });
});

describe("sink models", () => {
  it("answer what the engines matched before: the URL argument of Go and Python HTTP clients", () => {
    expect(sinkModelFor("go", "http.Get")).toMatchObject({ model: { rule: "ssrf" }, positions: [0] });
    expect(sinkModelFor("go", "httpClient.Post")).toMatchObject({ positions: [0] });
    expect(sinkModelFor("go", "net.Dial")).toMatchObject({ positions: [1] });      // net.Dial(network, address)
    expect(sinkModelFor("go", "cache.Get")).toBeNull();                             // a Get on something that isn't a client
    expect(sinkModelFor("py", "requests.get")).toMatchObject({ model: { id: "py:requests" }, positions: [0] });
    expect(sinkModelFor("py", "requests.request")).toMatchObject({ positions: [1] });  // request(method, url)
    expect(sinkModelFor("py", "get", "requests")).toMatchObject({ model: { id: "py:requests" } });  // from requests import get
    expect(sinkModelFor("py", "httpx.stream")).toMatchObject({ positions: [1] });
    expect(sinkModelFor("py", "session.get")).toBeNull();
    expect(sinkModelFor("js", "http.Get")).toBeNull();                              // models are per language
    // urllib: the positional URL before the url= keyword; only through urllib(.request)
    expect(sinkModelFor("py", "urllib.request.urlopen")).toMatchObject({ model: { id: "py:urllib", args: { keywordFallback: true } } });
    expect(sinkModelFor("py", "urlopen", "urllib.request")).toMatchObject({ model: { id: "py:urllib.request" } });
  });

  it("JS/TS clients: fetch, axios (any axios-prefixed client), Node http only when imported, packages called directly", () => {
    expect(sinkModelFor("js", "fetch")).toMatchObject({ model: { id: "js:fetch-http", args: { select: "request-target" } } });
    expect(sinkModelFor("js", "axiosInstance.post")).toMatchObject({ model: { id: "js:axios" } });
    expect(sinkModelFor("js", "http.post")).toBeNull();                                        // `http` not imported: not Node's
    expect(sinkModelFor("js", "http.post", "http")).toMatchObject({ model: { id: "js:http-module" } });
    expect(sinkModelFor("js", "got", "got")).toMatchObject({ model: { id: "js:got", args: { select: "request-target-method-first" } } });
    expect(sinkModelFor("js", "needle.head", "needle")).toMatchObject({ model: { id: "js:needle" } });
    expect(sinkModelFor("js", "got.extend", "got")).toBeNull();                                // not a request method
    expect(sinkModelFor("js", "got")).toBeNull();                                              // a local `got` that isn't the package
  });

  it("Java and C#: methods on any receiver, receiver-bound methods, constructors", () => {
    expect(sinkModelFor("java", "restTemplate.exchange")).toMatchObject({ model: { id: "java:resttemplate" }, positions: [0] });
    expect(sinkModelFor("java", "openStream")).toMatchObject({ model: { args: { select: "url-receiver" } } });
    expect(sinkModelFor("java", "HttpRequest.newBuilder")).toMatchObject({ model: { id: "java:http-request", args: { select: "all-arguments" } } });
    expect(sinkModelFor("java", "builder.uri")).toBeNull();                                    // only on HttpRequest itself
    expect(sinkModelFor("java", "InetAddress.getByName")).toMatchObject({ model: { id: "java:inetaddress" } });
    expect(sinkModelFor("java", "new Socket")).toMatchObject({ model: { id: "java:socket" }, positions: [0] });
    expect(sinkModelFor("java", "new UrlJwkProvider")).toMatchObject({ model: { id: "java:jwks" } });
    expect(sinkModelFor("java", "Socket")).toBeNull();                                         // a constructor only as `new`
    expect(sinkModelFor("java", "net.Socket")).toBeNull();                                     // ...not a call that ends in its name
    expect(sinkModelFor("java", "new Outer.exchange")).toBeNull();                             // a method never as `new`
    expect(sinkModelFor("cs", "client.GetStringAsync")).toMatchObject({ model: { id: "cs:http-client" }, positions: [0] });
    expect(sinkModelFor("cs", "client.OpenRead")).toMatchObject({ model: { id: "cs:openread" } });
    expect(sinkModelFor("cs", "OpenRead")).toMatchObject({ model: { id: "cs:openread" } });
    expect(sinkModelFor("cs", "File.OpenRead")).toBeNull();                                    // a file, not a URL
    expect(sinkModelFor("cs", "FileInfo.OpenRead")).toBeNull();
    expect(sinkModelFor("cs", "HttpWebRequest.CreateHttp")).toMatchObject({ model: { id: "cs:webrequest" } });
    expect(sinkModelFor("cs", "factory.Create")).toBeNull();
    expect(sinkModelFor("cs", "new HttpRequestMessage")).toMatchObject({ positions: [1] });   // (method, url)
    expect(sinkModelFor("java", "new HttpRequestMessage")).toBeNull();
  });

  it("PHP, Ruby and Rust: whole-callee patterns, all hits in order", () => {
    expect(sinkModelFor("rb", "::Net::HTTP.get_response")).toMatchObject({ model: { id: "rb:http" } });
    expect(sinkModelFor("rb", "Net::HTTP.get_responses")).toBeNull();                         // the whole callee, anchored
    expect(sinkModelFor("rb", "Redis.new")).toMatchObject({ model: { id: "rb:host-connect", target: "host", args: { keywords: ["host", "url", "hosts"] } } });
    expect(sinkModelsFor("rb", "HTTP.get").map(h => h.model.id)).toEqual(["rb:http", "rb:http-client"]);  // the engine picks the first that applies
    expect(sinkModelFor("rs", "std::net::TcpStream::connect")).toMatchObject({ model: { id: "rs:free-fns" } });
    expect(sinkModelFor("rs", "client.request")).toMatchObject({ positions: [1] });
    expect(sinkModelFor("rs", "http::Request::builder().uri")).toMatchObject({ model: { id: "rs:request-builder" } });
    expect(sinkModelFor("rs", "resp.uri")).toBeNull();
    expect(sinkModelFor("php", "curl_setopt")).toMatchObject({ positions: [2], model: { args: { select: "curl-option" } } });
    expect(sinkModelFor("php", "$curl.setopt")).toMatchObject({ positions: [1], model: { id: "php:curl-object-setopt" } });
    expect(sinkModelFor("php", "setopt")).toBeNull();
    expect(sinkModelFor("cpp", "curl_easy_setopt")).toMatchObject({ positions: [2], model: { args: { whenArg: { index: 1, pattern: "CURLOPT_URL" } } } });
  });

  it("every engine's SSRF sinks come from the registry", () => {
    const langs = new Set(reg.sinks.filter(s => s.rule === "ssrf").flatMap(s => s.langs));
    expect([...langs].sort()).toEqual(["cpp", "cs", "go", "java", "js", "kt", "php", "py", "rb", "rs"]);
  });
});

describe("propagator models", () => {
  it("every engine reads its propagators from the registry", () => {
    expect([...new Set(reg.propagators.map(p => p.lang))].sort()).toEqual(["cpp", "cs", "go", "java", "js", "kt", "php", "py", "rb", "rs"]);
    expect(propagatorNames("js", "decoder")).toEqual(new Set(["decodeURIComponent", "decodeURI", "unescape", "atob", "JSON.parse"]));
    expect(propagatorNames("go", "method-args")).toEqual(new Set(["Replace", "ReplaceAll", "Join", "Sprintf", "Format"]));
    expect(propagatorNames("py", "call-args").has("re.escape")).toBe(false);   // deliberately absent (see its comment)
    expect(propagatorNames("rb", "constructor-args").size).toBe(0);              // per language and kind
  });
  it("a decoder also carries its argument through", () => {
    for (const p of reg.propagators.filter(x => x.kind === "decoder")) {
      const carried = propagatorNames(p.lang, "call-args");
      expect({ lang: p.lang, notCarried: p.names.filter(n => !carried.has(n)) }).toEqual({ lang: p.lang, notCarried: [] });
    }
  });
});

describe("validator", () => {
  const broken = (patch: (r: ModelRegistry) => void) => {
    const copy: ModelRegistry = JSON.parse(JSON.stringify(reg));
    patch(copy);
    return validateRegistry(copy);
  };
  it("reports duplicate ids, unknown classes and languages, and a reported rule with no CWE", () => {
    expect(broken(r => r.sanitizers.push({ ...r.sanitizers[0] }))).toEqual([expect.stringContaining("duplicate id")]);
    expect(broken(r => { r.sanitizers[0].clears = ["HTML" as never]; })).toEqual([expect.stringContaining(`unknown class "HTML"`)]);
    expect(broken(r => { r.sanitizers[0].lang = "cobol" as never; })).toEqual([expect.stringContaining(`unknown language "cobol"`)]);
    expect(broken(r => { r.rules.find(x => x.id === "sql-injection")!.cwe = null; })).toEqual([expect.stringContaining("has no CWE")]);
    expect(broken(r => { r.rules[0].cwe = "89"; })).toEqual([expect.stringContaining("malformed CWE")]);
    expect(broken(r => r.sources.push({ ...r.sources[0] }))).toEqual([expect.stringContaining("duplicate id")]);
    expect(broken(r => { r.sources[0].kind = "http.everything" as never; })).toEqual([expect.stringContaining(`unknown kind "http.everything"`)]);
    expect(broken(r => { r.sources[0].langs = []; })).toEqual([expect.stringContaining("unknown or missing language")]);
    expect(broken(r => { r.sources[0].trust = "trusted" as never; })).toEqual([expect.stringContaining(`unknown trust "trusted"`)]);
    expect(broken(r => { r.sinks[0].rule = "server-side-thing"; })).toEqual([expect.stringContaining(`unknown rule "server-side-thing"`)]);
    expect(broken(r => { r.sinks[0].args.positions = [-1]; })).toEqual([expect.stringContaining("bad argument positions")]);
    expect(broken(r => { r.sinks[1].match = { kind: "receiver", receiver: "(", methods: ["Get"] }; })).toEqual([expect.stringContaining("doesn't compile")]);
    expect(broken(r => { r.sinks[1].match = { kind: "constructor", classes: [] }; })).toEqual([expect.stringContaining("empty match")]);
    expect(broken(r => { r.sinks[1].match = { kind: "method", methods: [] }; })).toEqual([expect.stringContaining("empty match")]);
    expect(broken(r => { r.sinks[1].label = "{recv}.{method}"; })).toEqual([expect.stringContaining(`unknown label field "{recv}"`)]);
    expect(broken(r => { r.sinks[1].match = { kind: "pattern", pattern: "a(" }; })).toEqual([expect.stringContaining(": pattern doesn't compile")]);
    expect(broken(r => { r.sinks[1].match = { kind: "pattern", pattern: "" }; })).toEqual([expect.stringContaining("empty match")]);
    expect(broken(r => { r.sinks[1].args.whenArg = { index: -1, pattern: "X" }; })).toEqual([expect.stringContaining("bad argument positions")]);
    expect(broken(r => r.propagators.push({ ...r.propagators[0] }))).toEqual([expect.stringContaining("propagator js:call-args: duplicate id")]);
    expect(broken(r => { r.propagators[0].kind = "sanitizer" as never; })).toEqual([expect.stringContaining(`unknown kind "sanitizer"`)]);
    expect(broken(r => { r.propagators[0].lang = "swift" as never; })).toEqual([expect.stringContaining(`unknown language "swift"`)]);
    expect(broken(r => { r.propagators[0].names = []; })).toEqual([expect.stringContaining("empty name")]);
    expect(broken(r => { r.sinks[1].args.whenArg = { index: 1, pattern: "(" }; })).toEqual([expect.stringContaining("whenArg pattern doesn't compile")]);
    expect(broken(r => { r.sinks[1].target = "port" as never; })).toEqual([expect.stringContaining(`unknown target "port"`)]);
  });
});
