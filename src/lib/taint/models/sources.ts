/**
 * Source models: where untrusted data enters, with what kind of input it is and how far it is trusted (Universal
 * Taint Model, docs/taint/utm-gap-report.md §6.2). Each entry names the languages whose engine uses it; an engine
 * reads its sets from here (sourceNames) instead of keeping its own copy.
 *
 * Migrated so far: the JVM (Java and Kotlin), which kept two copies of the same Servlet and Spring sources.
 * `langs` records exactly what each engine used before the move, so detection is unchanged; where the model shows
 * a language missing an API it could use (Java lacks getParts and the WebFlux functional API), enabling it is a
 * separate, reviewed change.
 */
import type { ModelLang } from "./types";

export type SourceKind =
  | "http.query" | "http.path" | "http.header" | "http.cookie" | "http.body" | "file.upload"
  | "identity" | "env" | "cli" | "stdin" | "network" | "queue" | "db.read" | "session" | "deserialized";

/** How an engine recognises the source: a method called on the request, a property read on it, or a parameter
 * annotation that binds request data to the parameter. */
export type SourceMatchKind = "request-call" | "request-property" | "param-annotation";

export interface SourceModel {
  id: string;
  langs: ModelLang[];
  framework: string;
  kind: SourceKind;
  /** `semi-trusted`: authenticated or server-derived (the logged-in user's name), not freely chosen by the client. */
  trust: "untrusted" | "semi-trusted";
  match: { kind: SourceMatchKind; name: string };
}

const JVM: ModelLang[] = ["java", "kt"];
const KT: ModelLang[] = ["kt"];
const src = (langs: ModelLang[], framework: string, kind: SourceKind, matchKind: SourceMatchKind, names: string[], trust: SourceModel["trust"] = "untrusted"): SourceModel[] =>
  names.map(name => ({ id: `${langs.join("+")}:${framework}:${matchKind}:${name}`, langs, framework, kind, trust, match: { kind: matchKind, name } }));

export const SOURCE_MODELS: readonly SourceModel[] = [
  // Spring MVC / JAX-RS: parameters bound to request data
  ...src(JVM, "spring", "http.query", "param-annotation", ["RequestParam", "QueryParam"]),
  ...src(JVM, "spring", "http.path", "param-annotation", ["PathVariable", "PathParam", "MatrixVariable", "MatrixParam"]),
  ...src(JVM, "spring", "http.header", "param-annotation", ["RequestHeader", "HeaderParam"]),
  ...src(JVM, "spring", "http.cookie", "param-annotation", ["CookieValue", "CookieParam"]),
  ...src(JVM, "spring", "http.body", "param-annotation", ["RequestBody", "FormParam", "ModelAttribute", "BeanParam", "RequestPart"]),

  // Servlet API: methods on the request
  ...src(JVM, "servlet", "http.query", "request-call", ["getParameter", "getParameterValues", "getParameterMap", "getParameterNames", "getQueryString"]),
  ...src(JVM, "servlet", "http.header", "request-call", ["getHeader", "getHeaders"]),
  ...src(JVM, "servlet", "http.cookie", "request-call", ["getCookies"]),
  ...src(JVM, "servlet", "http.body", "request-call", ["getInputStream", "getReader"]),
  ...src(JVM, "servlet", "file.upload", "request-call", ["getPart"]),
  ...src(JVM, "servlet", "http.path", "request-call", ["getPathInfo", "getRequestURI", "getRequestURL"]),
  ...src(KT, "servlet", "file.upload", "request-call", ["getParts"]),
  ...src(KT, "servlet", "identity", "request-call", ["getRemoteUser"], "semi-trusted"),

  // Spring WebFlux functional endpoints (ServerRequest)
  ...src(KT, "webflux", "http.query", "request-call", ["queryParam", "queryParams"]),
  ...src(KT, "webflux", "http.path", "request-call", ["pathVariable", "pathVariables"]),
  ...src(KT, "webflux", "http.body", "request-call", ["bodyToMono", "bodyToFlux", "awaitBody", "awaitBodyOrNull", "formData", "awaitFormData", "multipartData", "awaitMultipartData"]),

  // Kotlin property syntax on the Servlet request (request.queryString, request.parameterMap, ...)
  ...src(KT, "servlet", "http.query", "request-property", ["queryString", "parameterMap", "parameterNames", "queryParams"]),
  ...src(KT, "servlet", "http.header", "request-property", ["headers", "headerNames"]),
  ...src(KT, "servlet", "http.cookie", "request-property", ["cookies"]),
  ...src(KT, "servlet", "http.body", "request-property", ["body", "inputStream", "reader"]),
  ...src(KT, "servlet", "file.upload", "request-property", ["parts"]),
  ...src(KT, "servlet", "http.path", "request-property", ["pathInfo", "requestURI", "requestURL", "uri"]),
];

/** The names an engine matches for one kind of source, in one language. */
export function sourceNames(lang: ModelLang, kind: SourceMatchKind): Set<string> {
  return new Set(SOURCE_MODELS.filter(s => s.langs.includes(lang) && s.match.kind === kind).map(s => s.match.name));
}
