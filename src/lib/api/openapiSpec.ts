/**
 * API security from OpenAPI 3.x / Swagger 2.0 specs in the repo: operations that declare no authentication,
 * plain-HTTP servers, weak security schemes (HTTP Basic, API keys in the query string, the OAuth implicit
 * flow), and credentials passed as query parameters.
 *
 * An operation with `security: []` is declared public on purpose and is not reported. A spec that declares
 * no authentication anywhere is reported ONCE (at `paths`), not once per operation.
 */
import type { ScanIndicator } from "../scanner";
import { appsecHit } from "../appsecRules";
import { parseConfigDocuments, get, path, str, items, strings, entries, entryLine, type CNode } from "../iac/configTree";

const METHODS = ["get", "put", "post", "delete", "patch", "options", "head", "trace"];
const WRITE_METHODS = new Set(["put", "post", "delete", "patch"]);
const SENSITIVE_PARAM_RE = /^(?:password|passwd|pwd|pass|secret|client_secret|token|access_token|refresh_token|id_token|api_?key|apikey|auth|authorization|session_?id|private_key|otp|pin|ssn|credit_?card|card_?number|cvv)$/i;
const LOCAL_HOST_RE = /^https?:\/\/(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|[^/]*\.local|[^/]*\.internal|\{[^}]+\})(?::\d+)?(?:\/|$)/i;

export function isOpenApiDoc(doc: CNode | undefined): boolean {
  const v = str(get(doc, "openapi")) ?? str(get(doc, "swagger"));
  return !!v && /^[23]\./.test(v) && !!get(doc, "paths");
}

/** Does a security requirement list require anything? [] or [{}] require nothing. */
function requiresAuth(sec: CNode | undefined): boolean {
  return items(sec).some(req => req.kind === "map" && req.entries.length > 0);
}

export interface SpecOperation { method: string; path: string; line: number; secured: boolean; explicitPublic: boolean }

export function specOperations(doc: CNode): SpecOperation[] {
  const globalSec = get(doc, "security");
  const out: SpecOperation[] = [];
  for (const p of entries(get(doc, "paths"))) {
    for (const op of entries(p.node)) {
      if (!METHODS.includes(op.key.toLowerCase())) continue;
      const opSec = get(op.node, "security");
      const explicitPublic = !!opSec && !requiresAuth(opSec);
      const secured = opSec ? requiresAuth(opSec) : requiresAuth(globalSec);
      out.push({ method: op.key.toUpperCase(), path: p.key, line: op.line, secured, explicitPublic });
    }
  }
  return out;
}

export function scanOpenApiSpec(content: string): ScanIndicator[] {
  const out: ScanIndicator[] = [];
  for (const doc of parseConfigDocuments(content)) {
    if (!isOpenApiDoc(doc)) continue;
    const schemes = [...entries(path(doc, "components", "securitySchemes")), ...entries(get(doc, "securityDefinitions"))];

    const ops = specOperations(doc);
    const unsecured = ops.filter(o => !o.secured && !o.explicitPublic && o.method !== "OPTIONS" && o.method !== "HEAD");
    const anyAuth = schemes.length > 0 || ops.some(o => o.secured);
    if (!anyAuth && unsecured.length > 0) {
      const writes = unsecured.filter(o => WRITE_METHODS.has(o.method.toLowerCase())).length;
      out.push(appsecHit("api-spec-unauthenticated-operation", entryLine(doc, "paths") ?? 1,
        `The spec declares no authentication at all: none of its ${unsecured.length} operations (${writes} of them state-changing) require credentials.`,
        { confidence: 70, severity: writes ? "high" : "medium" }));
    } else {
      for (const o of unsecured.slice(0, 50)) {
        const write = WRITE_METHODS.has(o.method.toLowerCase());
        out.push(appsecHit("api-spec-unauthenticated-operation", o.line,
          `${o.method} ${o.path} has no security requirement, while the spec defines authentication for others.`,
          { confidence: 80, severity: write ? "high" : "medium" }));
      }
    }

    for (const s of items(get(doc, "servers"))) {
      const url = str(get(s, "url")) ?? "";
      if (/^http:\/\//i.test(url) && !LOCAL_HOST_RE.test(url)) out.push(appsecHit("api-spec-insecure-server", entryLine(s, "url") ?? s.line, `Server ${url} uses plain HTTP.`, { confidence: 90 }));
    }
    const swaggerSchemes = strings(get(doc, "schemes"));
    const host = str(get(doc, "host")) ?? "";
    if (swaggerSchemes.includes("http") && !/^(?:localhost|127\.|0\.0\.0\.0)/.test(host)) {
      out.push(appsecHit("api-spec-insecure-server", entryLine(doc, "schemes") ?? 1, `The API is offered over plain HTTP${host ? ` at ${host}` : ""}.`, { confidence: 85 }));
    }

    for (const sch of schemes) {
      const type = (str(get(sch.node, "type")) ?? "").toLowerCase();
      const scheme = (str(get(sch.node, "scheme")) ?? "").toLowerCase();
      if (type === "basic" || (type === "http" && scheme === "basic")) {
        out.push(appsecHit("api-spec-basic-auth", sch.line, `Security scheme '${sch.key}' is HTTP Basic.`, { confidence: 90 }));
      }
      if (type === "apikey" && (str(get(sch.node, "in")) ?? "").toLowerCase() === "query") {
        out.push(appsecHit("api-spec-key-in-query", entryLine(sch.node, "in") ?? sch.line, `Security scheme '${sch.key}' sends the key as query parameter '${str(get(sch.node, "name")) ?? "?"}'.`, { confidence: 95 }));
      }
      if (type === "oauth2" && (get(get(sch.node, "flows"), "implicit") || str(get(sch.node, "flow")) === "implicit")) {
        out.push(appsecHit("api-spec-oauth-implicit", sch.line, `Security scheme '${sch.key}' uses the OAuth2 implicit flow.`, { confidence: 90 }));
      }
    }

    const seen = new Set<string>();
    const checkParams = (params: CNode | undefined, where: string) => {
      for (const prm of items(params)) {
        const name = str(get(prm, "name")) ?? "";
        if ((str(get(prm, "in")) ?? "") !== "query" || !SENSITIVE_PARAM_RE.test(name)) continue;
        const key = `${prm.line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(appsecHit("api-spec-sensitive-query-param", prm.line, `${where} takes '${name}' as a query parameter.`, { confidence: 85 }));
      }
    };
    for (const p of entries(get(doc, "paths"))) {
      checkParams(get(p.node, "parameters"), p.key);
      for (const op of entries(p.node)) if (METHODS.includes(op.key.toLowerCase())) checkParams(get(op.node, "parameters"), `${op.key.toUpperCase()} ${p.key}`);
    }
    for (const prm of entries(path(doc, "components", "parameters"))) checkParams({ kind: "seq", line: prm.line, items: [prm.node] }, `Parameter '${prm.key}'`);
  }
  return out;
}
