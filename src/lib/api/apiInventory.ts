/**
 * API endpoint inventory: every HTTP endpoint the code declares, with where it is and what authentication
 * the code visibly applies to it -- Express/Koa/Fastify/Next.js, Flask/FastAPI, Spring, ASP.NET, Go
 * (net/http, gin, echo, chi) and Laravel.
 *
 * `auth` is what THIS file shows: "required" (a per-route middleware/decorator/annotation, or a file/class/
 * group-level one that covers the route), "public" (explicitly: [AllowAnonymous], @PermitAll,
 * security-neutral paths are NOT assumed public), or "none" (nothing visible -- auth may still be applied
 * globally elsewhere, e.g. Spring Security config or an app-wide middleware in another file).
 *
 * The finding (api-endpoint-missing-auth) is therefore deliberately about INCONSISTENCY, not absence: an
 * endpoint with no auth in a file whose convention is protected routes (most of its non-public endpoints
 * are) -- the forgotten-middleware bug. A read is only reported when the protected siblings include reads.
 */
import type { ScanIndicator } from "../scanner";
import { appsecHit } from "../appsecRules";

export type EndpointAuth = "required" | "public" | "none";

export interface ApiEndpoint {
  method: string;
  path: string;
  file: string;
  line: number;
  framework: string;
  auth: EndpointAuth;
  /** The middleware/decorator/annotation that decided `auth`. */
  authEvidence?: string;
}

/**
 * Is this identifier an authentication/authorization CHECK? Judged by its last segment's shape -- a check
 * verb or an auth noun at the end -- not by merely containing "auth": `security.isAuthorized`, `requireUser`,
 * `AuthRequired()`, `passport.authenticate`, `SetMiddlewareAuthentication` are checks;
 * `updateAuthenticatedUsers`, `authorName`, `oauthCallback` are not.
 */
const AUTH_LAST_SEGMENT_RE = /^(?:denyAll|deny|hasRole|hasAnyRole|hasPermission|hasScope|checkRole|checkPermissions?|roleRequired|is(?:Admin|Owner|Staff|Member|Manager|Accounting|Superuser)|auth|authn|authz|authenticated?|authorized?|isAuthenticated|isAuthorized|isLoggedIn|isAdmin|loggedIn|protect(?:ed|Route)?|checkJwt|jwtCheck|jwt|withAuth|clerkMiddleware|mustBeLoggedIn|ensure(?:LoggedIn|Authenticated|Auth\w*)|require[A-Z]\w*|verify(?:Token|Jwt|JWT|Session|User|Auth\w*)|(?:\w*?)(?:Auth|Authentication|Authorization|Authorized|Authenticated|Jwt|JWT|Guard)(?:Middleware|Required|Check|Handler|Guard)?|guard|authGuard)$/;

function authNameIn(text: string): string | null {
  for (const tok of text.match(/[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*/g) ?? []) {
    const last = tok.split(".").pop()!;
    if (AUTH_LAST_SEGMENT_RE.test(last)) return tok;
  }
  return null;
}
const AUTH_NAME_RE = { exec: (s: string): [string] | null => { const n = authNameIn(s); return n ? [n] : null; } };

/** The text between the `(` at `open` and its matching `)`, or null. Strings are skipped. */
function balancedArgs(src: string, open: number): string | null {
  let depth = 0;
  let q: string | null = null;
  for (let i = open; i < src.length && i < open + 20000; i++) {
    const c = src[i];
    if (q) { if (c === "\\") i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'" || c === "`") { q = c; continue; }
    if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return src.slice(open + 1, i);
  }
  return null;
}
/** Middleware arguments only: everything before an inline handler starts. */
function middlewareArgs(args: string): string {
  const cut = args.search(/\(\s*(?:req|request|ctx|c|_req)\b|\basync\b|\bfunction\b|=>/);
  return cut >= 0 ? args.slice(0, cut) : args;
}
/** An auth call inside a handler body (Next.js route handlers, API routes). */
const AUTH_CALL_RE = /\b(?:getServerSession|getSession|auth\(\)|currentUser\(|getToken\(|verifyApiKey\(|requireUser\(|requireAuth\(|supabase\.auth\.getUser|clerkClient|getAuth\(|validateRequest\(|verifyToken\(|jwt\.verify\(|withApiAuth|isAuthenticated\()/;
const PUBLIC_PATH_RE = /(?:^|\/)(?:login|logout|signin|sign-in|signup|sign-up|register|auth|oauth|callback|sso|saml|health|healthz|ready|readyz|live|status|ping|version|metrics|public|webhooks?|forgot|reset|verify|confirm|docs|swagger|openapi|favicon|robots|home|welcome|index)(?:\/|$|\.)/i;

const lineAt = (src: string, idx: number) => src.slice(0, idx).split("\n").length;

// ── JavaScript / TypeScript ──────────────────────────────────────────────────

function jsEndpoints(file: string, src: string): ApiEndpoint[] {
  const out: ApiEndpoint[] = [];
  // app.use(authMw) / router.use(requireUser) covers routes declared after it on that object;
  // app.use('/rest/basket', isAuthorized()) only those under that path prefix.
  const globalAuth: Array<{ obj: string; index: number; name: string; prefix: string }> = [];
  const USE_RE = /\b(\w+)\.use\(/g;
  let m: RegExpExecArray | null;
  while ((m = USE_RE.exec(src))) {
    const args = balancedArgs(src, m.index + m[0].length - 1);
    if (args == null) continue;
    const prefix = /^\s*(['"`])(\/[^'"`]*)\1\s*,/.exec(args);
    const a = AUTH_NAME_RE.exec(middlewareArgs(prefix ? args.slice(prefix[0].length) : args));
    if (a) globalAuth.push({ obj: m[1], index: m.index, name: a[0], prefix: prefix?.[2] ?? "" });
  }
  const ROUTE_RE = /\b(\w+)\.(get|post|put|patch|delete|all)\(\s*(['"`])(\/[^'"`]*)\3\s*,/g;
  while ((m = ROUTE_RE.exec(src))) {
    const [, obj, method, , routePath] = m;
    if (!/^(?:app|router|api|r|server|routes|route|fastify|instance|v\d|\w*[Rr]outer|\w*[Aa]pp)$/.test(obj)) continue;
    // A route declaration starts its own statement line; the same text inside a string or template literal
    // (sample code, docs, tests) sits mid-line and is not a route.
    if (!/^\s*(?:(?:export|await|return|void)\s+)?$/.test(src.slice(src.lastIndexOf("\n", m.index) + 1, m.index))) continue;
    const args = balancedArgs(src, m.index + m[0].indexOf("("));
    if (args == null) continue;
    const rest = args.slice(args.indexOf(",") + 1);
    const mw = middlewareArgs(rest);
    // Middleware by name; an inline handler by what it CALLS (reading a header named "authorization" is
    // not a check, calling req.isAuthenticated() / jwt.verify() is).
    const perRoute = AUTH_NAME_RE.exec(mw) ?? AUTH_CALL_RE.exec(rest.slice(mw.length));
    const covers = (prefix: string) => !prefix || routePath === prefix || routePath.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`) || /[*:]/.test(prefix) && routePath.startsWith(prefix.split(/[*:]/)[0]);
    const global = globalAuth.find(g => g.obj === obj && g.index < m!.index && covers(g.prefix));
    out.push({
      method: method.toUpperCase(), path: routePath, file, line: lineAt(src, m.index), framework: "express",
      auth: perRoute || global ? "required" : "none",
      authEvidence: perRoute?.[0] ?? (global ? `${global.obj}.use(${global.name})` : undefined),
    });
  }
  // Next.js App Router: app/**/route.ts exporting GET/POST/...
  const appRoute = /(?:^|\/)app\/(.*?)\/?route\.[jt]sx?$/.exec(file);
  if (appRoute) {
    const routePath = "/" + appRoute[1].split("/").filter(s => s && !/^\(.*\)$/.test(s)).map(s => s.replace(/^\[\.\.\.(\w+)\]$/, "*$1").replace(/^\[(\w+)\]$/, ":$1")).join("/");
    const EXPORT_RE = /export\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE)\b/g;
    const exportsAt: Array<{ method: string; index: number }> = [];
    while ((m = EXPORT_RE.exec(src))) exportsAt.push({ method: m[1], index: m.index });
    exportsAt.forEach((e, k) => {
      const body = src.slice(e.index, exportsAt[k + 1]?.index ?? src.length);
      const call = AUTH_CALL_RE.exec(body) ?? AUTH_NAME_RE.exec(body.slice(0, 400));
      out.push({ method: e.method, path: routePath, file, line: lineAt(src, e.index), framework: "nextjs", auth: call ? "required" : "none", authEvidence: call?.[0] });
    });
  }
  // Next.js Pages API: pages/api/**.ts default export.
  const pagesApi = /(?:^|\/)pages\/(api\/.*?)(?:\/index)?\.[jt]sx?$/.exec(file);
  if (pagesApi && /export\s+default/.test(src)) {
    const call = AUTH_CALL_RE.exec(src);
    const idx = src.search(/export\s+default/);
    out.push({ method: "ANY", path: "/" + pagesApi[1].replace(/\[(\w+)\]/g, ":$1"), file, line: lineAt(src, idx), framework: "nextjs", auth: call ? "required" : "none", authEvidence: call?.[0] });
  }
  return out;
}

// ── Python ───────────────────────────────────────────────────────────────────

function pyEndpoints(file: string, src: string): ApiEndpoint[] {
  const out: ApiEndpoint[] = [];
  const lines = src.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*@(\w+)\.(route|get|post|put|patch|delete|api_route)\(\s*['"]([^'"]*)['"]([^\n]*)/.exec(lines[i]);
    if (!m) continue;
    // The decorator stack this route belongs to, and the def it decorates.
    let j = i;
    while (j > 0 && /^\s*@/.test(lines[j - 1])) j--;
    let k = i;
    while (k < lines.length && !/^\s*(?:async\s+)?def\s/.test(lines[k])) k++;
    const decorators = lines.slice(j, k).join("\n");
    const signature = lines.slice(k, Math.min(lines.length, k + 6)).join("\n").split(/\)\s*(?:->[^:]*)?:/)[0];
    let methods = [m[2] === "route" || m[2] === "api_route" ? "GET" : m[2].toUpperCase()];
    const ms = /methods\s*=\s*\[([^\]]*)\]/.exec(m[4] + decorators);
    if (ms) methods = (ms[1].match(/['"](\w+)['"]/g) ?? []).map(x => x.replace(/['"]/g, "").toUpperCase());
    const dec = /@(?:\w+\.)?(login_required|jwt_required|token_required|auth_required|permission_required|roles_required|roles_accepted|admin_required|requires_auth|fresh_jwt_required|\w*auth\w*)\b/.exec(decorators);
    const dep = /Depends\(\s*(\w*(?:auth|user|token|oauth2|jwt|verify|security|session)\w*)/i.exec(signature + m[4]) ?? /Security\(\s*\w+/.exec(signature);
    const evidence = dec?.[0] ?? dep?.[0];
    for (const method of methods) {
      out.push({ method, path: m[3], file, line: i + 1, framework: m[2] === "route" ? "flask" : "fastapi", auth: evidence ? "required" : "none", authEvidence: evidence });
    }
  }
  return out;
}

// ── Java (Spring) ────────────────────────────────────────────────────────────

const SPRING_MAPPING_RE = /@(Get|Post|Put|Patch|Delete|Request)Mapping\s*(?:\(([^)]*)\))?/;

function javaEndpoints(file: string, src: string): ApiEndpoint[] {
  if (!/@(?:Rest)?Controller\b/.test(src)) return [];
  const out: ApiEndpoint[] = [];
  const lines = src.split("\n");
  const classIdx = lines.findIndex(l => /\bclass\s+\w+/.test(l));
  const classHeader = lines.slice(0, Math.max(0, classIdx + 1)).join("\n");
  const prefix = /@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?["']([^"']*)["']/.exec(classHeader)?.[1] ?? "";
  const classAuth = /@(PreAuthorize|Secured|RolesAllowed)\b/.exec(classHeader);
  const classPublic = /@PermitAll\b/.test(classHeader);
  for (let i = Math.max(0, classIdx + 1); i < lines.length; i++) {
    const m = SPRING_MAPPING_RE.exec(lines[i]);
    if (!m) continue;
    let j = i;
    while (j > 0 && /^\s*@|^\s*$/.test(lines[j - 1])) j--;
    let k = i;
    while (k < lines.length - 1 && /^\s*@/.test(lines[k + 1])) k++;
    const annotations = lines.slice(j, k + 1).join("\n");
    const args = m[2] ?? "";
    const p = /(?:value|path)?\s*=?\s*\{?\s*["']([^"']*)["']/.exec(args)?.[1] ?? "";
    const verb = m[1] === "Request" ? (/RequestMethod\.(\w+)/.exec(args)?.[1] ?? "ANY") : m[1].toUpperCase();
    const methodAuth = /@(PreAuthorize|Secured|RolesAllowed)\b/.exec(annotations);
    const isPublic = /@PermitAll\b/.test(annotations) || (classPublic && !methodAuth);
    const auth: EndpointAuth = methodAuth || (classAuth && !isPublic) ? "required" : isPublic ? "public" : "none";
    out.push({ method: verb, path: (prefix + (p ? (p.startsWith("/") ? p : `/${p}`) : "")) || "/", file, line: i + 1, framework: "spring", auth, authEvidence: (methodAuth ?? classAuth)?.[0] ?? (isPublic ? "@PermitAll" : undefined) });
  }
  return out;
}

// ── C# (ASP.NET Core) ────────────────────────────────────────────────────────

function csharpEndpoints(file: string, src: string): ApiEndpoint[] {
  const out: ApiEndpoint[] = [];
  const lines = src.split("\n");
  const classIdx = lines.findIndex(l => /\bclass\s+\w+/.test(l));
  if (classIdx >= 0) {
    const classHeader = lines.slice(Math.max(0, classIdx - 8), classIdx + 1).join("\n");
    if (!/ApiController|Controller\b|ControllerBase/.test(classHeader) && !/\[Http(?:Get|Post|Put|Patch|Delete)/.test(src)) return out;
    const prefix = (/\[Route\(\s*"([^"]*)"\s*\)\]/.exec(classHeader)?.[1] ?? "").replace("[controller]", (/class\s+(\w+?)Controller/.exec(classHeader)?.[1] ?? "").toLowerCase());
    const classAuth = /\[Authorize\b[^\]]*\]/.exec(classHeader);
    const classAnon = /\[AllowAnonymous\]/.test(classHeader);
    for (let i = classIdx + 1; i < lines.length; i++) {
      const m = /\[Http(Get|Post|Put|Patch|Delete)(?:\(\s*"([^"]*)"\s*\))?\]/.exec(lines[i]);
      if (!m) continue;
      let j = i;
      while (j > 0 && /^\s*\[/.test(lines[j - 1])) j--;
      let k = i;
      while (k < lines.length - 1 && /^\s*\[/.test(lines[k + 1])) k++;
      const attrs = lines.slice(j, k + 1).join("\n");
      const methodAuth = /\[Authorize\b[^\]]*\]/.exec(attrs);
      const anon = /\[AllowAnonymous\]/.test(attrs) || (classAnon && !methodAuth);
      const routePath = m[2]?.startsWith("/") || m[2]?.startsWith("~") ? m[2].replace(/^~/, "") : [prefix, m[2] ?? ""].filter(Boolean).join("/");
      out.push({ method: m[1].toUpperCase(), path: "/" + routePath.replace(/^\/+/, ""), file, line: i + 1, framework: "aspnet",
        auth: anon ? "public" : methodAuth || classAuth ? "required" : "none", authEvidence: anon ? "[AllowAnonymous]" : (methodAuth ?? classAuth)?.[0] });
    }
  }
  // Minimal APIs: app.MapGet("/x", ...).RequireAuthorization()
  const MAP_RE = /\b\w+\.Map(Get|Post|Put|Patch|Delete)\(\s*"([^"]*)"([\s\S]{0,300}?);/g;
  let m: RegExpExecArray | null;
  while ((m = MAP_RE.exec(src))) {
    const req = /RequireAuthorization\(/.exec(m[3]);
    const anon = /AllowAnonymous\(/.test(m[3]);
    out.push({ method: m[1].toUpperCase(), path: m[2], file, line: lineAt(src, m.index), framework: "aspnet", auth: anon ? "public" : req ? "required" : "none", authEvidence: anon ? "AllowAnonymous()" : req ? "RequireAuthorization()" : undefined });
  }
  return out;
}

// ── Go ───────────────────────────────────────────────────────────────────────

function goEndpoints(file: string, src: string): ApiEndpoint[] {
  const out: ApiEndpoint[] = [];
  // Groups/routers created with auth middleware, or given it via .Use(...).
  const authedObjs = new Map<string, string>();
  let m: RegExpExecArray | null;
  const GROUP_RE = /(\w+)\s*:?=\s*\w+\.Group\(\s*"[^"]*"\s*,([^)]*\))/g;
  while ((m = GROUP_RE.exec(src))) { const a = AUTH_NAME_RE.exec(m[2]); if (a) authedObjs.set(m[1], a[0]); }
  const USE_RE = /\b(\w+)\.Use\(([^)]*\))/g;
  while ((m = USE_RE.exec(src))) { const a = AUTH_NAME_RE.exec(m[2]); if (a) authedObjs.set(m[1], a[0]); }
  const ROUTE_RE = /\b(\w+)\.(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|HandleFunc|Handle)\(\s*"([^"]*)"\s*,([^\n]*)/g;
  while ((m = ROUTE_RE.exec(src))) {
    const [, obj, fn, routePath, rest] = m;
    const method = /^Handle/.test(fn) ? (/\.Methods\(\s*"(\w+)"/.exec(rest)?.[1] ?? "ANY") : fn.toUpperCase();
    const perRoute = AUTH_NAME_RE.exec(rest);
    const group = authedObjs.get(obj);
    out.push({ method, path: routePath, file, line: lineAt(src, m.index), framework: "go", auth: perRoute || group ? "required" : "none", authEvidence: perRoute?.[0] ?? group });
  }
  return out;
}

// ── PHP (Laravel) ────────────────────────────────────────────────────────────

function phpEndpoints(file: string, src: string): ApiEndpoint[] {
  const out: ApiEndpoint[] = [];
  // Route::middleware('auth')->group(function () { ... }) ranges.
  const authRanges: Array<{ start: number; end: number; name: string }> = [];
  const GROUP_RE = /Route::middleware\(\s*\[?([^\])]*)\]?\s*\)[^{]*\{/g;
  let m: RegExpExecArray | null;
  while ((m = GROUP_RE.exec(src))) {
    if (!/auth|sanctum|verified|can:|role/i.test(m[1])) continue;
    let depth = 0;
    let end = src.length;
    for (let i = m.index + m[0].length - 1; i < src.length; i++) {
      if (src[i] === "{") depth++;
      else if (src[i] === "}" && --depth === 0) { end = i; break; }
    }
    authRanges.push({ start: m.index, end, name: m[1].trim() });
  }
  const ROUTE_RE = /Route::(get|post|put|patch|delete|any|match)\(\s*(?:\[[^\]]*\]\s*,\s*)?['"]([^'"]*)['"]([^;]*);/g;
  while ((m = ROUTE_RE.exec(src))) {
    const perRoute = /->middleware\(\s*\[?\s*['"]([^'"]*(?:auth|sanctum|can:|role)[^'"]*)['"]/i.exec(m[3]);
    const group = authRanges.find(r => m!.index > r.start && m!.index < r.end);
    out.push({ method: m[1].toUpperCase(), path: m[2].startsWith("/") ? m[2] : `/${m[2]}`, file, line: lineAt(src, m.index), framework: "laravel",
      auth: perRoute || group ? "required" : "none", authEvidence: perRoute ? `middleware('${perRoute[1]}')` : group ? `middleware(${group.name})` : undefined });
  }
  return out;
}

/** Every endpoint `file` declares. */
export function extractEndpoints(file: string, content: string): ApiEndpoint[] {
  try {
    if (/\.(?:[cm]?[jt]sx?)$/i.test(file)) return jsEndpoints(file, content);
    if (/\.py$/i.test(file)) return pyEndpoints(file, content);
    if (/\.(?:java|kt)$/i.test(file)) return javaEndpoints(file, content);
    if (/\.cs$/i.test(file)) return csharpEndpoints(file, content);
    if (/\.go$/i.test(file)) return goEndpoints(file, content);
    if (/\.php$/i.test(file)) return phpEndpoints(file, content);
  } catch { /* an unparseable file declares nothing */ }
  return [];
}

const isWrite = (m: string) => m === "POST" || m === "PUT" || m === "PATCH" || m === "DELETE";

/** Endpoints with no auth whose siblings in the same file have it (see the module docblock). */
export function inconsistentAuth(endpoints: readonly ApiEndpoint[]): ApiEndpoint[] {
  const candidates = endpoints.filter(e => e.auth === "none" && !PUBLIC_PATH_RE.test(e.path));
  const protectedEps = endpoints.filter(e => e.auth === "required");
  // The file's convention must be "protected": at least two protected endpoints and more protected than
  // open ones. In a mostly-public route file (registration, feedback, catalogue), an open write is normal.
  if (protectedEps.length < 2 || protectedEps.length <= candidates.length) return [];
  const protectedReads = protectedEps.filter(e => !isWrite(e.method)).length;
  const openReads = candidates.filter(e => !isWrite(e.method)).length;
  // A read is only out of place when the protected siblings include reads too.
  return candidates.filter(e => isWrite(e.method) || (protectedReads >= 2 && protectedReads > openReads));
}

export function findEndpointMissingAuth(file: string, content: string): ScanIndicator[] {
  const eps = extractEndpoints(file, content);
  return inconsistentAuth(eps).map(e => {
    const sibling = eps.find(x => x.auth === "required" && x.authEvidence);
    return appsecHit("api-endpoint-missing-auth", e.line,
      `${e.method} ${e.path} has no authentication, while ${eps.filter(x => x.auth === "required").length} other endpoint(s) in this file use ${sibling?.authEvidence ?? "it"}.`,
      { confidence: 75, severity: isWrite(e.method) ? "high" : "medium" });
  });
}
