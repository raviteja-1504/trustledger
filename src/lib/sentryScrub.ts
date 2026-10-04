/**
 * Removes personal data and secrets from every Sentry event before it leaves the app (server, edge and browser).
 * TrustLedger handles customers' source code and security findings: Sentry gets stack traces, error codes and
 * trace/ref IDs — not emails, IP addresses, cookies, auth headers or tokens.
 */
import { redact } from "@/lib/logger";

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const DROP_HEADERS = /^(authorization|cookie|set-cookie|x-trustledger-key|x-hub-signature(-256)?|x-gitlab-token|x-api-key)$/i;

function scrubString(v: string): string {
  return (redact(v) as string).replace(EMAIL, "[email]");
}

function scrubDeep(value: unknown, depth = 0): unknown {
  if (typeof value === "string") return scrubString(value);
  if (depth > 8 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(v => scrubDeep(v, depth + 1));
  const red = redact(value) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(red)) out[k] = scrubDeep(v, depth + 1);
  return out;
}

// Structural type: works with the event objects of every Sentry runtime without importing @sentry here.
type AnyEvent = {
  user?: Record<string, unknown>;
  request?: { headers?: Record<string, string>; cookies?: unknown; data?: unknown; query_string?: unknown; url?: string };
  message?: string;
  exception?: { values?: Array<{ value?: string }> };
  breadcrumbs?: Array<{ message?: string; data?: unknown }>;
  extra?: Record<string, unknown>;
  contexts?: Record<string, unknown>;
  tags?: Record<string, unknown>;
};

export function scrubEvent<E>(event: E): E {
  const e = event as unknown as AnyEvent;
  // Who: an opaque id at most — never email, name or IP.
  if (e.user) e.user = e.user.id ? { id: String(e.user.id) } : {};
  if (e.request) {
    if (e.request.headers) {
      e.request.headers = Object.fromEntries(Object.entries(e.request.headers).filter(([k]) => !DROP_HEADERS.test(k)));
    }
    delete e.request.cookies;
    delete e.request.data;                       // request bodies can hold source code
    if (typeof e.request.query_string === "string") e.request.query_string = scrubString(e.request.query_string);
    if (e.request.url) e.request.url = scrubString(e.request.url);
  }
  if (e.message) e.message = scrubString(e.message);
  for (const ex of e.exception?.values ?? []) if (ex.value) ex.value = scrubString(ex.value);
  for (const b of e.breadcrumbs ?? []) {
    if (b.message) b.message = scrubString(b.message);
    if (b.data) b.data = scrubDeep(b.data);
  }
  if (e.extra) e.extra = scrubDeep(e.extra) as Record<string, unknown>;
  if (e.contexts) e.contexts = scrubDeep(e.contexts) as Record<string, unknown>;
  return event;
}

/** Settings shared by the server, edge and browser Sentry configs. */
export const sentryCommon = {
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  environment: process.env.NEXT_PUBLIC_VERCEL_ENV ?? process.env.VERCEL_ENV ?? process.env.NODE_ENV,
  release: process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA ?? process.env.VERCEL_GIT_COMMIT_SHA,
  sendDefaultPii: false,
  tracesSampleRate: process.env.NODE_ENV === "production" ? 0.1 : 1.0,
  initialScope: { tags: { product: "trustledger", component: "dashboard" } },
};
