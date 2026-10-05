/**
 * SAML identity providers are registered with Supabase Auth (which validates the SAML assertions -- we never
 * parse SAML ourselves) through the Supabase Management API:
 *   POST/GET/PUT/DELETE https://api.supabase.com/v1/projects/{ref}/config/auth/sso/providers[/{id}]
 *
 * Needs, on the server only:
 *   SUPABASE_MANAGEMENT_TOKEN  -- a Supabase access token (or fine-grained token with auth_config_write)
 *   NEXT_PUBLIC_SUPABASE_URL   -- https://<ref>.supabase.co (or SUPABASE_PROJECT_REF for a custom domain)
 * and a Supabase plan with SAML SSO (Pro or above), with SAML 2.0 enabled under Auth → Providers.
 */

const MANAGEMENT_API = "https://api.supabase.com";

export function supabaseProjectRef(): string | null {
  if (process.env.SUPABASE_PROJECT_REF) return process.env.SUPABASE_PROJECT_REF;
  try {
    const host = new URL(process.env.NEXT_PUBLIC_SUPABASE_URL ?? "").hostname;
    const m = /^([a-z0-9]{20})\.supabase\.co$/.exec(host);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

export type SsoAvailability = { available: true } | { available: false; reason: "management_token_missing" | "project_ref_unknown" };

export function ssoAvailability(): SsoAvailability {
  if (!process.env.SUPABASE_MANAGEMENT_TOKEN) return { available: false, reason: "management_token_missing" };
  if (!supabaseProjectRef()) return { available: false, reason: "project_ref_unknown" };
  return { available: true };
}

/** What the customer enters in their IdP (Supabase is the SAML service provider). */
export function serviceProviderDetails(): { entity_id: string; acs_url: string; metadata_url: string } | null {
  const base = (process.env.NEXT_PUBLIC_SUPABASE_URL ?? "").replace(/\/+$/, "");
  if (!base) return null;
  return {
    entity_id:    `${base}/auth/v1/sso/saml/metadata`,
    metadata_url: `${base}/auth/v1/sso/saml/metadata?download=true`,
    acs_url:      `${base}/auth/v1/sso/saml/acs`,
  };
}

export class SsoProviderError extends Error {
  constructor(public code: "sso_not_on_plan" | "sso_management_unauthorized" | "sso_invalid_metadata" | "sso_provider_not_found" | "sso_provider_failed",
              message: string, public status?: number) {
    super(message);
  }
}

export interface SsoProviderInput {
  metadata_url?: string;
  metadata_xml?: string;
  domains: string[];
}

export interface SsoProvider { id: string; entity_id: string | null; domains: string[] }

async function call(method: string, path: string, body?: unknown): Promise<unknown> {
  const ref = supabaseProjectRef();
  const token = process.env.SUPABASE_MANAGEMENT_TOKEN;
  if (!ref || !token) throw new SsoProviderError("sso_management_unauthorized", "SSO isn't configured on this deployment.");
  const res = await fetch(`${MANAGEMENT_API}/v1/projects/${ref}/config/auth/sso/providers${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  const text = await res.text();
  let json: unknown = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON error page */ }
  if (res.ok) return json;

  const detail = String((json as { message?: string; msg?: string } | null)?.message ?? (json as { msg?: string } | null)?.msg ?? text).slice(0, 300);
  if (res.status === 401 || res.status === 403) {
    // 403 is also how Supabase answers on a plan without SAML.
    const onPlan = /plan|upgrade|not available|saml.*disabled|enable saml/i.test(detail);
    throw new SsoProviderError(onPlan ? "sso_not_on_plan" : "sso_management_unauthorized", detail, res.status);
  }
  if (res.status === 402) throw new SsoProviderError("sso_not_on_plan", detail, res.status);
  if (res.status === 404) throw new SsoProviderError("sso_provider_not_found", detail, res.status);
  if (res.status === 400 || res.status === 422) throw new SsoProviderError("sso_invalid_metadata", detail, res.status);
  throw new SsoProviderError("sso_provider_failed", detail, res.status);
}

function toProvider(raw: unknown): SsoProvider {
  const r = raw as { id: string; saml?: { entity_id?: string }; domains?: Array<{ domain: string }> };
  return { id: r.id, entity_id: r.saml?.entity_id ?? null, domains: (r.domains ?? []).map(d => d.domain) };
}

function body(input: SsoProviderInput) {
  return {
    ...(input.metadata_url ? { metadata_url: input.metadata_url } : {}),
    ...(input.metadata_xml ? { metadata_xml: input.metadata_xml } : {}),
    domains: input.domains,
  };
}

export async function createSsoProvider(input: SsoProviderInput): Promise<SsoProvider> {
  return toProvider(await call("POST", "", { type: "saml", ...body(input) }));
}

export async function updateSsoProvider(id: string, input: SsoProviderInput): Promise<SsoProvider> {
  return toProvider(await call("PUT", `/${encodeURIComponent(id)}`, body(input)));
}

/** Only the domains change (a domain was verified or removed); the IdP metadata stays as registered. */
export async function setSsoProviderDomains(id: string, domains: string[]): Promise<SsoProvider> {
  return toProvider(await call("PUT", `/${encodeURIComponent(id)}`, { domains }));
}

export async function deleteSsoProvider(id: string): Promise<void> {
  try {
    await call("DELETE", `/${encodeURIComponent(id)}`);
  } catch (e) {
    if (e instanceof SsoProviderError && e.code === "sso_provider_not_found") return;   // already gone
    throw e;
  }
}

/** Light checks before sending metadata to Supabase (which does the real validation). */
export function metadataInputError(input: { metadata_url?: string; metadata_xml?: string }): string | null {
  if (!input.metadata_url && !input.metadata_xml) return "Provide the IdP metadata URL or paste its metadata XML.";
  if (input.metadata_url && input.metadata_xml) return "Provide either a metadata URL or metadata XML, not both.";
  if (input.metadata_url) {
    let u: URL;
    try { u = new URL(input.metadata_url); } catch { return "The metadata URL isn't a valid URL."; }
    if (u.protocol !== "https:") return "The metadata URL must use https.";
  }
  if (input.metadata_xml) {
    if (input.metadata_xml.length > 200_000) return "That metadata XML is too large.";
    if (!/EntityDescriptor/.test(input.metadata_xml)) return "That doesn't look like SAML metadata (no EntityDescriptor).";
  }
  return null;
}
