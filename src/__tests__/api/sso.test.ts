/**
 * @jest-environment node
 *
 * SAML SSO: domain ownership, which org an SSO identity may join (never by email alone), just-in-time
 * provisioning, "require SSO" enforcement, and the admin API that registers the IdP with Supabase Auth.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
const getUser = jest.fn();
const getUserById = jest.fn();
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({ ...db.client, auth: { getUser: (t: string) => getUser(t), admin: { getUserById: (id: string) => getUserById(id) } } }),
}));
const cacheDel = jest.fn(async (_k: string) => {});
jest.mock("@/lib/cache", () => ({ cached: async (_k: string, _t: number, fn: () => unknown) => fn(), cacheDel: (k: string) => cacheDel(k), cacheKeys: {} }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn(async () => {}) }));
const resolveTxt = jest.fn();
jest.mock("dns", () => ({ promises: { resolveTxt: (h: string) => resolveTxt(h) } }));

import { checkDomainTxt, domainClaimError, emailInDomains, normalizeDomain, verificationRecord } from "@/lib/ssoDomains";
import { getJwtSsoProviderId } from "@/lib/jwt";
import { resolveSsoMembership, ssoRequiredError } from "@/lib/ssoMembership";
import { metadataInputError, supabaseProjectRef } from "@/lib/supabaseSso";
import { ssoDomainOf } from "@/lib/authFlow";
import { verifyApiKey } from "@/app/api/_middleware";
import { POST as bootstrapPOST } from "@/app/api/auth/bootstrap/route";
import { GET as ssoGET, PUT as ssoPUT, DELETE as ssoDELETE } from "@/app/api/sso/route";
import { POST as domainPOST, PATCH as domainPATCH, DELETE as domainDELETE } from "@/app/api/sso/domains/route";

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const token = (payload: Record<string, unknown>) => `${b64({ alg: "HS256" })}.${b64(payload)}.sig`;
const ssoToken = (provider: string, session = "s-sso") => token({ session_id: session, amr: [{ method: "sso/saml", provider, timestamp: 1 }] });
const pwToken = (session = "s-pw") => token({ session_id: session, amr: [{ method: "password", timestamp: 1 }] });

const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const bearer = (t: string, url = "/api/x", method = "GET", body?: unknown) =>
  new NextRequest(new URL(url, "https://app.example"), { method, headers: { Authorization: `Bearer ${t}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });

const ACME_IDP = "prov-acme";
const EVIL_IDP = "prov-evil";

function world() {
  db = fakeSupabase({
    organizations: [{ id: "org-acme" }, { id: "org-evil" }],
    sso_connections: [
      { org_id: "org-acme", provider_id: ACME_IDP, jit_enabled: true, jit_role: "developer", enforce_sso: false },
      { org_id: "org-evil", provider_id: EVIL_IDP, jit_enabled: true, jit_role: "developer", enforce_sso: false },
    ],
    sso_domains: [
      { org_id: "org-acme", domain: "acme.com", verification_token: "t1", verified_at: "2026-10-01T00:00:00Z" },
      { org_id: "org-acme", domain: "acme.io", verification_token: "t2", verified_at: null },
      { org_id: "org-evil", domain: "evil.test", verification_token: "t3", verified_at: "2026-10-01T00:00:00Z" },
    ],
    org_members: [
      { id: "m-admin", org_id: "org-acme", user_id: "u-admin", email: "boss@acme.com", role: "admin", active_session_id: null },
      { id: "m-alice", org_id: "org-acme", user_id: "u-alice-pw", email: "alice@acme.com", role: "security_reviewer", active_session_id: "s-old" },
      { id: "m-invite", org_id: "org-acme", user_id: null, email: "newbie@acme.com", role: "security_reviewer", active_session_id: null },
    ],
    user_2fa: [],
  });
}

beforeEach(() => {
  jest.clearAllMocks();
  delete process.env.NEXT_PUBLIC_SKIP_AUTH;
  world();
});

describe("domains", () => {
  it("normalises and refuses what can't be owned", () => {
    expect(normalizeDomain(" https://Acme.COM/ ")).toBe("acme.com");
    expect(normalizeDomain("@acme.com")).toBe("acme.com");
    expect(normalizeDomain("not a domain")).toBeNull();
    expect(domainClaimError("gmail.com")).toBe("public_email_domain");
    expect(domainClaimError("acme")).toBe("invalid_domain");
    expect(domainClaimError("acme.com")).toBeNull();
  });

  it("matches an email to a domain exactly (a subdomain or look-alike is a different domain)", () => {
    expect(emailInDomains("Alice@ACME.com", ["acme.com"])).toBe(true);
    expect(emailInDomains("alice@eu.acme.com", ["acme.com"])).toBe(false);
    expect(emailInDomains("alice@acme.com.evil.test", ["acme.com"])).toBe(false);
    expect(emailInDomains(null, ["acme.com"])).toBe(false);
  });

  it("verifies by TXT record (joining split chunks; DNS errors count as not yet)", async () => {
    const { name, value } = verificationRecord("acme.com", "tok");
    expect(name).toBe("_trustledger-challenge.acme.com");
    expect(await checkDomainTxt("acme.com", "tok", async () => [["v=spf1"], [value.slice(0, 10), value.slice(10)]])).toBe(true);
    expect(await checkDomainTxt("acme.com", "tok", async () => [["trustledger-domain-verification=other"]])).toBe(false);
    expect(await checkDomainTxt("acme.com", "tok", async () => { throw new Error("ENOTFOUND"); })).toBe(false);
  });

  it("login page: work email → domain", () => {
    expect(ssoDomainOf(" Ann@Acme.com ")).toBe("acme.com");
    expect(ssoDomainOf("ann")).toBeNull();
  });
});

describe("session helpers", () => {
  it("reads the SSO provider from the session's amr claim only", () => {
    expect(getJwtSsoProviderId(ssoToken("p1"))).toBe("p1");
    expect(getJwtSsoProviderId(pwToken())).toBeNull();
    // GitHub sign-ins carry a provider too -- only the sso/saml method counts
    expect(getJwtSsoProviderId(token({ amr: [{ method: "oauth", provider: "github", timestamp: 1 }] }))).toBeNull();
    expect(getJwtSsoProviderId("garbage")).toBeNull();
  });

  it("SSO required: non-admins need a session from the org's own IdP; admins are exempt (break-glass)", () => {
    const enf = { enforce: true, provider_id: ACME_IDP };
    expect(ssoRequiredError(enf, "developer", null)).toBe("sso_required");
    expect(ssoRequiredError(enf, "developer", EVIL_IDP)).toBe("sso_required");
    expect(ssoRequiredError(enf, "developer", ACME_IDP)).toBeNull();
    expect(ssoRequiredError(enf, "admin", null)).toBeNull();
    expect(ssoRequiredError({ enforce: false, provider_id: ACME_IDP }, "developer", null)).toBeNull();
  });

  it("project ref and metadata checks", () => {
    process.env.NEXT_PUBLIC_SUPABASE_URL = "https://abcdefghijklmnopqrst.supabase.co";
    expect(supabaseProjectRef()).toBe("abcdefghijklmnopqrst");
    expect(metadataInputError({})).toMatch(/metadata/);
    expect(metadataInputError({ metadata_url: "http://idp.example/meta" })).toMatch(/https/);
    expect(metadataInputError({ metadata_xml: "<x/>" })).toMatch(/EntityDescriptor/);
    expect(metadataInputError({ metadata_url: "https://idp.example/meta" })).toBeNull();
  });
});

describe("which org an SSO identity joins", () => {
  const ssoUser = (id: string, email: string) => ({ id, email, user_metadata: { full_name: "Some One" } });

  it("just-in-time: a new person at a verified domain joins the IdP's org with the default role", async () => {
    expect(await resolveSsoMembership(db.client as never, ssoUser("u-new", "New.Person@acme.com"), ACME_IDP)).toEqual({ status: "member", org_id: "org-acme" });
    expect(rows("org_members").find(m => m.user_id === "u-new")).toMatchObject({ org_id: "org-acme", email: "new.person@acme.com", role: "developer", name: "Some One" });
  });

  it("claims their invite, keeping the invited role", async () => {
    await resolveSsoMembership(db.client as never, ssoUser("u-newbie", "newbie@acme.com"), ACME_IDP);
    expect(rows("org_members").find(m => m.id === "m-invite")).toMatchObject({ user_id: "u-newbie", role: "security_reviewer" });
    expect(rows("org_members").filter(m => m.email === "newbie@acme.com")).toHaveLength(1);
  });

  it("takes over their existing seat from the password account (role kept, old session dropped)", async () => {
    await resolveSsoMembership(db.client as never, ssoUser("u-alice-sso", "alice@acme.com"), ACME_IDP);
    expect(rows("org_members").find(m => m.id === "m-alice")).toMatchObject({ user_id: "u-alice-sso", role: "security_reviewer", active_session_id: null });
  });

  it("ANOTHER org's IdP asserting an acme.com address can't get into acme -- or touch Alice's seat", async () => {
    expect(await resolveSsoMembership(db.client as never, ssoUser("u-attacker", "alice@acme.com"), EVIL_IDP)).toEqual({ status: "sso_domain_mismatch" });
    expect(rows("org_members").find(m => m.id === "m-alice")!.user_id).toBe("u-alice-pw");
    expect(rows("org_members").some(m => m.user_id === "u-attacker")).toBe(false);
  });

  it("refuses emails at unverified domains, unknown providers, and turned-off JIT without an invite", async () => {
    expect((await resolveSsoMembership(db.client as never, ssoUser("u1", "bob@acme.io"), ACME_IDP)).status).toBe("sso_domain_mismatch");
    expect((await resolveSsoMembership(db.client as never, ssoUser("u1", "bob@acme.com"), "prov-gone")).status).toBe("sso_not_configured");
    rows("sso_connections")[0].jit_enabled = false;
    expect((await resolveSsoMembership(db.client as never, ssoUser("u1", "bob@acme.com"), ACME_IDP)).status).toBe("sso_not_invited");
    expect(rows("org_members").some(m => m.user_id === "u1")).toBe(false);
  });

  it("never claims an invite for the same address in a DIFFERENT org", async () => {
    rows("org_members").push({ id: "m-elsewhere", org_id: "org-evil", user_id: null, email: "bob@acme.com", role: "developer" });
    expect(await resolveSsoMembership(db.client as never, ssoUser("u-bob", "bob@acme.com"), ACME_IDP)).toEqual({ status: "member", org_id: "org-acme" });
    expect(rows("org_members").find(m => m.id === "m-elsewhere")!.user_id).toBeNull();
    expect(rows("org_members").find(m => m.user_id === "u-bob")).toMatchObject({ org_id: "org-acme" });
  });

  it("an identity already in another org stays there", async () => {
    rows("org_members").push({ id: "m-x", org_id: "org-evil", user_id: "u-x", email: "x@evil.test", role: "developer" });
    expect((await resolveSsoMembership(db.client as never, ssoUser("u-x", "x@acme.com"), ACME_IDP)).status).toBe("sso_other_org");
  });
});

describe("verifyApiKey with SSO", () => {
  it("an SSO session with no membership yet is provisioned and let in", async () => {
    getUser.mockResolvedValue({ data: { user: { id: "u-carol", email: "carol@acme.com", email_confirmed_at: "x" } }, error: null });
    expect(await verifyApiKey(bearer(ssoToken(ACME_IDP)))).toMatchObject({ org_id: "org-acme", user_id: "u-carol", role: "developer" });
  });

  it("an SSO identity never claims a seat by email -- even with a confirmed email", async () => {
    getUser.mockResolvedValue({ data: { user: { id: "u-attacker", email: "alice@acme.com", email_confirmed_at: "x" } }, error: null });
    expect((await verifyApiKey(bearer(ssoToken(EVIL_IDP)))).error).toBe("sso_domain_mismatch");
    expect(rows("org_members").find(m => m.id === "m-alice")!.user_id).toBe("u-alice-pw");
  });

  it("a password account claims an invite, but never a seat held by another live account", async () => {
    // Alice's seat now belongs to her SSO identity
    Object.assign(rows("org_members").find(m => m.id === "m-alice")!, { user_id: "u-alice-sso", active_session_id: null });
    getUser.mockResolvedValue({ data: { user: { id: "u-alice-pw", email: "alice@acme.com", email_confirmed_at: "x" } }, error: null });
    getUserById.mockResolvedValue({ data: { user: { id: "u-alice-sso" } }, error: null });
    expect((await verifyApiKey(bearer(pwToken()))).error).toBe("no_org_membership");
    expect(rows("org_members").find(m => m.id === "m-alice")!.user_id).toBe("u-alice-sso");

    // ...unless that account no longer exists (an older invite flow recorded a UID that was never used)
    getUserById.mockResolvedValue({ data: { user: null }, error: { message: "User not found", status: 404 } });
    expect(await verifyApiKey(bearer(pwToken()))).toMatchObject({ org_id: "org-acme", user_id: "u-alice-pw" });
  });

  it("require SSO: a developer's password session is refused; through the org's IdP, or as an admin, it's fine", async () => {
    rows("sso_connections")[0].enforce_sso = true;
    rows("org_members").push({ id: "m-dev", org_id: "org-acme", user_id: "u-dev", email: "dev@acme.com", role: "developer", active_session_id: null });
    getUser.mockResolvedValue({ data: { user: { id: "u-dev", email: "dev@acme.com" } }, error: null });
    expect((await verifyApiKey(bearer(pwToken()))).error).toBe("sso_required");
    expect((await verifyApiKey(bearer(ssoToken(EVIL_IDP)))).error).toBe("sso_required");
    expect(await verifyApiKey(bearer(ssoToken(ACME_IDP)))).toMatchObject({ org_id: "org-acme", user_id: "u-dev" });
    getUser.mockResolvedValue({ data: { user: { id: "u-admin", email: "boss@acme.com" } }, error: null });
    expect(await verifyApiKey(bearer(pwToken()))).toMatchObject({ org_id: "org-acme", role: "admin" });
  });
});

describe("bootstrap after an SSO sign-in", () => {
  it("joins the org, or says why not", async () => {
    getUser.mockResolvedValue({ data: { user: { id: "u-dana", email: "dana@acme.com" } }, error: null });
    expect(await (await bootstrapPOST(bearer(ssoToken(ACME_IDP), "/api/auth/bootstrap", "POST"))).json()).toMatchObject({ has_org: true, mfa_required: false });
    getUser.mockResolvedValue({ data: { user: { id: "u-eve", email: "eve@acme.com" } }, error: null });
    expect(await (await bootstrapPOST(bearer(ssoToken(EVIL_IDP), "/api/auth/bootstrap", "POST"))).json()).toMatchObject({ has_org: false, sso_status: "sso_domain_mismatch" });
  });
});

describe("/api/sso admin API", () => {
  const realFetch = global.fetch;
  let mgmt: jest.Mock;
  const asUser = (id: string, email: string) => getUser.mockResolvedValue({ data: { user: { id, email } }, error: null });

  beforeEach(() => {
    process.env.NEXT_PUBLIC_SUPABASE_URL = "https://abcdefghijklmnopqrst.supabase.co";
    process.env.SUPABASE_MANAGEMENT_TOKEN = "mgmt-test";
    mgmt = jest.fn(async (_url: string, init?: RequestInit) => new Response(JSON.stringify({
      id: "prov-new", saml: { entity_id: "https://idp.acme.com" }, domains: (JSON.parse(String(init?.body ?? "{}")).domains ?? []).map((d: string) => ({ domain: d })),
    }), { status: init?.method === "POST" ? 201 : 200 }));
    global.fetch = mgmt as unknown as typeof fetch;
    // acme starts without an IdP
    rows("sso_connections").splice(0, 1);
    asUser("u-admin", "boss@acme.com");
  });
  afterEach(() => { global.fetch = realFetch; delete process.env.SUPABASE_MANAGEMENT_TOKEN; });

  const put = (body: unknown) => ssoPUT(bearer(pwToken(), "/api/sso", "PUT", body));

  it("is for built-in admins only", async () => {
    asUser("u-alice-pw", "alice@acme.com");   // a security reviewer, in her current session
    expect((await ssoGET(bearer(pwToken("s-old"), "/api/sso"))).status).toBe(403);
    expect((await ssoPUT(bearer(pwToken("s-old"), "/api/sso", "PUT", { enforce_sso: true }))).status).toBe(403);
    expect((await domainPOST(bearer(pwToken("s-old"), "/api/sso/domains", "POST", { domain: "acme.net" }))).status).toBe(403);
  });

  it("shows what to enter in the IdP, and the domain records", async () => {
    const body = await (await ssoGET(bearer(pwToken(), "/api/sso"))).json();
    expect(body.sp.acs_url).toBe("https://abcdefghijklmnopqrst.supabase.co/auth/v1/sso/saml/acs");
    expect(body.availability).toEqual({ available: true });
    expect(body.domains.find((d: { domain: string }) => d.domain === "acme.io")).toMatchObject({ verified: false, record: { name: "_trustledger-challenge.acme.io" } });
  });

  it("registers the IdP with Supabase for the org's VERIFIED domains only", async () => {
    const res = await put({ metadata_url: "https://idp.acme.com/metadata" });
    expect(res.status).toBe(200);
    const [url, init] = mgmt.mock.calls[0];
    expect(url).toBe("https://api.supabase.com/v1/projects/abcdefghijklmnopqrst/config/auth/sso/providers");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer mgmt-test");
    expect(JSON.parse(init.body)).toEqual({ type: "saml", metadata_url: "https://idp.acme.com/metadata", domains: ["acme.com"] });
    expect(rows("sso_connections").find(c => c.org_id === "org-acme")).toMatchObject({ provider_id: "prov-new", idp_entity_id: "https://idp.acme.com" });

    // saving again updates the same provider (PUT), not a second one
    await put({ metadata_url: "https://idp.acme.com/metadata2" });
    expect(mgmt.mock.calls[1][0]).toMatch(/\/providers\/prov-new$/);
    expect(mgmt.mock.calls[1][1].method).toBe("PUT");
    expect(rows("sso_connections").filter(c => c.org_id === "org-acme")).toHaveLength(1);
  });

  it("needs a verified domain first, https metadata, and a deployment with the management token", async () => {
    rows("sso_domains").forEach(d => { if (d.org_id === "org-acme") d.verified_at = null; });
    expect((await put({ metadata_url: "https://idp.acme.com/metadata" })).status).toBe(422);
    rows("sso_domains")[0].verified_at = "2026-10-01T00:00:00Z";
    expect((await put({ metadata_url: "http://idp.acme.com/metadata" })).status).toBe(400);
    delete process.env.SUPABASE_MANAGEMENT_TOKEN;
    expect((await put({ metadata_url: "https://idp.acme.com/metadata" })).status).toBe(422);
    expect(mgmt).not.toHaveBeenCalled();
  });

  it("explains a Supabase plan without SAML", async () => {
    mgmt.mockResolvedValueOnce(new Response(JSON.stringify({ message: "SAML SSO is not available on your plan" }), { status: 403 }));
    const res = await put({ metadata_url: "https://idp.acme.com/metadata" });
    expect(res.status).toBe(502);
    expect((await res.json()).error).toBe("sso_not_on_plan");
  });

  it("JIT role can't be admin; SSO can't be required before an IdP is connected", async () => {
    expect((await put({ jit_role: "admin" })).status).toBe(400);
    expect((await put({ enforce_sso: true })).status).toBe(422);
    await put({ metadata_url: "https://idp.acme.com/metadata" });
    expect((await put({ enforce_sso: true, jit_role: "security_reviewer" })).status).toBe(200);
    expect(rows("sso_connections").find(c => c.org_id === "org-acme")).toMatchObject({ enforce_sso: true, jit_role: "security_reviewer" });
    expect(cacheDel).toHaveBeenCalledWith("sso:enforce:org-acme");
  });

  it("domains: no public mail domains, no domain another org verified, DNS proof required", async () => {
    expect((await domainPOST(bearer(pwToken(), "/api/sso/domains", "POST", { domain: "gmail.com" }))).status).toBe(400);
    expect((await domainPOST(bearer(pwToken(), "/api/sso/domains", "POST", { domain: "evil.test" }))).status).toBe(409);
    const added = await domainPOST(bearer(pwToken(), "/api/sso/domains", "POST", { domain: "Acme.Net" }));
    expect(added.status).toBe(201);
    const { record } = await added.json();

    resolveTxt.mockResolvedValue([["something-else"]]);
    expect(await (await domainPATCH(bearer(pwToken(), "/api/sso/domains", "PATCH", { domain: "acme.net" }))).json()).toMatchObject({ verified: false });
    expect(rows("sso_domains").find(d => d.domain === "acme.net")!.verified_at).toBeFalsy();

    resolveTxt.mockImplementation(async (host: string) => host === record.name ? [[record.value]] : []);
    expect(await (await domainPATCH(bearer(pwToken(), "/api/sso/domains", "PATCH", { domain: "acme.net" }))).json()).toMatchObject({ verified: true });
    expect(rows("sso_domains").find(d => d.domain === "acme.net")!.verified_at).toBeTruthy();
  });

  it("verifying a domain adds it to the registered IdP; removing the last one turns enforcement off", async () => {
    await put({ metadata_url: "https://idp.acme.com/metadata" });
    await put({ enforce_sso: true });
    const t2 = rows("sso_domains").find(d => d.domain === "acme.io")!;
    resolveTxt.mockResolvedValue([[verificationRecord("acme.io", String(t2.verification_token)).value]]);
    await domainPATCH(bearer(pwToken(), "/api/sso/domains", "PATCH", { domain: "acme.io" }));
    const last = mgmt.mock.calls[mgmt.mock.calls.length - 1];
    expect(JSON.parse(last[1].body)).toEqual({ domains: ["acme.com", "acme.io"] });

    await domainDELETE(bearer(pwToken(), "/api/sso/domains?domain=acme.com", "DELETE"));
    await domainDELETE(bearer(pwToken(), "/api/sso/domains?domain=acme.io", "DELETE"));
    expect(rows("sso_connections").find(c => c.org_id === "org-acme")!.enforce_sso).toBe(false);
  });

  it("disconnecting removes the provider from Supabase and the connection", async () => {
    await put({ metadata_url: "https://idp.acme.com/metadata" });
    expect((await ssoDELETE(bearer(pwToken(), "/api/sso", "DELETE"))).status).toBe(200);
    const last = mgmt.mock.calls[mgmt.mock.calls.length - 1];
    expect(last[0]).toMatch(/\/providers\/prov-new$/);
    expect(last[1].method).toBe("DELETE");
    expect(rows("sso_connections").some(c => c.org_id === "org-acme")).toBe(false);
  });
});
