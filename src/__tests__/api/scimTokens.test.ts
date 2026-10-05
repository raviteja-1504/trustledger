/**
 * @jest-environment node
 *
 * SCIM: each org has its own token (hash stored), the token decides the org, rotation/revocation take effect at
 * once, the old shared env token is gone, and SCIM can only provision addresses at the org's verified domains.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let role = "admin";
let orgId = "org-1";
const createUser = jest.fn();
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => ({ ...db.client, auth: { admin: { createUser: (a: unknown) => createUser(a) } } }) }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn(async () => {}) }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: orgId, user_id: "u-admin", actor_email: "a@acme.test", role }),
}));

import { GET as tokenGET, POST as tokenPOST, DELETE as tokenDELETE } from "@/app/api/scim-token/route";
import { GET as usersGET, POST as usersPOST } from "@/app/api/scim/v2/Users/route";
import { hashScimToken } from "@/lib/scimAuth";
import { redact } from "@/lib/logger";

const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const req = (url: string, method = "GET", body?: unknown, token?: string) =>
  new NextRequest(new URL(url, "https://app.example"), {
    method, headers: token ? { Authorization: `Bearer ${token}` } : {}, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
const newToken = async () => (await (await tokenPOST(req("/api/scim-token", "POST"))).json()).token as string;
const listUsers = async (token: string) => usersGET(req("/api/scim/v2/Users", "GET", undefined, token));

beforeEach(() => {
  jest.clearAllMocks();
  role = "admin"; orgId = "org-1";
  delete process.env.SCIM_TOKEN; delete process.env.SCIM_ORG_ID;
  db = fakeSupabase({
    scim_tokens: [],
    org_members: [
      { org_id: "org-1", user_id: "u-1", email: "one@acme.com", name: "One", role: "developer" },
      { org_id: "org-2", user_id: "u-2", email: "two@other.test", name: "Two", role: "developer" },
    ],
    sso_domains: [
      { org_id: "org-1", domain: "acme.com", verification_token: "t", verified_at: "2026-10-01T00:00:00Z" },
      { org_id: "org-1", domain: "acme.io", verification_token: "t", verified_at: null },
    ],
  });
  createUser.mockImplementation(async ({ email }: { email: string }) => ({ data: { user: { id: `auth-${email}` } }, error: null }));
});

describe("/api/scim-token", () => {
  it("creates a token shown once; only its hash and a short prefix are stored", async () => {
    const token = await newToken();
    expect(token).toMatch(/^tl_scim_[A-Za-z0-9_-]{40,}$/);
    expect(rows("scim_tokens")).toEqual([expect.objectContaining({ org_id: "org-1", token_hash: hashScimToken(token), token_prefix: token.slice(0, 14) })]);
    expect(JSON.stringify(rows("scim_tokens"))).not.toContain(token);
    const info = await (await tokenGET(req("/api/scim-token"))).json();
    expect(info).toMatchObject({ exists: true, prefix: token.slice(0, 14), verified_domains: ["acme.com"] });
    expect(JSON.stringify(info)).not.toContain(token);
  });

  it("is for built-in admins only", async () => {
    role = "security_reviewer";
    expect((await tokenPOST(req("/api/scim-token", "POST"))).status).toBe(403);
    expect((await tokenGET(req("/api/scim-token"))).status).toBe(403);
    expect(rows("scim_tokens")).toHaveLength(0);
  });

  it("rotating replaces the old token at once; revoking leaves none", async () => {
    const first = await newToken();
    const second = await newToken();
    expect(rows("scim_tokens")).toHaveLength(1);
    expect((await listUsers(first)).status).toBe(401);
    expect((await listUsers(second)).status).toBe(200);
    await tokenDELETE(req("/api/scim-token", "DELETE"));
    expect((await listUsers(second)).status).toBe(401);
  });
});

describe("SCIM requests", () => {
  it("the token decides the org: each org sees only its own people", async () => {
    const t1 = await newToken();
    orgId = "org-2";
    const t2 = await newToken();
    const users = async (t: string) => ((await (await listUsers(t)).json()).Resources as Array<{ userName: string }>).map(u => u.userName);
    expect(await users(t1)).toEqual(["one@acme.com"]);
    expect(await users(t2)).toEqual(["two@other.test"]);
  });

  it("the old shared environment token no longer works; malformed or unknown tokens are refused", async () => {
    process.env.SCIM_TOKEN = "legacy-env-token"; process.env.SCIM_ORG_ID = "org-1";
    expect((await listUsers("legacy-env-token")).status).toBe(401);
    expect((await listUsers("tl_scim_not-a-real-token")).status).toBe(401);
    expect((await usersGET(req("/api/scim/v2/Users"))).status).toBe(401);
  });

  it("provisions only addresses at the org's verified domains", async () => {
    const t = await newToken();
    const provision = (email: string) => usersPOST(req("/api/scim/v2/Users", "POST", { userName: email }, t));
    expect((await provision("new.person@acme.com")).status).toBe(201);
    expect(rows("org_members").find(m => m.email === "new.person@acme.com")).toMatchObject({ org_id: "org-1", role: "developer" });
    for (const email of ["ceo@othercorp.com", "x@acme.io", "x@sub.acme.com"]) {
      expect((await provision(email)).status).toBe(403);
    }
    expect(createUser).toHaveBeenCalledTimes(1);
  });

  it("SCIM tokens are redacted from logs", () => {
    expect(redact("Authorization: Bearer tl_scim_AbCdEfGhIjKlMnOpQrStUv123")).not.toContain("AbCdEfGhIjKlMnOp");
  });
});
