/**
 * @jest-environment node
 *
 * A GitHub organisation belongs to one TrustLedger organisation (its pull requests are routed by that handle): saving a
 * handle another organisation already holds is refused with a clear error, not lost quietly.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", role: "admin" }),
}));

import { POST } from "@/app/api/onboarding/route";

const save = async (github_org: string) => {
  const res = await POST(new NextRequest(new URL("/api/onboarding", "https://app.example"), { method: "POST", body: JSON.stringify({ action: "save_github_org", github_org }) }));
  return { status: res.status, body: await res.json() };
};
const handleOf = async (id: string) => ((await db.client.from("organizations").select("github_org").eq("id", id).single()) as unknown as { data: { github_org: string | null } }).data.github_org;

beforeEach(() => {
  db = fakeSupabase({ organizations: [{ id: "org-1", github_org: null }, { id: "org-2", github_org: "taken-corp" }] });
});

describe("POST /api/onboarding save_github_org", () => {
  it("links a free handle to the caller's organisation", async () => {
    expect((await save("acme-corp")).status).toBe(200);
    expect(await handleOf("org-1")).toBe("acme-corp");
  });
  it("refuses a handle another organisation already holds, and changes nothing", async () => {
    const r = await save("taken-corp");
    expect(r).toEqual({ status: 409, body: { error: "github_org_taken" } });
    expect(await handleOf("org-1")).toBeNull();
    expect(await handleOf("org-2")).toBe("taken-corp");
  });
  it("saving the organisation's own handle again is fine", async () => {
    await save("acme-corp");
    expect((await save("acme-corp")).status).toBe(200);
  });
  it("a missing handle is a 400", async () => {
    expect((await save("  ")).status).toBe(400);
  });
});

describe("POST /api/onboarding save_github_org: what people actually type", () => {
  it("a pasted repository address is saved as its owner, in lower case", async () => {
    expect((await save("https://github.com/Acme-Corp/payments-api")).status).toBe(200);
    expect(await handleOf("org-1")).toBe("acme-corp");
  });
  it("@name and owner/repo are accepted", async () => {
    await save("@Acme-Corp");
    expect(await handleOf("org-1")).toBe("acme-corp");
    await save("acme-corp/payments-api");
    expect(await handleOf("org-1")).toBe("acme-corp");
  });
  it("an email address is refused with a message, and nothing is saved", async () => {
    const r = await save("me@example.com");
    expect(r.status).toBe(400);
    expect(r.body).toMatchObject({ error: "github_org_invalid", message: expect.stringMatching(/email address/i) });
    expect(await handleOf("org-1")).toBeNull();
  });
  it("a name GitHub would not allow is refused", async () => {
    expect((await save("acme corp")).status).toBe(400);
    expect(await handleOf("org-1")).toBeNull();
  });
  it("a handle another organisation holds is 'taken' whatever the capitals", async () => {
    expect((await save("TAKEN-Corp")).body).toEqual({ error: "github_org_taken" });
    expect(await handleOf("org-1")).toBeNull();
  });
  it("a handle another organisation saved with capitals earlier still counts as taken", async () => {
    db = fakeSupabase({ organizations: [{ id: "org-1", github_org: null }, { id: "org-2", github_org: "Taken-Corp" }] });
    expect((await save("taken-corp")).status).toBe(409);
  });
  it("_ in a name is literal, not a wildcard", async () => {
    db = fakeSupabase({ organizations: [{ id: "org-1", github_org: null }, { id: "org-2", github_org: "acmeXcorp" }] });
    expect((await save("acme_corp")).status).toBe(200);
  });
});

