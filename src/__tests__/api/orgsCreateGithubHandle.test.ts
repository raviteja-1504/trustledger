/**
 * @jest-environment node
 *
 * The create-organisation form has the same optional "GitHub account name" box as the setup wizard: what is saved must be an owner name,
 * not an email address or a pasted repository link.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyJWT: async () => ({ user_id: "u1", email: "ada@acme.dev", name: "Ada" }),
}));

import { POST } from "@/app/api/orgs/create/route";

const create = async (github_org?: string) => {
  const res = await POST(new NextRequest(new URL("/api/orgs/create", "https://app.example"), {
    method: "POST", headers: { Authorization: "Bearer x.y.z" }, body: JSON.stringify({ name: "Acme", slug: "acme", github_org }),
  }));
  return { status: res.status, body: await res.json() as Record<string, unknown> };
};
const savedHandle = async () => ((await db.client.from("organizations").select("github_org").eq("slug", "acme").single()) as unknown as { data: { github_org: string | null } }).data?.github_org;

beforeEach(() => { db = fakeSupabase({ organizations: [], org_members: [] }); });

describe("POST /api/orgs/create: the GitHub account name", () => {
  it("is optional", async () => {
    expect((await create()).status).toBe(201);
    expect(await savedHandle()).toBeFalsy();
  });
  it("a pasted repository address is saved as its owner, in lower case", async () => {
    expect((await create("https://github.com/Acme-Corp/payments-api")).status).toBe(201);
    expect(await savedHandle()).toBe("acme-corp");
  });
  it("an email address is refused with a message, and no organisation is created", async () => {
    const r = await create("ada@acme.dev");
    expect(r.status).toBe(400);
    expect(r.body).toMatchObject({ error: "github_org_invalid", message: expect.stringMatching(/email address/i) });
    expect(await savedHandle()).toBeUndefined();
  });
});
