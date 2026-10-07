/**
 * @jest-environment node
 *
 * Evidence storage: a caller-supplied path can't leave the caller's org folder ({org_id}/...). The old check
 * only asked "does it start with the org id?", so `{org_id}/../org-2/x` passed straight to the bucket.
 */
import { NextRequest } from "next/server";
import { orgStorageKey, orgStorageFolder } from "@/lib/storagePath";

const calls: { op: string; arg: unknown }[] = [];
const bucket = {
  createSignedUrl: async (p: string) => { calls.push({ op: "sign", arg: p }); return { data: { signedUrl: `https://signed/${p}` }, error: null }; },
  upload: async (p: string) => { calls.push({ op: "upload", arg: p }); return { error: null }; },
  remove: async (ps: string[]) => { calls.push({ op: "remove", arg: ps }); return { error: null }; },
  list: async (p: string) => { calls.push({ op: "list", arg: p }); return { data: [], error: null }; },
};
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => ({ storage: { from: () => bucket } }) }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => {} }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", actor_email: "a@org1.test", role: "admin" }),
  requirePermission: async () => null,
}));

import { GET, POST, DELETE } from "@/app/api/storage/route";

const url = (q: string) => new URL(`https://app.example/api/storage${q}`);
const TRAVERSALS = ["org-1/../org-2/secret.pdf", "../org-2/secret.pdf", "a/../../org-2/x", "org-1/./x", "a//b", "a\\..\\x", "%2e%2e/org-2/x", "org-1/", "org-1/a\u0000b"];

beforeEach(() => { calls.length = 0; });

describe("orgStorageKey / orgStorageFolder", () => {
  it("keeps normal paths inside the org folder", () => {
    expect(orgStorageKey("org-1", "org-1/ctl/1_a.pdf")).toBe("org-1/ctl/1_a.pdf");
    expect(orgStorageKey("org-1", "ctl/1_a.pdf")).toBe("org-1/ctl/1_a.pdf");
    expect(orgStorageKey("org-1", "1_a.pdf")).toBe("org-1/1_a.pdf");
    expect(orgStorageFolder("org-1", "")).toBe("");
    expect(orgStorageFolder("org-1", "SOC2 CC6.1/")).toBe("SOC2 CC6.1");
    expect(orgStorageFolder("org-1", "org-1/ctl")).toBe("ctl");
  });

  it("rejects every traversal / ambiguous form", () => {
    for (const p of TRAVERSALS) {
      expect(orgStorageKey("org-1", p)).toBeNull();
      expect(orgStorageFolder("org-1", p)).toBeNull();
    }
    expect(orgStorageKey("org-1", "")).toBeNull();
  });

  it("another org's id is just a sub-folder of the caller's org, never the other org's folder", () => {
    expect(orgStorageKey("org-1", "org-2/x.pdf")).toBe("org-1/org-2/x.pdf");
    // prefix without the slash (old startsWith check) is not treated as the org folder
    expect(orgStorageKey("org-1", "org-1x/y")).toBe("org-1/org-1x/y");
  });
});

describe("/api/storage", () => {
  it("GET signs a normal path in the caller's org", async () => {
    const res = await GET(new NextRequest(url("?path=org-1/ctl/a.pdf")));
    expect(res.status).toBe(200);
    expect(calls).toEqual([{ op: "sign", arg: "org-1/ctl/a.pdf" }]);
  });

  it("GET / DELETE reject traversal without touching the bucket", async () => {
    for (const p of TRAVERSALS) {
      const q = `?path=${encodeURIComponent(p)}`;
      expect((await GET(new NextRequest(url(q)))).status).toBe(400);
      expect((await DELETE(new NextRequest(url(q), { method: "DELETE" }))).status).toBe(400);
    }
    expect(calls).toEqual([]);
  });

  it("DELETE removes a normal path", async () => {
    const res = await DELETE(new NextRequest(url("?path=ctl/a.pdf"), { method: "DELETE" }));
    expect(res.status).toBe(200);
    expect(calls).toEqual([{ op: "remove", arg: ["org-1/ctl/a.pdf"] }]);
  });

  const upload = (path: string) => {
    const fd = new FormData();
    fd.set("file", new File(["x"], "evidence.pdf", { type: "application/pdf" }));
    fd.set("path", path);
    return POST(new NextRequest(url(""), { method: "POST", body: fd }));
  };

  it("POST rejects a traversal folder without uploading", async () => {
    for (const p of TRAVERSALS) expect((await upload(p)).status).toBe(400);
    expect(calls).toEqual([]);
  });

  it("POST uploads into the org folder", async () => {
    const res = await upload("ctl");
    expect(res.status).toBe(200);
    expect(calls[0].op).toBe("upload");
    expect(calls[0].arg).toMatch(/^org-1\/ctl\/\d+_evidence\.pdf$/);
  });
});
