/**
 * @jest-environment node
 *
 * Request-body caps are enforced while streaming (a missing or lying Content-Length must not bypass them).
 */
import { NextRequest } from "next/server";
import { readTextLimited } from "@/lib/readBody";

const streamOf = (chunks: string[]) => new ReadableStream<Uint8Array>({
  start(c) { for (const ch of chunks) c.enqueue(new TextEncoder().encode(ch)); c.close(); },
});
const post = (body: ReadableStream<Uint8Array> | string, headers: Record<string, string> = {}) =>
  new Request("https://app.example/x", { method: "POST", body, headers, ...(typeof body === "string" ? {} : { duplex: "half" } as object) });

describe("readTextLimited", () => {
  it("returns the text when within the cap", async () => {
    expect(await readTextLimited(post("hello"), 10)).toBe("hello");
  });
  it("returns an empty string for no body", async () => {
    expect(await readTextLimited(new Request("https://app.example/x"), 10)).toBe("");
  });
  it("refuses an oversized declared Content-Length without reading", async () => {
    expect(await readTextLimited(post("hi", { "content-length": "999" }), 10)).toBeNull();
  });
  it("catches an oversized body with NO Content-Length (chunked)", async () => {
    expect(await readTextLimited(post(streamOf(["aaaaaa", "bbbbbb"])), 10)).toBeNull();
  });
  it("catches an oversized body whose Content-Length lies", async () => {
    expect(await readTextLimited(post(streamOf(["a".repeat(50)]), { "content-length": "3" }), 10)).toBeNull();
  });
  it("accepts a body of exactly the cap and reassembles chunks and multibyte text", async () => {
    expect(await readTextLimited(post(streamOf(["héllo", " wö"])), 20)).toBe("héllo wö");
    expect(await readTextLimited(post("1234567890"), 10)).toBe("1234567890");
  });
});

describe("edge middleware body checks", () => {
  const ENV = ["NODE_ENV", "NEXT_PUBLIC_SKIP_AUTH", "NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_ANON_KEY"];
  const saved: Record<string, string | undefined> = {};
  const env = process.env as Record<string, string | undefined>;
  beforeEach(() => { for (const k of ENV) { saved[k] = env[k]; } env.NEXT_PUBLIC_SKIP_AUTH = "false"; env.NEXT_PUBLIC_SUPABASE_URL = "https://abc.supabase.co"; env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon"; jest.resetModules(); });
  afterEach(() => { for (const k of ENV) { if (saved[k] === undefined) delete env[k]; else env[k] = saved[k]; } });

  const run = async (headers: Record<string, string>) => {
    const { middleware } = await import("@/middleware");
    return middleware(new NextRequest("https://app.example/api/scans", { method: "POST", headers }));
  };

  it("413 for an oversized declared length", async () => {
    expect((await run({ "content-length": String(11 * 1024 * 1024) })).status).toBe(413);
  });
  it("400 for a non-numeric length (used to slip through as NaN)", async () => {
    expect((await run({ "content-length": "abc" })).status).toBe(400);
  });
  it("411 for a chunked body with no length", async () => {
    expect((await run({ "transfer-encoding": "chunked" })).status).toBe(411);
  });
  it("lets a normal request through to its own auth", async () => {
    expect((await run({ "content-length": "100" })).status).toBe(200);
  });
});
