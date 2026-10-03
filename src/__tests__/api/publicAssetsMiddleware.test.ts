/**
 * @jest-environment node
 *
 * Signed-out visitors must be able to load the logo, favicons, PWA icons, og-image and manifest — the
 * landing and login pages show them. Previously /brand/*.png was redirected to /login (a broken image).
 */
import { NextRequest } from "next/server";

let middleware: (req: NextRequest) => Promise<Response>;

beforeAll(async () => {
  process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
  process.env.NEXT_PUBLIC_SUPABASE_URL = "https://abc.supabase.co";
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon";
  ({ middleware } = await import("@/middleware"));
});

const get = (path: string) => middleware(new NextRequest(new URL(path, "https://app.example")));

it.each([
  "/brand/trustledger-logo.png", "/brand/trustledger-wordmark.png", "/brand/trustledger-mark.png",
  "/favicon-16x16.png", "/favicon-32x32.png", "/apple-touch-icon.png", "/icon-192.png", "/icon-512.png",
  "/og-image.png", "/manifest.json",
])("serves %s without a session", async path => {
  const res = await get(path);
  expect(res.headers.get("location")).toBeNull();
  expect(res.status).toBe(200);
});

it("still sends signed-out visitors on app pages to the login page", async () => {
  const res = await get("/dashboard");
  expect(res.status).toBe(307);
  expect(res.headers.get("location")).toContain("/login");
});

it("does not open nested paths that merely end in .png", async () => {
  const res = await get("/reports/x.png");
  expect(res.status).toBe(307);
});
