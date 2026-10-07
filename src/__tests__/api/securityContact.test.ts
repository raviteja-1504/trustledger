/**
 * @jest-environment node
 *
 * Vulnerability disclosure: /.well-known/security.txt (RFC 9116) and /security are public, and both publish the
 * contact from NEXT_PUBLIC_SECURITY_CONTACT -- falling back to an undeliverable `.example` placeholder, never to
 * a guessed real-looking domain that a stranger could own.
 */
import { NextRequest } from "next/server";
import { GET as securityTxt } from "@/app/.well-known/security.txt/route";
import { securityContact, isPlaceholderSecurityContact, PLACEHOLDER_SECURITY_CONTACT } from "@/lib/securityContact";

const saved = process.env.NEXT_PUBLIC_SECURITY_CONTACT;
afterEach(() => { if (saved === undefined) delete process.env.NEXT_PUBLIC_SECURITY_CONTACT; else process.env.NEXT_PUBLIC_SECURITY_CONTACT = saved; });

const fields = async () => {
  const res = securityTxt(new NextRequest(new URL("https://app.example/.well-known/security.txt")));
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
  const text = await res.text();
  return Object.fromEntries(text.trim().split("\n").map(l => [l.slice(0, l.indexOf(":")), l.slice(l.indexOf(":") + 2)]));
};

describe("securityContact", () => {
  it("uses NEXT_PUBLIC_SECURITY_CONTACT when it is an email address", () => {
    process.env.NEXT_PUBLIC_SECURITY_CONTACT = "  security@acme-sec.io ";
    expect(securityContact()).toBe("security@acme-sec.io");
    expect(isPlaceholderSecurityContact()).toBe(false);
  });
  it("falls back to the .example placeholder when unset or not an address", () => {
    for (const v of [undefined, "", "not-an-email", "a@b", "x@y.com>evil"]) {
      if (v === undefined) delete process.env.NEXT_PUBLIC_SECURITY_CONTACT; else process.env.NEXT_PUBLIC_SECURITY_CONTACT = v;
      expect(securityContact()).toBe(PLACEHOLDER_SECURITY_CONTACT);
    }
    expect(PLACEHOLDER_SECURITY_CONTACT.endsWith(".example")).toBe(true);
    expect(isPlaceholderSecurityContact()).toBe(true);
  });
});

describe("/.well-known/security.txt", () => {
  it("has the RFC 9116 fields, pointing at this site", async () => {
    process.env.NEXT_PUBLIC_SECURITY_CONTACT = "security@acme-sec.io";
    const f = await fields();
    expect(f.Contact).toBe("mailto:security@acme-sec.io");
    expect(f.Canonical).toBe("https://app.example/.well-known/security.txt");
    expect(f.Policy).toBe("https://app.example/security");
    expect(f["Preferred-Languages"]).toBe("en");
  });

  it("links use the configured app URL, not the request's Host header", async () => {
    const savedApp = process.env.NEXT_PUBLIC_APP_URL;
    process.env.NEXT_PUBLIC_APP_URL = "https://trust.example.org/";
    try {
      const f = await fields();
      expect(f.Canonical).toBe("https://trust.example.org/.well-known/security.txt");
      expect(f.Policy).toBe("https://trust.example.org/security");
    } finally {
      if (savedApp === undefined) delete process.env.NEXT_PUBLIC_APP_URL; else process.env.NEXT_PUBLIC_APP_URL = savedApp;
    }
  });

  it("Expires is in the future and less than a year away (RFC 9116 §2.5.5)", async () => {
    const expires = Date.parse((await fields()).Expires);
    expect(expires).toBeGreaterThan(Date.now() + 30 * 86400_000);
    expect(expires).toBeLessThan(Date.now() + 365 * 86400_000);
  });

  it("publishes the placeholder until a real contact is configured", async () => {
    delete process.env.NEXT_PUBLIC_SECURITY_CONTACT;
    expect((await fields()).Contact).toBe(`mailto:${PLACEHOLDER_SECURITY_CONTACT}`);
  });
});

describe("public without a session", () => {
  let middleware: (req: NextRequest) => Promise<Response>;
  beforeAll(async () => {
    process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
    process.env.NEXT_PUBLIC_SUPABASE_URL = "https://abc.supabase.co";
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon";
    ({ middleware } = await import("@/middleware"));
  });
  it.each(["/security", "/.well-known/security.txt"])("%s is not redirected to login", async path => {
    const res = await middleware(new NextRequest(new URL(path, "https://app.example")));
    expect(res.headers.get("location")).toBeNull();
  });
});
