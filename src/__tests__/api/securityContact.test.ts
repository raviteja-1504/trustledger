/**
 * @jest-environment node
 *
 * Vulnerability disclosure: /.well-known/security.txt (RFC 9116) and /security are public, and both publish the
 * contact from NEXT_PUBLIC_SECURITY_CONTACT -- falling back to an undeliverable `.example` placeholder, never to
 * a guessed real-looking domain that a stranger could own.
 */
import { NextRequest } from "next/server";
import { GET as securityTxt } from "@/app/.well-known/security.txt/route";
import { readFileSync, readdirSync, statSync } from "fs";
import { join } from "path";
import { securityContact, isPlaceholderSecurityContact, PLACEHOLDER_SECURITY_CONTACT, contactEmail, contactDomain, PLACEHOLDER_CONTACT_DOMAIN } from "@/lib/contacts";
import { OPENAPI_SPEC } from "@/lib/openapi";

const saved = process.env.NEXT_PUBLIC_SECURITY_CONTACT;
const savedDomain = process.env.NEXT_PUBLIC_CONTACT_DOMAIN;
afterEach(() => {
  if (saved === undefined) delete process.env.NEXT_PUBLIC_SECURITY_CONTACT; else process.env.NEXT_PUBLIC_SECURITY_CONTACT = saved;
  if (savedDomain === undefined) delete process.env.NEXT_PUBLIC_CONTACT_DOMAIN; else process.env.NEXT_PUBLIC_CONTACT_DOMAIN = savedDomain;
});

describe("published contact addresses", () => {
  it("are role@trustledger.example until a domain is configured", () => {
    delete process.env.NEXT_PUBLIC_CONTACT_DOMAIN;
    expect(contactDomain()).toBe(PLACEHOLDER_CONTACT_DOMAIN);
    expect(PLACEHOLDER_CONTACT_DOMAIN.endsWith(".example")).toBe(true);
    for (const role of ["hello", "privacy", "sales", "support", "updates", "security"] as const) {
      expect(contactEmail(role)).toBe(`${role}@trustledger.example`);
    }
  });

  it("one setting switches them all; the security address can still be set on its own", () => {
    process.env.NEXT_PUBLIC_CONTACT_DOMAIN = " @Acme-Sec.io ";
    expect(contactEmail("privacy")).toBe("privacy@acme-sec.io");
    expect(contactEmail("security")).toBe("security@acme-sec.io");
    process.env.NEXT_PUBLIC_SECURITY_CONTACT = "psirt@other.org";
    expect(contactEmail("security")).toBe("psirt@other.org");
    expect(contactEmail("hello")).toBe("hello@acme-sec.io");
  });

  it("ignores a setting that isn't a plain domain", () => {
    for (const v of ["", "acme", "acme.com/evil", "a b.com", "-acme.com", "x@acme.com"]) {
      process.env.NEXT_PUBLIC_CONTACT_DOMAIN = v;
      expect(contactDomain()).toBe(PLACEHOLDER_CONTACT_DOMAIN);
    }
  });

  it("the API docs publish the support address and no link to a domain we don't own", () => {
    expect(OPENAPI_SPEC.info.contact).toEqual({ name: "TrustLedger Support", email: contactEmail("support") });
  });

  it("no page publishes an address on trustledger.dev (someone else's domain) for people to write to", () => {
    const walk = (d: string): string[] => readdirSync(d).flatMap(n => {
      const p = join(d, n);
      return statSync(p).isDirectory() ? (n === "__tests__" ? [] : walk(p)) : /\.tsx?$/.test(n) ? [p] : [];
    });
    const hits = walk(join(process.cwd(), "src")).flatMap(f =>
      [...readFileSync(f, "utf8").matchAll(/\b(hello|privacy|sales|support|updates|contact|info)@trustledger\.dev\b|docs\.trustledger\.dev/g)].map(m => `${f}: ${m[0]}`));
    expect(hits).toEqual([]);
  });
});

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
