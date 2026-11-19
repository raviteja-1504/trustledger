/**
 * @jest-environment node
 *
 * The Branding tab used to accept an empty form: every field was stored as "" and the button still said "Applied".
 * validateBranding() trims, drops empty fields, requires at least one real value, and checks formats.
 */
import { validateBranding } from "@/lib/branding";

describe("validateBranding", () => {
  it("rejects an empty form, and a form of only blanks: nothing to apply", () => {
    for (const input of [{}, { org_name: "", logo_url: "", primary_color: "", favicon_url: "", support_email: "", tagline: "" }, { org_name: "   ", tagline: "\t" }]) {
      const r = validateBranding(input);
      expect(r.ok).toBe(false);
      expect(r.errors.org_name).toMatch(/at least one value/i);
      expect(r.cleaned).toEqual({});
    }
  });

  it("accepts a single real value and keeps only the filled-in fields, trimmed", () => {
    const r = validateBranding({ org_name: "  Acme Corp ", tagline: "", logo_url: "", primary_color: undefined });
    expect(r.ok).toBe(true);
    expect(r.cleaned).toEqual({ org_name: "Acme Corp" });
  });

  it("accepts a complete, well-formed form", () => {
    const full = { org_name: "Acme", tagline: "Safe code", logo_url: "https://acme.com/logo.png", favicon_url: "http://acme.com/f.ico", primary_color: "#1A2b3C", support_email: "sec@acme.com" };
    const r = validateBranding(full);
    expect(r.ok).toBe(true);
    expect(r.cleaned).toEqual(full);
  });

  it.each([
    ["primary_color", "red"], ["primary_color", "#12345"], ["primary_color", "#12345g"], ["primary_color", "6366f1"],
    ["logo_url", "acme.com/logo.png"], ["logo_url", "javascript:alert(1)"], ["logo_url", "data:image/png;base64,AAAA"], ["logo_url", "ftp://acme.com/l.png"],
    ["favicon_url", "not a url"], ["favicon_url", "file:///etc/passwd"],
    ["support_email", "not-an-email"], ["support_email", "a@b"],
  ] as const)("rejects a bad %s: %s", (field, value) => {
    const r = validateBranding({ org_name: "Acme", [field]: value });
    expect(r.ok).toBe(false);
    expect(r.errors[field]).toBeTruthy();
  });

  it("reports every bad field at once", () => {
    const r = validateBranding({ primary_color: "red", logo_url: "nope", support_email: "x" });
    expect(Object.keys(r.errors).sort()).toEqual(["logo_url", "primary_color", "support_email"]);
  });
});
