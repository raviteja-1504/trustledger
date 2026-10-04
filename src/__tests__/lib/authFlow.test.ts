/**
 * @jest-environment node
 */
import { authLinkErrorCode, GENERIC_LOGIN_ERROR, hasAuthCallbackParams, loginErrorMessage, safeNextPath } from "@/lib/authFlow";
import { generateTOTP, verifyTOTP } from "@/lib/totp";

describe("loginErrorMessage", () => {
  it("maps known codes and never echoes an unknown ?error= value", () => {
    expect(loginErrorMessage("session_revoked")).toMatch(/signed in somewhere else/);
    expect(loginErrorMessage("link_other_browser")).toMatch(/same browser/);
    const crafted = "Your account is locked. Call support at 555-0100";
    expect(loginErrorMessage(crafted)).toBe(GENERIC_LOGIN_ERROR);
    expect(loginErrorMessage("%")).toBe(GENERIC_LOGIN_ERROR);
    expect(loginErrorMessage(null)).toBeNull();
  });
});

describe("safeNextPath", () => {
  it.each([
    ["/reports?tab=soc2", "/reports?tab=soc2"],
    ["/pr/123", "/pr/123"],
  ])("keeps same-site path %s", (input, out) => expect(safeNextPath(input)).toBe(out));

  it.each([
    "https://evil.example", "//evil.example", "/\\evil.example", "/\t/evil.example", "javascript:alert(1)",
    "/login", "/login?next=/x", "/auth/callback", "", null, undefined,
  ])("falls back to /dashboard for %p", input => expect(safeNextPath(input as string | null)).toBe("/dashboard"));
});

describe("authLinkErrorCode", () => {
  it("explains a link opened in another browser, an expired link, and anything else", () => {
    expect(authLinkErrorCode(null, "https://a/")).toBeNull();
    expect(authLinkErrorCode({ name: "AuthPKCECodeVerifierMissingError", message: "PKCE code verifier not found in storage" }, "https://a/?code=x")).toBe("link_other_browser");
    expect(authLinkErrorCode({ name: "AuthImplicitGrantRedirectError", message: "Email link is invalid or has expired", details: { code: "otp_expired" } }, "https://a/#error=access_denied&error_code=otp_expired")).toBe("link_expired");
    expect(authLinkErrorCode({ name: "AuthApiError", message: "invalid flow state" }, "https://a/?code=x")).toBe("link_invalid");
  });

  it("only treats real auth callback URLs as link results", () => {
    expect(hasAuthCallbackParams("?code=abc", "")).toBe(true);
    expect(hasAuthCallbackParams("", "#error=access_denied&error_code=otp_expired&error_description=x")).toBe(true);
    expect(hasAuthCallbackParams("?error=session_revoked", "")).toBe(false);   // our own login-page codes
    expect(hasAuthCallbackParams("?tab=code", "")).toBe(false);
  });
});

describe("TOTP (RFC 6238 test vectors, SHA-1)", () => {
  // Secret "12345678901234567890" in base32; RFC 6238 Appendix B (last 6 of the 8-digit values)
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  it.each([[59, "287082"], [1111111109, "081804"], [1234567890, "005924"], [2000000000, "279037"]])("t=%i → %s", (t, code) => {
    expect(generateTOTP(secret, t)).toBe(code);
  });
  it("accepts the current code and its neighbours only", () => {
    const now = Date.now() / 1000;
    expect(verifyTOTP(secret, generateTOTP(secret, now))).toBe(true);
    expect(verifyTOTP(secret, generateTOTP(secret, now - 30))).toBe(true);
    expect(verifyTOTP(secret, generateTOTP(secret, now - 120))).toBe(false);
  });
});
