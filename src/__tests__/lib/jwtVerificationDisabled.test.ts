import { analyzeFile } from "@/lib/scanner";

describe("JWT signature verification disabled via PyJWT's options dict (found via real-world Damn Vulnerable GraphQL App testing)", () => {
  it("flags PyJWT's modern options={'verify_signature': False} bypass form", () => {
    const content = `
from jwt import decode

def get_identity(token):
  return decode(token, options={"verify_signature":False, "verify_exp":False}).get('identity')
`;
    const result = analyzeFile("core/helpers.py", content);
    const finding = result.indicators.find(i => i.id === "jwt-none-alg");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  it("still flags the older bare verify=False kwarg form", () => {
    const content = `
import jwt

def decode_token(token):
  return jwt.decode(token, verify=False)
`;
    const result = analyzeFile("auth/tokens.py", content);
    expect(result.indicators.some(i => i.id === "jwt-none-alg")).toBe(true);
  });

  it("does not flag a properly verified decode call", () => {
    const content = `
import jwt

def decode_token(token, secret):
  return jwt.decode(token, secret, algorithms=["HS256"])
`;
    const result = analyzeFile("auth/tokens.py", content);
    expect(result.indicators.some(i => i.id === "jwt-none-alg")).toBe(false);
  });
});
