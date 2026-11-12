/**
 * @jest-environment node
 *
 * A literal that is a credential by how the code uses it (found as the largest group of credentials the RealVuln benchmark
 * labelled and we missed): a fallback for a secret environment variable, the password of an account the code creates, and a
 * password constant. Weak and placeholder-looking values count here, because the code itself says they are the credential.
 */
import { findLiteralCredentialUse } from "@/lib/credentialAssignments";
import { runScan } from "@/lib/scanner";

const labelOf = (l: string) => findLiteralCredentialUse(l)?.label ?? null;

describe("findLiteralCredentialUse", () => {
  it("a secret environment variable that falls back to a literal", () => {
    for (const l of [
      `const SECRET = process.env.INVITE_SECRET ?? "dev-enrollment-invite-secret";`,
      `  jwt.sign(payload, process.env.JWT_SECRET || 'supersecretkey')`,
      `const key = process.env.PAYMENT_API_KEY || \`sk_fallback_9f3ac2b8\``,
      `SECRET_KEY = os.environ.get("SECRET_KEY", "django-insecure-abc123xyz")`,
      `token = os.getenv('API_TOKEN', 'dev-token-123456')`,
      `SECRET = os.environ.get("APP_SECRET") or "local-development-secret"`,
      `SECRET_KEY = env("SECRET_KEY", default="insecure-dev-key-123")`,
    ]) expect({ l, label: labelOf(l) }).toEqual({ l, label: "Hardcoded fallback secret" });
  });

  it("not a fallback that is empty, a URL, a path, a mode, or about a credential rather than one", () => {
    for (const l of [
      `const s = process.env.JWT_SECRET ?? "";`,
      `const u = process.env.TOKEN_URL ?? "https://auth.example.com/token";`,
      `const h = process.env.API_KEY_HEADER ?? "x-api-key";`,
      `const f = process.env.SECRET_KEY_FILE || "/run/secrets/key";`,
      `const e = process.env.NODE_ENV ?? "development";`,
      `const p = process.env.PORT ?? "3000";`,
      `const s = process.env.JWT_SECRET ?? "your-secret-here";`,
      `const s = process.env.JWT_SECRET ?? someDefault;`,
      `x = os.environ.get("SECRET_KEY")`,
    ]) expect({ l, label: labelOf(l) }).toEqual({ l, label: null });
  });

  it("the password of an account the code creates", () => {
    for (const l of [
      `const passwordHash = await bcrypt.hash('password123', 10);`,
      `const pw = await hashPassword("Password123!");`,
      `user.password = generate_password_hash("admin")`,
      `u = User(email="a@b.io", password=make_password("Welcome1!"))`,
      `const h = bcryptjs.hashSync("hunter2hunter", 8)`,
    ]) expect({ l, label: labelOf(l) }).toEqual({ l, label: "Hardcoded password" });
    for (const l of [`const h = await bcrypt.hash(password, 10);`, `hashPassword(req.body.password)`, `generate_password_hash(pw)`, `bcrypt.hash(\`\${seed}x\`, 10)`]) expect(labelOf(l)).toBeNull();
  });

  it("a password constant, but not wording, rules or field names", () => {
    for (const l of [`const DEMO_PASSWORD = "PortalDemo!2026";`, `const PASSWORD = "Password123!";`, `ADMIN_PASSWORD = 'hunter2hunter'`, `export const defaultPassword: string = "Sup3rSecret!";`]) {
      expect({ l, label: labelOf(l) }).toEqual({ l, label: "Hardcoded password" });
    }
    for (const l of [
      `const invalidPasswordErrorMessage = "Invalid password";`, `const PASSWORD_MIN_LENGTH = "8";`, `const passwordField = "password";`,
      `const PASSWORD_REGEX = "^(?=.*[A-Z]).{8,}$";`, `const passwordPlaceholder = "Enter your password";`, `const password = process.env.DB_PASSWORD;`,
      `const resetPasswordPath = "/account/reset-password";`, `const password = "";`,
    ]) expect({ l, label: labelOf(l) }).toEqual({ l, label: null });
  });
});

describe("in the scanner", () => {
  const found = (path: string, content: string) =>
    runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] }).files[0].indicators.filter(i => i.id === "hardcoded-secret");

  it("reports them in application code and in a seed script, as hardcoded-secret at the line", () => {
    const f = found("prisma/seed.ts", `import bcrypt from "bcryptjs";\nasync function main() {\n  const passwordHash = await bcrypt.hash("Password123!", 10);\n}\n`);
    expect(f.map(i => i.line)).toEqual([3]);
    expect(f[0].severity).toBe("high");
    const g = found("src/lib/invite.ts", `const SECRET = process.env.INVITE_SECRET ?? "dev-enrollment-invite-secret";\n`);
    expect(g.map(i => i.line)).toEqual([1]);
  });

  it("not in test files", () => {
    expect(found("src/auth.test.ts", `const PASSWORD = "Password123!";\nconst h = await bcrypt.hash("Password123!", 10);\n`)).toHaveLength(0);
  });
});
