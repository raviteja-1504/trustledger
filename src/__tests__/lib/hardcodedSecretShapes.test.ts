/**
 * @jest-environment node
 *
 * Hard-coded credentials in the shapes the word-keyed rules used to miss: Go's `:=`, struct fields and object keys
 * set to a literal, passwords inside any URL's userinfo, literals handed straight to SMTP auth or a JWT signer, and
 * keys built from a byte literal. Templates, placeholders and environment lookups stay silent.
 */
import { analyzeFile } from "@/lib/scanner";

const secret = (code: string, file = "internal/config/config.go") => analyzeFile(file, code).indicators.some(i => i.id === "hardcoded-secret");
const go = (body: string) => `package config\n\nfunc Load() {\n${body}\n}\n`;

describe("hard-coded credential shapes", () => {
  it("Go := and struct / object fields set to a literal", () => {
    expect(secret(go(`\tpassword := "Pr0d-Db-Pass!2024"\n\t_ = password`))).toBe(true);
    expect(secret(go(`\tcfg := DBConfig{\n\t\tHost:     "db.internal",\n\t\tPassword: "prod_secret_123",\n\t}\n\t_ = cfg`))).toBe(true);
    expect(secret(`import { db } from "./db";\nconst cfg = { apiKey: "Zq8xL2vR7nT4pW9k" };\nexport default cfg;\n`, "src/config.ts")).toBe(true);
  });
  it("a password in any URL's userinfo, but not a template or a URL without one", () => {
    expect(secret(go(`\taddr := "redis://:MyS3cr3tP@ssw0rd@localhost:6379"\n\t_ = addr`))).toBe(true);
    expect(secret(go(`\tes := "https://admin:ElasticPass123@es.internal:9200"\n\t_ = es`))).toBe(true);
    expect(secret(go(`\tdsn := fmt.Sprintf("redis://:%s@%s", pass, host)\n\t_ = dsn`))).toBe(false);
    expect(secret(go(`\ttmpl := "https://{user}:{dbSecretValue}@db.internal/api"\n\t_ = tmpl`))).toBe(false);
    expect(secret(go(`\tes := "https://es.internal:9200/_search"\n\t_ = es`))).toBe(false);
  });
  it("literals passed to SMTP auth or a JWT signer, and byte-literal keys", () => {
    expect(secret(go(`\tauth := smtp.PlainAuth("", "noreply@mail.internal", "SmtpP4ssw0rd!", host)\n\t_ = auth`))).toBe(true);
    expect(secret(go(`\ts, _ := token.SignedString([]byte("my-super-secret-jwt-key-2024"))\n\t_ = s`))).toBe(true);
    expect(secret(go(`\tencKey := []byte("Kq9vX2mL7pR4tW8nB5cZ3hJ6")\n\t_ = encKey`))).toBe(true);
    expect(secret(go(`\tauth := smtp.PlainAuth("", user, os.Getenv("SMTP_PASSWORD"), host)\n\t_ = auth`))).toBe(false);
    expect(secret(go(`\ts, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))\n\t_ = s`))).toBe(false);
  });
  it("typed constants: Rust &str and byte strings, TypeScript and Go typed declarations", () => {
    const rs = (line: string) => secret(`${line}\npub fn handle() {}\n`, "src/handlers.rs");
    expect(rs(`const DB_PASSWORD: &str = "P@ssw0rd2024!Prod";`)).toBe(true);
    expect(rs(`static JWT_SECRET: &'static str = "super-secret-jwt-signing-key-2024";`)).toBe(true);
    expect(rs(`const API_KEY: &[u8] = b"Zq8xL2vR7nT4pW9kB3mH";`)).toBe(true);
    expect(secret(`import { db } from "./db";\nconst password: string = "Pr0d-Db-Pass!2024";\nexport default password;\n`, "src/config.ts")).toBe(true);
    expect(secret(go(`\tvar password string = "Pr0d-Db-Pass!2024"\n\t_ = password`))).toBe(true);
    expect(rs(`const DB_PASSWORD: &str = env!("DB_PASSWORD");`)).toBe(false);
  });
  it("placeholders and type annotations are not secrets", () => {
    expect(secret(go(`\tpassword := "changeme"\n\t_ = password`))).toBe(false);
    expect(secret(`import { db } from "./db";\ninterface Creds { password: string }\nexport type { Creds };\n`, "src/types.ts")).toBe(false);
    expect(secret(go(`\tcfg := DBConfig{Password: os.Getenv("DB_PASSWORD")}\n\t_ = cfg`))).toBe(false);
  });
});
