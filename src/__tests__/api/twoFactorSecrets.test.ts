/**
 * @jest-environment node
 *
 * 2FA secrets at rest: the TOTP secret is sealed (AES-256-GCM under DATA_ENCRYPTION_KEY) and backup codes are
 * stored only as salted scrypt hashes. Legacy plain rows keep working.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { generateTOTP } from "@/lib/totp";
import { sealSecret, openSecret, hashBackupCode, matchBackupCode, needsUpgrade, isSealed } from "@/lib/secretBox";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn(async () => {}) }));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true, reset: 0, headers: {} }) }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "o1", user_id: "u", actor_email: "a@acme.dev", role: "admin" }),
}));

import { POST } from "@/app/api/auth/2fa/route";

// scrypt is deliberately slow (8 backup codes are hashed per enable, and matched one by one), so under the full
// suite's parallel CPU load a test can pass jest's default 5 s limit. Give it room rather than weaken the hash.
jest.setTimeout(30_000);

const KEY_HEX = "ab".repeat(32);
const row = () => (db.client.from("user_2fa") as unknown as { rows: Record<string, unknown>[] }).rows[0];
const call = (action: string, body: unknown = {}) =>
  POST(new NextRequest(new URL(`https://app.example/api/auth/2fa?action=${action}`), { method: "POST", body: JSON.stringify(body) }));

afterEach(() => { delete process.env.DATA_ENCRYPTION_KEY; });

describe("secretBox", () => {
  it("seals and opens a secret; a sealed value hides the plain text and differs each time", () => {
    process.env.DATA_ENCRYPTION_KEY = KEY_HEX;
    const a = sealSecret("JBSWY3DPEHPK3PXP"), b = sealSecret("JBSWY3DPEHPK3PXP");
    expect(a).toMatch(/^enc:v1:/);
    expect(a).not.toContain("JBSWY3DPEHPK3PXP");
    expect(a).not.toBe(b);
    expect(openSecret(a)).toBe("JBSWY3DPEHPK3PXP");
  });

  it("accepts a base64 key too", () => {
    process.env.DATA_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");
    expect(openSecret(sealSecret("S"))).toBe("S");
  });

  it("a tampered value, a wrong key or a missing key can't be opened", () => {
    process.env.DATA_ENCRYPTION_KEY = KEY_HEX;
    const sealed = sealSecret("SECRET");
    const raw = Buffer.from(sealed.slice(7), "base64"); raw[raw.length - 1] ^= 1;
    expect(openSecret("enc:v1:" + raw.toString("base64"))).toBeNull();
    expect(openSecret("enc:v1:AAAA")).toBeNull();
    process.env.DATA_ENCRYPTION_KEY = "cd".repeat(32);
    expect(openSecret(sealed)).toBeNull();
    delete process.env.DATA_ENCRYPTION_KEY;
    expect(openSecret(sealed)).toBeNull();
  });

  it("without a (valid) key, values are stored and read as plain -- 2FA keeps working", () => {
    expect(sealSecret("PLAIN")).toBe("PLAIN");
    process.env.DATA_ENCRYPTION_KEY = "too-short";
    expect(sealSecret("PLAIN")).toBe("PLAIN");
    expect(openSecret("PLAIN")).toBe("PLAIN");
    expect(openSecret(null)).toBeNull();
  });

  it("backup codes: hashed with a per-code salt, matched case/space-insensitively; legacy plain codes still match", async () => {
    const h1 = await hashBackupCode("AB12CD34"), h2 = await hashBackupCode("AB12CD34");
    expect(h1).toMatch(/^scrypt:/);
    expect(h1).not.toContain("AB12CD34");
    expect(h1).not.toBe(h2);
    const stored = ["11112222", h1, "EEEEFFFF"];
    expect(await matchBackupCode(stored, "ab12 cd34")).toBe(1);
    expect(await matchBackupCode(stored, "eeeeffff")).toBe(2);
    expect(await matchBackupCode(stored, "AB12CD35")).toBe(-1);
    expect(await matchBackupCode(stored, "1111222")).toBe(-1);
    expect(await matchBackupCode(stored, "")).toBe(-1);
    expect(await matchBackupCode(["scrypt:broken"], "AB12CD34")).toBe(-1);
    expect(await matchBackupCode(null, "AB12CD34")).toBe(-1);
  });

  it("needsUpgrade: plain codes always; a plain secret only once a key exists", async () => {
    const h = await hashBackupCode("X");
    expect(needsUpgrade("PLAIN", [h])).toEqual({ secret: false, codes: false });
    expect(needsUpgrade("PLAIN", [h, "Y"])).toEqual({ secret: false, codes: true });
    process.env.DATA_ENCRYPTION_KEY = KEY_HEX;
    expect(needsUpgrade("PLAIN", [])).toEqual({ secret: true, codes: false });
    expect(needsUpgrade(sealSecret("PLAIN"), [])).toEqual({ secret: false, codes: false });
  });
});

describe("/api/auth/2fa setup → verify → disable", () => {
  beforeEach(() => { db = fakeSupabase({ user_2fa: [] }); });

  it("stores a sealed secret and only hashes of the backup codes it shows once", async () => {
    process.env.DATA_ENCRYPTION_KEY = KEY_HEX;
    const setup = await (await call("setup")).json() as { secret: string };
    expect(isSealed(row().secret as string)).toBe(true);
    expect(String(row().secret)).not.toContain(setup.secret);

    expect((await call("verify", { code: "000000" === generateTOTP(setup.secret) ? "111111" : "000000" })).status).toBe(400);
    const res = await call("verify", { code: generateTOTP(setup.secret) });
    expect(res.status).toBe(200);
    const { backup_codes } = await res.json() as { backup_codes: string[] };
    expect(backup_codes).toHaveLength(8);
    const stored = row().backup_codes as string[];
    expect(stored).toHaveLength(8);
    expect(stored.every(c => c.startsWith("scrypt:"))).toBe(true);
    for (const c of backup_codes) expect(stored.join()).not.toContain(c);
    expect(row().enabled).toBe(true);

    // disable with a shown backup code
    expect((await call("disable", { code: "NOTACODE" })).status).toBe(400);
    expect((await call("disable", { code: backup_codes[3].toLowerCase() })).status).toBe(200);
    expect(row()).toMatchObject({ enabled: false, secret: null, backup_codes: [] });
  });

  it("disable accepts the authenticator code against a sealed secret", async () => {
    process.env.DATA_ENCRYPTION_KEY = KEY_HEX;
    const { secret } = await (await call("setup")).json() as { secret: string };
    await call("verify", { code: generateTOTP(secret) });
    expect((await call("disable", { code: generateTOTP(secret) })).status).toBe(200);
  });

  it("a legacy plain pending secret is verified, then sealed once a key exists", async () => {
    db = fakeSupabase({ user_2fa: [{ user_id: "u", enabled: false, secret: "JBSWY3DPEHPK3PXP", backup_codes: [] }] });
    process.env.DATA_ENCRYPTION_KEY = KEY_HEX;
    expect((await call("verify", { code: generateTOTP("JBSWY3DPEHPK3PXP") })).status).toBe(200);
    expect(openSecret(row().secret as string)).toBe("JBSWY3DPEHPK3PXP");
    expect(isSealed(row().secret as string)).toBe(true);
  });

  it("without a key the flow still works (plain secret, hashed codes)", async () => {
    const { secret } = await (await call("setup")).json() as { secret: string };
    expect(row().secret).toBe(secret);
    expect((await call("verify", { code: generateTOTP(secret) })).status).toBe(200);
    expect((row().backup_codes as string[]).every(c => c.startsWith("scrypt:"))).toBe(true);
  });
});
