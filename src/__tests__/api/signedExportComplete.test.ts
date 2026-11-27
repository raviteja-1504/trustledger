/**
 * @jest-environment node
 *
 * The signed audit export is complete or it is nothing, and it can be verified without TrustLedger:
 *  - every event is read (past the database's 1000-row cap) and the count is checked, or the export fails with 503;
 *  - the CSV signs its own bytes and carries every column the audit hash needs, so scripts/verify-audit-export.cjs
 *    re-derives each entry's hash and the chain links from the file alone;
 *  - hostile values in the log cannot make a CSV cell run as a formula or fake the signature block.
 */
import crypto from "crypto";
import { spawnSync } from "child_process";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { _resetExportKeyCache, keyIdFromPem } from "@/lib/exportSigning";
import { auditEntryHash, auditEntryHashV2 } from "@/lib/audit";
import { parseCsv } from "@/lib/csv";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-admin", actor_email: "admin@acme.dev", role: "admin" }),
}));
import { GET as signedGET } from "@/app/api/export/signed/route";

const SCRIPT = join(__dirname, "../../../scripts/verify-audit-export.cjs");
const MARKER = "# --- signature ---";
const T0 = Date.now() - 3 * 3600_000;

type Ev = { id: number; org_id: string; event_type: string; actor_email: string | null; resource_type: string; resource_id: string; payload: unknown; prev_hash: string | null; entry_hash: string; created_at: string };
function chain(n: number, edit?: (i: number) => Partial<Ev>, legacy = 0): Ev[] {
  const rows: Ev[] = [];
  let prev: string | null = null;
  for (let i = 0; i < n; i++) {
    const created_at = new Date(T0 + i * 1000).toISOString();
    const base = { event_type: "scan_complete", actor_email: i % 3 === 0 ? null : "ana@acme.dev", resource_type: "scan", resource_id: `s${i}`, payload: { n: i, repo: "acme/app" }, ...(edit?.(i) ?? {}) };
    // the first `legacy` entries stand for old rows whose hash was computed over a time that was not stored
    const entry_hash: string = i < legacy ? crypto.createHash("sha256").update(`legacy-${i}`).digest("hex") : auditEntryHash(prev, base.event_type, base.actor_email, base.payload, created_at);
    rows.push({ id: i + 1, org_id: "org-1", ...base, prev_hash: prev, entry_hash, created_at });
    prev = entry_hash;
  }
  return rows;
}

const genEd = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return { privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string, publicPem: publicKey.export({ type: "spki", format: "pem" }) as string };
};
const saved = { priv: process.env.EXPORT_SIGNING_PRIVATE_KEY, hmac: process.env.EXPORT_SIGNING_KEY };
const setPriv = (pem?: string) => { if (pem) process.env.EXPORT_SIGNING_PRIVATE_KEY = pem; else delete process.env.EXPORT_SIGNING_PRIVATE_KEY; _resetExportKeyCache(); };
const dir = mkdtempSync(join(tmpdir(), "audit-export-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
afterEach(() => {
  setPriv(saved.priv);
  if (saved.hmac === undefined) delete process.env.EXPORT_SIGNING_KEY; else process.env.EXPORT_SIGNING_KEY = saved.hmac;
});

const seed = (events: Ev[], opts: Parameters<typeof fakeSupabase>[1] = {}) => {
  db = fakeSupabase({
    organizations: [{ id: "org-1", name: "Acme", slug: "acme" }],
    org_members: [{ id: "m1", org_id: "org-1", user_id: "u-admin", email: "admin@acme.dev", role: "admin", custom_role_id: null }],
    audit_log: events as unknown as Record<string, unknown>[],
  }, opts);
};
const fetchExport = (format: "json" | "csv", query = "") =>
  signedGET(new NextRequest(new URL(`https://app.example/api/export/signed?format=${format}${query}`)));
let n = 0;
const save = (name: string, content: string) => { const f = join(dir, `${++n}-${name}`); writeFileSync(f, content); return f; };
const run = (file: string, ...args: string[]) => {
  const r = spawnSync(process.execPath, [SCRIPT, file, ...args], { encoding: "utf8" });
  return { code: r.status, out: r.stdout ? JSON.parse(r.stdout) : null, err: r.stderr };
};
const withKey = () => { const k = genEd(); setPriv(k.privatePem); delete process.env.EXPORT_SIGNING_KEY; return { ...k, keyFile: save("trusted.pem", k.publicPem) }; };
const splitCsv = (csv: string) => { const at = csv.lastIndexOf(MARKER + "\n"); return { body: csv.slice(0, at), footer: csv.slice(at) }; };

describe("complete or nothing", () => {
  it("exports every event, even when the log is longer than the database's 1000-row response cap", async () => {
    withKey();
    seed(chain(1242), { maxRows: 1000 });
    const out = await (await fetchExport("json")).json();
    expect(out.events).toHaveLength(1242);
    expect(out.metadata.event_count).toBe(1242);
    expect(new Set(out.events.map((e: { id: number }) => e.id)).size).toBe(1242);
    // each export writes its own "data exported" audit entry, so start the second one from the same log
    seed(chain(1242), { maxRows: 1000 });
    const csv = await (await fetchExport("csv")).text();
    expect(parseCsv(splitCsv(csv).body.split("\n\n")[1]).length - 1).toBe(1242);
  });

  it("refuses to sign (503, no signature) when the server shortens pages below the page size", async () => {
    withKey();
    seed(chain(1242), { maxRows: 500 });                      // a page of 500 looks like the last page; the count says otherwise
    const res = await fetchExport("json");
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ error: "export_incomplete", reason: "row_count_mismatch" });
    expect(res.headers.get("X-TrustLedger-Signature")).toBeNull();
  });

  it.each([
    ["the events cannot be read", 1, "read_failed"],
    ["the row count cannot be read", 2, "read_failed"],
    ["the hash chain cannot be read", 3, "chain_unreadable"],
  ])("refuses to sign when %s", async (_what, failingCall, reason) => {
    withKey();
    seed(chain(5), { errorFor: (table, call) => (table === "audit_log" && call === failingCall ? { message: "db down" } : null) });
    for (const format of ["json", "csv"] as const) {
      // the failure applies to the n-th audit_log read of the fresh client; reseed so each format starts from call 1
      seed(chain(5), { errorFor: (table, call) => (table === "audit_log" && call === failingCall ? { message: "db down" } : null) });
      const res = await fetchExport(format);
      expect(res.status).toBe(503);
      const body = await res.json();
      expect(body).toMatchObject({ error: "export_incomplete", reason });
      expect(JSON.stringify(body)).not.toContain("signature");
      expect(res.headers.get("X-TrustLedger-Signature")).toBeNull();
    }
  });

  it("an empty period is a complete export of nothing, not a failure", async () => {
    withKey();
    seed(chain(5));
    const res = await fetchExport("json", `&period_start=2020-01-01T00:00:00Z&period_end=2020-01-02T00:00:00Z`);
    expect(res.status).toBe(200);
    expect((await res.json()).events).toEqual([]);
  });
});

describe("JSON export, verified offline", () => {
  it("verifies with the trusted key", async () => {
    const k = withKey(); seed(chain(40));
    const file = save("audit.json", await (await fetchExport("json")).text());
    const r = run(file, k.keyFile);
    expect(r.code).toBe(0);
    expect(r.out).toMatchObject({ kind: "json", signature: "valid", key_trusted: true, events: 40, events_declared: 40, problems: [] });
    expect(r.out.rows).toMatchObject({ checked: 40, verified: 40, legacy: 0, broken_at: null });
  });

  it("fails when an event was changed, dropped or added after signing", async () => {
    const k = withKey(); seed(chain(10));
    const doc = JSON.parse(await (await fetchExport("json")).text());
    const changed = JSON.parse(JSON.stringify(doc)); changed.events[4].payload.n = 999;
    const dropped = JSON.parse(JSON.stringify(doc)); dropped.events.splice(4, 1);
    const droppedFixedCount = JSON.parse(JSON.stringify(dropped)); droppedFixedCount.metadata.event_count = 9;
    for (const [name, d] of [["changed", changed], ["dropped", dropped], ["dropped-recounted", droppedFixedCount]] as const) {
      const r = run(save(`${name}.json`, JSON.stringify(d)), k.keyFile);
      expect({ name, code: r.code }).toEqual({ name, code: 1 });
      expect(r.out.signature).toBe("invalid");
    }
    expect(run(save("dropped.json", JSON.stringify(dropped)), k.keyFile).out.problems.join(" ")).toMatch(/declares 10 events but contains 9/);
  });
});

describe("CSV export signs its own bytes", () => {
  it("carries the columns the audit hash needs and a signature block below a marker", async () => {
    withKey(); seed(chain(6));
    const csv = await (await fetchExport("csv")).text();
    const { body, footer } = splitCsv(csv);
    expect(body).toContain("# Format: trustledger-audit-csv/2");
    expect(body).toContain("# Events: 6");
    expect(body).toContain("id,event_type,actor_email,resource_type,resource_id,payload,prev_hash,entry_hash,created_at,actor_id");
    expect(footer).toMatch(/^# --- signature ---\n# Signature \(Ed25519\): [A-Za-z0-9+/=]+\n/);
    expect(footer).toContain("# Public key (SPKI, base64): ");
    expect(footer).toContain("# Public key id: ");
    // the signature is over exactly the bytes above the marker
    const sig = /# Signature \(Ed25519\): (\S+)/.exec(footer)![1];
    const pub = crypto.createPublicKey({ key: Buffer.from(/# Public key \(SPKI, base64\): (\S+)/.exec(footer)![1], "base64"), format: "der", type: "spki" });
    expect(crypto.verify(null, Buffer.from(body), pub, Buffer.from(sig, "base64"))).toBe(true);
  });

  it("verifies offline from the CSV alone: signature, event count, every entry's hash and every link", async () => {
    const k = withKey(); seed(chain(60));
    const r = run(save("audit.csv", await (await fetchExport("csv")).text()), k.keyFile);
    expect(r.code).toBe(0);
    expect(r.out).toMatchObject({ kind: "csv", signature: "valid", key_trusted: true, events: 60, events_declared: 60, problems: [], chain_integrity_claimed: "VERIFIED" });
    expect(r.out.rows).toMatchObject({ checked: 60, verified: 60, legacy: 0, broken_at: null });
  });

  it("older entries whose hash cannot be recomputed are counted as legacy, not as tampering", async () => {
    const k = withKey(); seed(chain(8, undefined, 3));
    const r = run(save("legacy.csv", await (await fetchExport("csv")).text()), k.keyFile);
    expect(r.code).toBe(0);
    expect(r.out.rows).toMatchObject({ checked: 8, verified: 5, legacy: 3 });
  });

  it("fails when a cell is changed, a row removed, or a row added", async () => {
    const k = withKey(); seed(chain(10));
    const csv = await (await fetchExport("csv")).text();
    const lines = csv.split("\n");
    const firstRow = lines.findIndex(l => l.startsWith("1,scan_complete"));
    const changed = [...lines]; changed[firstRow + 3] = changed[firstRow + 3].replace("scan_complete", "attestation");
    const removed = [...lines]; removed.splice(firstRow + 3, 1);
    const added = [...lines]; added.splice(firstRow + 3, 0, lines[firstRow + 3]);
    for (const [name, text] of [["changed", changed], ["removed", removed], ["added", added]] as const) {
      const r = run(save(`${name}.csv`, text.join("\n")), k.keyFile);
      expect({ name, code: r.code }).toEqual({ name, code: 1 });
      expect(r.out.signature).toBe("invalid");
    }
    expect(run(save("removed.csv", removed.join("\n")), k.keyFile).out.problems.join(" ")).toMatch(/declares 10 events but contains 9/);
  });

  it("a header edit (claiming the chain is fine, or another count) breaks the signature", async () => {
    const k = withKey(); seed(chain(5));
    const csv = (await (await fetchExport("csv")).text()).replace("# Events: 5", "# Events: 4");
    expect(run(save("count.csv", csv), k.keyFile).out.signature).toBe("invalid");
  });

  it("hostile values cannot become formulas or fake a signature block, and the file still verifies", async () => {
    const k = withKey();
    const hostile = [
      '=HYPERLINK("https://evil.example","click")', "+cmd|' /C calc'!A0", "@SUM(1+1)", "-2+3", "'=quoted", "\t=tab",
      `fake\n${MARKER}\n# Signature (Ed25519): AAAA\n# Public key id: 0000000000000000`, 'quote " and, comma', "line\r\nbreak",
    ];
    seed(chain(hostile.length, i => ({ actor_email: hostile[i], resource_id: hostile[(i + 1) % hostile.length], payload: { note: hostile[i] } })));
    const csv = await (await fetchExport("csv")).text();
    const rows = parseCsv(splitCsv(csv).body.split("\n\n")[1]).slice(1);
    expect(rows).toHaveLength(hostile.length);
    for (const row of rows) for (const cell of row) expect(/^[=+\-@\t\r]/.test(cell)).toBe(false);
    const r = run(save("hostile.csv", csv), k.keyFile);
    expect(r.code).toBe(0);
    expect(r.out).toMatchObject({ signature: "valid", events: hostile.length, problems: [] });
    expect(r.out.rows.verified).toBe(hostile.length);
  });

  it("is self-consistent but not trusted when re-signed with someone else's key and the real key is pinned", async () => {
    const k = withKey(); seed(chain(5));
    const { body } = splitCsv(await (await fetchExport("csv")).text());
    const evil = genEd();
    const evilSig = crypto.sign(null, Buffer.from(body), crypto.createPrivateKey(evil.privatePem)).toString("base64");
    const spki = evil.publicPem.replace(/-----(?:BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
    const forged = `${body}${MARKER}\n# Signature (Ed25519): ${evilSig}\n# Public key id: ${keyIdFromPem(evil.publicPem)}\n# Public key (SPKI, base64): ${spki}\n`;
    const file = save("forged.csv", forged);
    expect(run(file).out.signature).toBe("valid");             // nothing pinned: the file only agrees with itself
    const pinned = run(file, k.keyFile);
    expect(pinned.code).toBe(1);
    expect(pinned.out.key_trusted).toBe(false);
    expect(pinned.out.problems.join(" ")).toMatch(/not the trusted key/);
  });

  it("verifies a file that was saved with Windows line endings, and says so", async () => {
    const k = withKey(); seed(chain(5));
    const r = run(save("crlf.csv", (await (await fetchExport("csv")).text()).replace(/\n/g, "\r\n")), k.keyFile);
    expect(r.code).toBe(0);
    expect(r.out.note).toMatch(/CRLF/);
  });

  it("the legacy HMAC export can only be checked with the shared secret", async () => {
    setPriv(undefined); process.env.EXPORT_SIGNING_KEY = "shared-secret";
    seed(chain(5));
    const file = save("hmac.csv", await (await fetchExport("csv")).text());
    const none = run(file);
    expect(none.code).toBe(1);
    expect(none.out.signature).toBe("unverifiable");
    expect(run(file, "--hmac-key", "shared-secret")).toMatchObject({ code: 0, out: { signature: "valid", signature_algo: "HMAC-SHA256" } });
    expect(run(file, "--hmac-key", "wrong").code).toBe(1);
  });

  it("exits 2 with a message for a file that is not an audit export", () => {
    expect(run(save("junk.csv", "a,b\n1,2\n")).code).toBe(2);
    expect(run(save("junk.json", "{}")).code).toBe(2);
  });
});

describe("hash v2 entries (org, actor and resource covered), verified offline", () => {
  /** Like chain(), but every entry is v2-hashed and carries its actor_id. */
  function chainV2(n: number, fork = false): Array<Ev & { actor_id: string }> {
    const rows: Array<Ev & { actor_id: string }> = [];
    let prev: string | null = null;
    for (let i = 0; i < n; i++) {
      const created_at = new Date(T0 + i * 1000).toISOString();
      const f = { event_type: "member_role_changed", actor_id: `user-${i}`, actor_email: `ana${i}@acme.dev`, resource_type: "member", resource_id: `m${i}`, payload: { n: i } };
      const parent: string | null = fork && i === n - 1 ? rows[0].entry_hash : prev;   // the last entry claims the FIRST as its parent
      const entry_hash: string = auditEntryHashV2({ ...f, prev_hash: parent, org_id: "org-1", created_at });
      rows.push({ id: i + 1, org_id: "org-1", ...f, prev_hash: parent, entry_hash, created_at });
      prev = entry_hash;
    }
    return rows;
  }

  it("the CSV carries actor_id and the offline script verifies every entry with its metadata", async () => {
    const k = withKey(); seed(chainV2(12));
    const csv = await (await fetchExport("csv")).text();
    expect(csv).toContain("# Format: trustledger-audit-csv/2");
    expect(csv).toContain("# Chain integrity: VERIFIED");
    expect(csv).toContain(",actor_id\n");
    const r = run(save("v2.csv", csv), k.keyFile);
    expect(r.code).toBe(0);
    expect(r.out.rows).toMatchObject({ checked: 12, verified: 12, metadata_verified: 12, legacy: 0, broken_at: null });
  });

  it("the JSON export verifies offline too", async () => {
    const k = withKey(); seed(chainV2(8));
    const r = run(save("v2.json", await (await fetchExport("json")).text()), k.keyFile);
    expect(r.code).toBe(0);
    expect(r.out.rows).toMatchObject({ checked: 8, verified: 8, metadata_verified: 8 });
  });

  it("a forked chain is exported as NOT CLEAN, never as VERIFIED, and the offline script fails it", async () => {
    const k = withKey(); seed(chainV2(6, true));
    const res = await fetchExport("csv");
    expect(res.headers.get("X-TrustLedger-Chain-Valid")).toBe("false");
    const csv = await res.text();
    expect(csv).toContain("# Chain integrity: NOT CLEAN (forked");
    expect(csv).not.toContain("# Chain integrity: VERIFIED");
    const r = run(save("fork.csv", csv), k.keyFile);
    expect(r.code).not.toBe(0);
    expect(r.out.problems.join(" ")).toMatch(/fork/);
  });
});
