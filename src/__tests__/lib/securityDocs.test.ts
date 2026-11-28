/**
 * @jest-environment node
 *
 * The security documentation stays true: what SECURITY.md promises matches what the site publishes and what the code does, the
 * subprocessor list, retention limits and certification statements agree across SECURITY.md, the data-handling document and the Trust
 * Center, and /.well-known/security.txt is a valid RFC 9116 file.
 */
import fs from "fs";
import path from "path";
import { NextRequest } from "next/server";
import { GET as securityTxt } from "@/app/.well-known/security.txt/route";
import { PRIMARY_CONTACT, SECURITY_ACK_BUSINESS_DAYS, securityContact } from "@/lib/contacts";
import { MIN_DAYS, MAX_DAYS } from "@/lib/retention";

const ROOT = path.join(__dirname, "../../..");
const read = (p: string) => fs.readFileSync(path.join(ROOT, p), "utf8");
const SECURITY = read("SECURITY.md");
const DATA = read("docs/security/data-handling.md");
const INCIDENT = read("docs/security/incident-response.md");
const TRUST = read("src/app/trust/page.tsx");
const PRIVACY = read("src/app/privacy/page.tsx");

const saved = { c: process.env.NEXT_PUBLIC_SECURITY_CONTACT, d: process.env.NEXT_PUBLIC_CONTACT_DOMAIN, u: process.env.NEXT_PUBLIC_APP_URL };
afterEach(() => {
  for (const [k, v] of [["NEXT_PUBLIC_SECURITY_CONTACT", saved.c], ["NEXT_PUBLIC_CONTACT_DOMAIN", saved.d], ["NEXT_PUBLIC_APP_URL", saved.u]] as const) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});

describe("SECURITY.md matches what the site publishes", () => {
  it("names the address the site publishes by default, and the same acknowledgement time", () => {
    delete process.env.NEXT_PUBLIC_SECURITY_CONTACT; delete process.env.NEXT_PUBLIC_CONTACT_DOMAIN;
    expect(securityContact()).toBe(PRIMARY_CONTACT);
    expect(SECURITY).toContain(PRIMARY_CONTACT);
    expect(SECURITY).toContain(`within **${SECURITY_ACK_BUSINESS_DAYS} business days**`);
  });

  it("promises customer notification within 72 hours, the same in SECURITY.md, the incident runbook and the Trust Center", () => {
    for (const text of [SECURITY, INCIDENT, TRUST]) expect(text).toMatch(/72 hours/);
  });

  it("links to every document it relies on, and they exist", () => {
    for (const link of ["docs/security/incident-response.md", "docs/security/data-handling.md", "docs/security/secret-detection.md", "docs/operations/runbook.md", "docs/operations/backup-and-restore.md"]) {
      expect(SECURITY).toContain(link);
      expect(fs.existsSync(path.join(ROOT, link))).toBe(true);
    }
  });

  it("says plainly what is not certified, and claims no certification we do not hold", () => {
    for (const text of [SECURITY, DATA]) {
      expect(text).toMatch(/SOC 2[^\n]*not certified|not certified[^\n]*SOC 2/i);
      expect(text).toMatch(/ISO 27001[^\n]*not certified|not certified[^\n]*ISO 27001/i);
      expect(text).toMatch(/penetration test[^\n]*(not yet performed|has been performed yet|No independent)|No independent penetration test/i);
    }
    // nowhere on the public pages or in these documents is a certification claimed
    const claims = /(we are|is|are|now|fully|officially)\s+(SOC ?2|ISO ?27001)[- ]?(Type\s?(I|II|1|2))?\s*(certified|compliant|audited)|SOC ?2 Type (I|II) (report|certified)/i;
    for (const text of [SECURITY, DATA, TRUST, PRIVACY]) expect(text).not.toMatch(claims);
    expect(TRUST).toMatch(/SOC 2:<\/strong> not certified/);
    expect(TRUST).toMatch(/ISO 27001:<\/strong> not certified/);
  });
});

describe("the data-handling document agrees with the code and the Trust Center", () => {
  it("states the retention window limits the code enforces", () => {
    expect(MIN_DAYS).toBe(30);
    expect(MAX_DAYS).toBe(2555);                                        // 7 years
    expect(DATA).toMatch(/between \*\*30 days and 7 years\*\*/);
    expect(TRUST).toMatch(/between 30 days and 7 years/);
  });

  it("lists the same subprocessors as the Trust Center: every provider in the document is on the page, and every row on the page is in the document", () => {
    const section = DATA.slice(DATA.indexOf("## 6. Subprocessors"), DATA.indexOf("## 7."));
    const fromDoc = [...section.matchAll(/^\| ([^|]+?) \| [^|]+ \| [^|]+ \|$/gm)].map(m => m[1].trim()).filter(n => n !== "Provider" && !/^-+$/.test(n));
    expect(fromDoc.length).toBe(8);
    for (const provider of fromDoc) expect(TRUST).toContain(provider);
    // the page's own table rows: ["Provider", "Purpose", "Data"] triples after the Subprocessors heading
    const page = TRUST.slice(TRUST.indexOf('id="subprocessors"'), TRUST.indexOf('id="disclosure"'));
    const fromPage = [...page.matchAll(/\[\s*"([^"]+)",\s*"[^"]+",\s*"[^"]+"\s*\]/g)].map(m => m[1]);
    expect([...fromPage].sort()).toEqual([...fromDoc].sort());
  });

  it("describes deletion the way the product does: a typed name, a step-up, a waiting period you can cancel, evidence kept", () => {
    for (const text of [DATA, TRUST.replace(/&apos;/g, "'")]) {
      expect(text).toMatch(/24 hours/);
      expect(text).toMatch(/cancel/i);
      expect(text).toMatch(/audit log, attestations and (signed )?(audit )?checkpoints/i);
    }
    expect(PRIVACY).toMatch(/audit log, attestations and signed audit checkpoints/);
  });

  it("says how retention is applied, and that it depends on the daily maintenance cron actually being scheduled", () => {
    expect(DATA).toMatch(/daily maintenance run/);
    expect(read("docs/operations/runbook.md")).toMatch(/daily maintenance run/);
    const crons = (JSON.parse(read("vercel.json")).crons ?? []) as Array<{ path: string; schedule: string }>;
    expect(crons.map(c => c.path)).toContain("/api/cron/pipeline-health");
  });

  it("every control it names exists: the sealing key, hashed API keys, the signing keys, the org two-factor requirement", () => {
    expect(read("src/lib/secretBox.ts")).toContain("DATA_ENCRYPTION_KEY");
    expect(read("src/app/api/_middleware.ts")).toContain("mfa_enrollment_required");
    expect(read("src/app/api/keys/route.ts")).toContain('createHash("sha256")');
    expect(read("src/lib/exportSigning.ts")).toContain("EXPORT_SIGNING_PRIVATE_KEY");
    expect(fs.existsSync(path.join(ROOT, "src/app/.well-known/trustledger-export-signing-key/route.ts"))).toBe(true);
  });
});

describe("/.well-known/security.txt (RFC 9116)", () => {
  const fetchTxt = (origin = "https://app.example.com") => {
    process.env.NEXT_PUBLIC_APP_URL = origin;
    return securityTxt(new NextRequest(new URL("/.well-known/security.txt", origin)));
  };
  const fields = (text: string) => text.split("\n").filter(l => l && !l.startsWith("#")).map(l => { const i = l.indexOf(":"); return [l.slice(0, i), l.slice(i + 1).trim()] as const; });

  it("is plain UTF-8 text with the required Contact and Expires fields", async () => {
    const res = await fetchTxt();
    expect(res.headers.get("Content-Type")).toMatch(/^text\/plain; charset=utf-8/);
    const f = fields(await res.text());
    expect(f.filter(([k]) => k === "Contact").length).toBeGreaterThanOrEqual(1);
    expect(f.filter(([k]) => k === "Expires").length).toBe(1);                // exactly one, as the RFC requires
  });

  it("Contact is a mailto: of the published security address", async () => {
    delete process.env.NEXT_PUBLIC_SECURITY_CONTACT; delete process.env.NEXT_PUBLIC_CONTACT_DOMAIN;
    const contact = fields(await (await fetchTxt()).text()).find(([k]) => k === "Contact")![1];
    expect(contact).toBe(`mailto:${PRIMARY_CONTACT}`);
    process.env.NEXT_PUBLIC_CONTACT_DOMAIN = "acme.com";
    expect(fields(await (await fetchTxt()).text()).find(([k]) => k === "Contact")![1]).toBe("mailto:security@acme.com");
  });

  it("Expires is an ISO 8601 UTC time in the future and less than a year away", async () => {
    const expires = fields(await (await fetchTxt()).text()).find(([k]) => k === "Expires")![1];
    expect(expires).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/);
    const ms = Date.parse(expires) - Date.now();
    expect(ms).toBeGreaterThan(30 * 86400_000);
    expect(ms).toBeLessThan(365 * 86400_000);
  });

  it("Canonical and Policy are https URLs on the configured site (not whatever Host header the request carried)", async () => {
    const res = await securityTxt(new NextRequest("https://evil.example/.well-known/security.txt", { headers: { host: "evil.example" } }));
    process.env.NEXT_PUBLIC_APP_URL = "https://app.example.com";
    const f = fields(await (await fetchTxt("https://app.example.com")).text());
    expect(f.find(([k]) => k === "Canonical")![1]).toBe("https://app.example.com/.well-known/security.txt");
    expect(f.find(([k]) => k === "Policy")![1]).toBe("https://app.example.com/security");
    void res;
  });

  it("every line is a known field or a comment (no stray text a parser would reject)", async () => {
    const known = new Set(["Contact", "Expires", "Preferred-Languages", "Canonical", "Policy", "Acknowledgments", "Encryption", "Hiring"]);
    for (const [k] of fields(await (await fetchTxt()).text())) expect(known.has(k)).toBe(true);
  });
});
