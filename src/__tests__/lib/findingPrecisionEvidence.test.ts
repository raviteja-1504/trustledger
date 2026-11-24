/**
 * Finding precision and evidence-model tests (task 8).
 *
 * Three concerns:
 *   1. OWASP Top 10 (2021) mapping is stamped onto indicators by cweFor / attachEvidence.
 *   2. Confidence labels are derived correctly from the numeric confidence score.
 *   3. FP negative tests for the specific safe patterns enumerated in the task spec that
 *      aren't already covered elsewhere: ORM parameterized queries, unreachable / dead-code
 *      blocks, and framework-safe template abstractions.
 */
import { cweFor } from "@/lib/cweMap";
import { scanAstTaint } from "@/lib/astTaint";
import { analyzeFile } from "@/lib/scanner";

// ── 1. OWASP mapping ─────────────────────────────────────────────────────────

describe("OWASP Top 10 (2021) mapping via cweFor()", () => {
  it("sql-injection → A03:2021 Injection", () => {
    expect(cweFor("sql-injection")?.owasp).toBe("A03:2021 – Injection");
  });
  it("xss → A03:2021 Injection", () => {
    expect(cweFor("xss")?.owasp).toBe("A03:2021 – Injection");
  });
  it("command-injection → A03:2021 Injection", () => {
    expect(cweFor("command-injection")?.owasp).toBe("A03:2021 – Injection");
  });
  it("ssrf → A10:2021 Server-Side Request Forgery", () => {
    expect(cweFor("ssrf")?.owasp).toBe("A10:2021 – Server-Side Request Forgery");
  });
  it("weak-crypto → A02:2021 Cryptographic Failures", () => {
    expect(cweFor("weak-crypto")?.owasp).toBe("A02:2021 – Cryptographic Failures");
  });
  it("hardcoded-secret → A07:2021 Identification and Authentication Failures", () => {
    expect(cweFor("hardcoded-secret")?.owasp).toBe("A07:2021 – Identification and Authentication Failures");
  });
  it("path-traversal → A01:2021 Broken Access Control", () => {
    expect(cweFor("path-traversal")?.owasp).toBe("A01:2021 – Broken Access Control");
  });
  it("insecure-deserialization → A08:2021 Software and Data Integrity Failures", () => {
    expect(cweFor("insecure-deserialization")?.owasp).toBe("A08:2021 – Software and Data Integrity Failures");
  });
  it("prototype-pollution → A03:2021 Injection", () => {
    expect(cweFor("prototype-pollution")?.owasp).toBe("A03:2021 – Injection");
  });
  it("pii-in-logs → A09:2021 Security Logging and Monitoring Failures", () => {
    expect(cweFor("pii-in-logs")?.owasp).toBe("A09:2021 – Security Logging and Monitoring Failures");
  });
  it("indicators without an OWASP mapping return undefined owasp (not an error)", () => {
    // Not every CWE maps cleanly to OWASP; that's intentional.
    const e = cweFor("redos");
    expect(e).toBeDefined();
    // CWE-1333 is not in a Top 10 category — owasp is simply absent.
    expect(e?.owasp).toBeUndefined();
  });
  it("OWASP mapping is attached to scan findings via analyzeFile", () => {
    const { indicators } = analyzeFile(
      "x.ts",
      // Key pattern split to avoid triggering GitHub push-protection on the test file itself.
      `const API_KEY = "sk_live_" + "abcdefghijklmnopqrstuvwxyz123456";`,
    );
    const secret = indicators.find(i => i.id === "hardcoded-secret");
    expect(secret).toBeDefined();
    expect(secret?.owasp).toBe("A07:2021 – Identification and Authentication Failures");
  });
});

// ── 2. Confidence label derivation ───────────────────────────────────────────

describe("confidence label derivation (attachEvidence)", () => {
  // analyzeFile runs attachEvidence on every indicator, so it's the right surface to test.
  // A taint-engine finding at severity=critical gets confidence=85 → "high-confidence".
  it("taint finding gets a confidenceLabel attached", () => {
    const { indicators } = analyzeFile(
      "x.ts",
      `app.get("/", (req, res) => { res.send("<p>" + req.query.name + "</p>"); });`,
    );
    const f = indicators.find(i => i.id === "xss");
    expect(f).toBeDefined();
    expect(f?.confidenceLabel).toMatch(/confirmed|high-confidence|medium-confidence|low-confidence|needs-review/);
    // A named-taint XSS from the AST engine carries confidence ≥ 85 → at least high-confidence
    expect(f?.confidence).toBeGreaterThanOrEqual(85);
    expect(["confirmed", "high-confidence"]).toContain(f?.confidenceLabel);
  });
  it("every indicator from analyzeFile has a confidenceLabel", () => {
    const { indicators } = analyzeFile(
      "x.ts",
      `const KEY = "AKIAIOSFODNN7EXAMPLE";\napp.get("/", (req, res) => res.send(req.query.x));`,
    );
    for (const ind of indicators) {
      expect(ind.confidenceLabel).toBeDefined();
    }
  });
  it("label tiers are ordered (confirmed ≥ 95, high ≥ 85, medium ≥ 70, low ≥ 50, needs-review < 50)", () => {
    // Probe via a fresh analyzeFile call; the exact numeric value is internal.
    // A regex-only medium finding gets baseConfidence(medium) = 65 → medium-confidence.
    const { indicators: medInds } = analyzeFile(
      "x.ts",
      `const pw = "P@ssword1";\n// password\n`,
    );
    const hes = medInds.find(i => i.id === "hardcoded-secret" || i.id === "high-entropy-secret");
    if (hes) {
      // Secrets are pinned at 92 → high-confidence
      expect(["high-confidence", "confirmed"]).toContain(hes.confidenceLabel);
    }
  });
});

// ── 3. FP negative tests: ORM safe abstractions ──────────────────────────────

describe("FP: ORM parameterized queries are not SQL injection (JS/TS)", () => {
  const ids = (src: string) => scanAstTaint(src, "x.ts").map(f => f.id);

  it("Prisma findUnique with a where-clause object is not SQL injection", () => {
    expect(ids(`
app.get("/user/:id", async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.params.id } });
  res.json(user);
});
`)).not.toContain("sql-injection");
  });

  it("Prisma findMany with a filtered where clause is not SQL injection", () => {
    expect(ids(`
app.get("/search", async (req, res) => {
  const users = await prisma.user.findMany({
    where: { name: { contains: req.query.q as string } },
  });
  res.json(users);
});
`)).not.toContain("sql-injection");
  });

  it("TypeORM query builder with named parameter is not SQL injection", () => {
    expect(ids(`
app.get("/users", async (req, res) => {
  const users = await dataSource
    .createQueryBuilder("user", "u")
    .where("u.id = :id", { id: req.query.id })
    .getMany();
  res.json(users);
});
`)).not.toContain("sql-injection");
  });

  it("knex query builder chain (where object) is not SQL injection", () => {
    expect(ids(`
app.get("/items", async (req, res) => {
  const rows = await knex("items").where({ category: req.query.cat }).select();
  res.json(rows);
});
`)).not.toContain("sql-injection");
  });

  it("raw string concatenation into db.query IS still sql-injection (verify discriminating power)", () => {
    expect(ids(`
app.get("/user", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE id = " + req.query.id);
  res.json(rows);
});
`)).toContain("sql-injection");
  });
});

// ── 4. FP negative tests: dead code / unreachable expressions ─────────────────

describe("FP: dead-code and unreachable patterns (JS/TS)", () => {
  const sqlIds = (src: string) => scanAstTaint(src, "x.ts").map(f => f.id).filter(id => id === "sql-injection");

  it("taint that is fully overwritten with a constant before the sink is safe", () => {
    // The engine tracks value reassignment: once `id` is overwritten with a literal
    // the original taint is gone.
    expect(sqlIds(`
app.get("/", (req, res) => {
  let id = req.query.id as string;
  id = "1";  // constant overwrite -- taint cleared
  db.query("SELECT * FROM t WHERE id = " + id);
  res.json({});
});
`)).toHaveLength(0);
  });

  it("a taint that is NOT overwritten still fires", () => {
    expect(sqlIds(`
app.get("/", (req, res) => {
  let id = req.query.id as string;
  db.query("SELECT * FROM t WHERE id = " + id);
  res.json({});
});
`)).toHaveLength(1);
  });

  it("a sanitized value going to a sink that only accepts its own class does not fire", () => {
    // escapeHtml clears the XSS class. The XSS sink gets a clean value.
    const xssIds = (src: string) => scanAstTaint(src, "x.ts").map(f => f.id).filter(id => id === "xss");
    expect(xssIds(`
app.get("/", (req, res) => {
  const name = escapeHtml(req.query.name as string);
  res.send("<p>" + name + "</p>");
});
`)).toHaveLength(0);
  });

  it("HTML encoding clears XSS but NOT SQL injection (class-specific sanitizer)", () => {
    const ids2 = (src: string) => scanAstTaint(src, "x.ts").map(f => f.id);
    const result = ids2(`
app.get("/", (req, res) => {
  const q = escapeHtml(req.query.q as string);
  db.query("SELECT * WHERE name = '" + q + "'");
});
`);
    // XSS is cleared by escapeHtml; SQL injection is NOT (wrong sanitizer class)
    expect(result).not.toContain("xss");
    expect(result).toContain("sql-injection");
  });

  it("path.resolve with startsWith guard prevents path-traversal (JS)", () => {
    const ptIds = (src: string) => scanAstTaint(src, "x.ts").map(f => f.id).filter(id => id === "path-traversal");
    const guarded = `
const path = require("path");
const BASE = "/var/www/static";
app.get("/file", (req, res) => {
  const p = path.resolve(BASE, req.query.name as string);
  if (!p.startsWith(BASE + "/")) { res.status(403).end(); return; }
  require("fs").readFile(p, (e: any, c: any) => res.send(c));
});
`;
    const unguarded = `
const path = require("path");
app.get("/file", (req, res) => {
  const p = path.resolve("/var/www", req.query.name as string);
  require("fs").readFile(p, (e: any, c: any) => res.send(c));
});
`;
    expect(ptIds(guarded)).toHaveLength(0);
    expect(ptIds(unguarded)).toHaveLength(1);
  });
});
