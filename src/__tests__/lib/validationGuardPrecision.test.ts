import { runScan } from "@/lib/scanner";

/**
 * Precision: a value that has passed a full-match regex or a validator.js type check (isUUID, isInt, ...) can no longer carry an
 * injection payload. A guard that proves nothing (unanchored regex, a class allowing quotes, a check on another variable, the wrong
 * side of the branch) leaves the finding.
 */
const find = (id: string, body: string) => {
  const code = `import express from "express";\nconst app = express();\napp.get("/x", async (req, res) => {\n${body}\n});\n`;
  return runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "src/a.ts", content: code }] })
    .files[0].indicators.filter(i => i.id === id);
};
const SQL = (guard: string, q = "SELECT * FROM t WHERE id='\" + id + \"'") => `  const id = String(req.query.id);\n  ${guard}\n  await db.query("${q}");\n  res.end();`;

describe("anchored regex test as a guard", () => {
  it("a full match of letters, digits and underscore clears the value", () => {
    expect(find("sql-injection", SQL("if (!/^[a-z0-9_]+$/i.test(id)) return res.status(400).end();"))).toHaveLength(0);
  });
  it("an unanchored pattern proves nothing", () => {
    expect(find("sql-injection", SQL("if (!/[a-z0-9_]+/i.test(id)) return res.status(400).end();")).length).toBeGreaterThan(0);
  });
  it("a class that allows quotes proves nothing for SQL", () => {
    expect(find("sql-injection", SQL("if (!/^[a-z0-9_' ]+$/i.test(id)) return res.status(400).end();")).length).toBeGreaterThan(0);
  });
  it("the wrong side of the branch (rejecting the safe values) proves nothing", () => {
    expect(find("sql-injection", SQL("if (/^[a-z0-9_]+$/i.test(id)) return res.status(400).end();")).length).toBeGreaterThan(0);
  });
  it("a check on a different variable proves nothing", () => {
    expect(find("sql-injection", SQL("if (!/^[a-z0-9_]+$/i.test(String(req.query.other))) return res.status(400).end();")).length).toBeGreaterThan(0);
  });
});

describe("validator.js type checks as a guard", () => {
  it("validator.isUUID", () => {
    expect(find("sql-injection", SQL("if (!validator.isUUID(id)) return res.status(400).end();"))).toHaveLength(0);
  });
  it("validator.isInt", () => {
    expect(find("sql-injection", SQL("if (!validator.isInt(id)) return res.status(400).end();"))).toHaveLength(0);
  });
  it("validator.isEmail is not a safe-alphabet proof (quotes are valid in an address)", () => {
    expect(find("sql-injection", SQL("if (!validator.isEmail(id)) return res.status(400).end();")).length).toBeGreaterThan(0);
  });
  it("a look-alike on another object is not validator.js", () => {
    expect(find("sql-injection", SQL("if (!myThing.isUUID(id)) return res.status(400).end();")).length).toBeGreaterThan(0);
  });
  it("no guard at all", () => {
    expect(find("sql-injection", SQL("")).length).toBeGreaterThan(0);
  });
});

describe("a lookup in a table of constants", () => {
  const ORDER = (setup: string) => `${setup}\n  await db.query("SELECT * FROM t ORDER BY " + col);\n  res.end();`;
  it("an inline table with a default", () => {
    expect(find("sql-injection", ORDER("  const col = ({ name: \"name\", date: \"created_at\" } as Record<string, string>)[String(req.query.sort)] ?? \"name\";"))).toHaveLength(0);
  });
  it("a const table with a default", () => {
    expect(find("sql-injection", ORDER("  const SORTS = { name: \"name\", date: \"created_at\" };\n  const col = SORTS[String(req.query.sort)] ?? \"name\";"))).toHaveLength(0);
  });
  it("a table with one value taken from the request is still reported", () => {
    expect(find("sql-injection", ORDER("  const SORTS = { name: \"name\", other: String(req.query.col) };\n  const col = SORTS[String(req.query.sort)] ?? \"name\";")).length).toBeGreaterThan(0);
  });
  it("the request value itself with a default is still reported", () => {
    expect(find("sql-injection", ORDER("  const col = String(req.query.sort) ?? \"name\";")).length).toBeGreaterThan(0);
  });
  it("a table that spreads in other data is still reported", () => {
    expect(find("sql-injection", ORDER("  const SORTS = { name: \"name\", ...req.query };\n  const col = SORTS[String(req.query.sort)] ?? \"name\";")).length).toBeGreaterThan(0);
  });
});

describe("the multiline flag defeats an anchored regex guard", () => {
  it("/^[a-z0-9_]+$/m does not confine a value that has a second line", () => {
    expect(find("sql-injection", SQL("if (!/^[a-z0-9_]+$/m.test(id)) return res.status(400).end();")).length).toBeGreaterThan(0);
  });
});
