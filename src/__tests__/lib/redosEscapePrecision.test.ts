import { runScan } from "@/lib/scanner";

/**
 * Precision: a value put through the standard regex-escape before it becomes a RegExp can only match literally, so it is not a ReDoS
 * sink. An unescaped value, or an escape that misses pattern characters, still is.
 */
const redos = (body: string) => {
  const content = `import express from "express";\nconst app = express();\napp.get("/s", (req, res) => {\n  const q = String(req.query.q);\n  ${body}\n  res.send("ok");\n});\n`;
  const r = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "src/app.ts", content }] });
  return r.files[0].indicators.filter(i => i.id === "redos");
};

describe("regex-escaped input is not a ReDoS sink", () => {
  it("the standard escape idiom, in a template", () => {
    expect(redos("const re = new RegExp(`\\\\b${q.replace(/[.*+?^${}()|[\\]\\\\]/g, \"\\\\$&\")}\\\\b`, \"i\");")).toHaveLength(0);
  });
  it("a named escape helper, and RegExp.escape", () => {
    expect(redos("const re = new RegExp(escapeRegExp(q));")).toHaveLength(0);
    expect(redos("const re = new RegExp(RegExp.escape(q));")).toHaveLength(0);
  });
  it("escaped parts joined with literals", () => {
    expect(redos("const re = new RegExp(\"^\" + escapeRegex(q) + \"$\");")).toHaveLength(0);
  });
});

describe("still flagged when not really escaped", () => {
  it("raw request input", () => {
    expect(redos("const re = new RegExp(q);").length).toBeGreaterThan(0);
  });
  it("a template with one unescaped substitution", () => {
    expect(redos("const re = new RegExp(`^${escapeRegExp(q)}${req.query.suffix}$`);").length).toBeGreaterThan(0);
  });
  it("a replace that misses pattern characters (only dots) is not an escape", () => {
    expect(redos("const re = new RegExp(q.replace(/\\./g, \"\\\\$&\"));").length).toBeGreaterThan(0);
  });
  it("a replace whose replacement does not put a backslash in front", () => {
    expect(redos("const re = new RegExp(q.replace(/[.*+?^${}()|[\\]\\\\]/g, \"$&\"));").length).toBeGreaterThan(0);
  });
});
