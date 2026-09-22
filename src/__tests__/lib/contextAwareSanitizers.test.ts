import { runScan } from "@/lib/scanner";

// Context-aware sanitizer checks (item 5 of the roadmap): HTML-escaping neutralizes the HTML-BODY
// context specifically -- it doesn't make a value safe inside a <script> block (already covered
// across all six engines from an earlier phase) or an UNQUOTED HTML attribute value (new here).

function xssDetails(content: string): string[] {
  const result = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "src/route.ts", content }] });
  return result.files[0].indicators.filter(i => i.id === "xss").map(i => i.detail ?? "");
}

const HEAD = `function escapeHtml(s){return s.replace(/</g,"&lt;");}\n`;

describe("unquoted HTML attribute context", () => {
  it("flags an HTML-escaped value dropped into an unquoted attribute", () => {
    const code = `${HEAD}app.get("/x", (req, res) => {
  const v = escapeHtml(req.query.value);
  document.write(\`<div title=\${v}>\`);
});`;
    const details = xssDetails(code);
    expect(details.some(d => /unquoted/i.test(d))).toBe(true);
  });

  it("does not flag the same value when the attribute IS quoted", () => {
    const code = `${HEAD}app.get("/x", (req, res) => {
  const v = escapeHtml(req.query.value);
  document.write(\`<div title="\${v}">\`);
});`;
    expect(xssDetails(code)).toEqual([]);
  });

  it("does not flag a value that sits in the HTML body, not an attribute", () => {
    const code = `${HEAD}app.get("/x", (req, res) => {
  const v = escapeHtml(req.query.value);
  document.write(\`<div>\${v}</div>\`);
});`;
    expect(xssDetails(code)).toEqual([]);
  });

  it("still flags an UNescaped value in an unquoted attribute via the ordinary XSS sink check (not this context check specifically)", () => {
    const code = `app.get("/x", (req, res) => {
  document.write(\`<div title=\${req.query.value}>\`);
});`;
    expect(xssDetails(code).length).toBeGreaterThan(0);
  });
});
