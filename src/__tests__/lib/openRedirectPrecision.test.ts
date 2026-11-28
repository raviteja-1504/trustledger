import { runScan } from "@/lib/scanner";

/**
 * Precision: a redirect whose destination starts with a literal same-site path (`/onboarding?...`) cannot change the host, whatever
 * is appended. A target the request can start, or one beginning `//` or `/\`, is still an open redirect.
 */
const redirects = (body: string) => {
  const content = `import express from "express";\nconst app = express();\napp.get("/go", (req, res) => {\n  const next = String(req.query.next);\n  ${body}\n});\n`;
  return runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "src/app.ts", content }] })
    .files[0].indicators.filter(i => i.id === "open-redirect");
};

describe("a literal same-site path is not an open redirect", () => {
  it("path with a query string built from the request", () => {
    expect(redirects("res.redirect(`/onboarding?next=${next}`);")).toHaveLength(0);
  });
  it("path concatenated with the request value", () => {
    expect(redirects("res.redirect(\"/items/\" + next);")).toHaveLength(0);
  });
});

describe("still flagged when the host can be chosen", () => {
  it("the raw value", () => {
    expect(redirects("res.redirect(next);").length).toBeGreaterThan(0);
  });
  it("a bare slash then the value (the value may start with another slash)", () => {
    expect(redirects("res.redirect(`/${next}`);").length).toBeGreaterThan(0);
  });
  it("a protocol-relative prefix", () => {
    expect(redirects("res.redirect(\"//\" + next);").length).toBeGreaterThan(0);
  });
  it("a backslash after the slash", () => {
    expect(redirects("res.redirect(\"/\\\\\" + next);").length).toBeGreaterThan(0);
  });
  it("a scheme-and-host prefix with a tainted host", () => {
    expect(redirects("res.redirect(\"https://\" + next);").length).toBeGreaterThan(0);
  });
});

describe("through a helper in another file", () => {
  const helper = "export function go(url: string) {\n  window.location.assign(url);\n}\n";
  const page = (call: string) => "import { go } from \"./nav\";\nexport function Page() {\n  const q = new URLSearchParams(window.location.search);\n  " + call + "\n}\n";
  const run = (call: string) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "src/nav.ts", content: helper }, { path: "src/page.tsx", content: page(call) }] })
    .files.flatMap(f => f.indicators).filter(i => i.id === "open-redirect");
  it("a same-site path with the query string appended is not reported", () => {
    expect(run("go(`/onboarding?${q.toString()}`);")).toHaveLength(0);
  });
  it("the raw query value is still reported", () => {
    expect(run("go(q.get(\"next\")!);").length).toBeGreaterThan(0);
  });
});
