import { runScan } from "@/lib/scanner";

/**
 * Precision, line-pattern layer: a constant multi-line <style>/<script> block in dangerouslySetInnerHTML is not XSS, and a stack
 * handed to a logger is not sent to the client. The same constructs with something the request controls, or sent in a response, are
 * still reported.
 */
const ids = (path: string, content: string, id: string) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] }).files[0].indicators.filter(i => i.id === id);

describe("dangerouslySetInnerHTML with a constant multi-line literal", () => {
  it("a static <style> block is not XSS", () => {
    const code = "export default function P() {\n  return <style dangerouslySetInnerHTML={{ __html:`\n    .a { display:none; }\n    .b { color:red; }\n  `}} />;\n}\n";
    expect(ids("src/p.tsx", code, "xss")).toHaveLength(0);
  });
  it("an interpolated multi-line literal is still reported", () => {
    const code = "export default function P({ css }: { css: string }) {\n  return <style dangerouslySetInnerHTML={{ __html:`\n    .a { color:${css}; }\n  `}} />;\n}\n";
    expect(ids("src/p.tsx", code, "xss").length).toBeGreaterThan(0);
  });
  it("a variable is still reported", () => {
    const code = "export default function P({ html }: { html: string }) {\n  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n";
    expect(ids("src/p.tsx", code, "xss").length).toBeGreaterThan(0);
  });
});

describe("a stack that goes to a logger is not a verbose error to the client", () => {
  it("stack as a field of a recordEvent call", () => {
    const code = "import { NextResponse } from \"next/server\";\nexport function fail(err: Error) {\n  void recordEvent({\n    kind: \"api.error\",\n    data: {\n      stack: err.stack,\n    },\n  });\n  return NextResponse.json({ error: \"failed\" }, { status: 500 });\n}\n";
    expect(ids("src/lib/e.ts", code, "verbose-error")).toHaveLength(0);
  });
  it("stack in the response body is still reported", () => {
    const code = "import { NextResponse } from \"next/server\";\nexport function fail(err: Error) {\n  return NextResponse.json({\n    stack: err.stack,\n  }, { status: 500 });\n}\n";
    expect(ids("src/lib/e.ts", code, "verbose-error").length).toBeGreaterThan(0);
  });
  it("a response opened after the logging call is still reported", () => {
    const code = "export function fail(err: Error, res: any) {\n  logger.error(\"x\");\n  res.status(500).json({\n    stack: err.stack,\n  });\n}\n";
    expect(ids("src/lib/e.ts", code, "verbose-error").length).toBeGreaterThan(0);
  });
});
