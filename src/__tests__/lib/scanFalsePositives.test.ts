/**
 * @jest-environment node
 *
 * False positives found by scanning semgrep/semgrep, each with the counterpart that must still be reported:
 *  - a rule file of a pattern-matching analyser quotes vulnerable code as its pattern; that text is not project code;
 *  - a workflow pin file holds public commit SHAs under action names like "configure-aws-credentials";
 *  - a `nosem` / `nosec` comment is recorded on the finding, never used to hide it (a pull request's author wrote it).
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";
jest.setTimeout(300_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);
const scan = (path: string, content: string) =>
  runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] })
    .files[0].indicators.filter(i => i.line != null && i.id !== "ai-model-attribution");
const ids = (path: string, content: string) => scan(path, content).map(i => i.id);

const RULES = `rules:
  - id: exec-injection
    languages: [python]
    severity: ERROR
    message: Detected user input reaching exec(). Do not call os.system(cmd) with a request value.
    patterns:
      - pattern: os.system($X + request.args.get(...))
      - pattern-either:
          - pattern: subprocess.call(..., shell=True)
          - pattern: requests.get(..., verify=False)
`;

describe("a rule file of a pattern-matching analyser", () => {
  it("is not reported for the vulnerable code its patterns quote", () => {
    const found = ids("perf/rules/python.yml", RULES);
    expect(found).not.toContain("command-injection");
    expect(found).not.toContain("eval-exec");
    expect(found).not.toContain("tls-verification-disabled");
  });
  it("still reports a credential that leaked into it", () => {
    expect(ids("perf/rules/python.yml", RULES + `  - id: leak\n    message: token\n    pattern: foo()\n    key: "AKIAIOSFODNN7EXAMPLQ"\n`)).toContain("hardcoded-secret");
  });
  it("the same code in a real source file is still reported", () => {
    expect(ids("app/views.py", `import os\nfrom flask import request\ndef run():\n    os.system("ls " + request.args.get("d"))\n`)).toContain("command-injection");
  });
});

describe("a workflow pin file", () => {
  const pins = `{\n  "actions": {\n    "create-github-app-token": "bcd2ba49218906704ab6c1aa796996da409d3eb1",\n    "checkout": "df4cb1c069e1874edd31b4311f1884172cec0e10"\n  },\n  "aws-actions": {\n    "configure-aws-credentials": "cbe3b392738ccf3f987d68400dafcf4b0624a56c"\n  }\n}\n`;
  it("holding commit SHAs is not a secret", () => {
    expect(ids(".github/workflows/libs/useslockfile.json", pins)).not.toContain("hardcoded-secret");
    expect(ids("tools/actions-lock.json", pins)).not.toContain("hardcoded-secret");
  });
  it("a real credential in the same file is still reported", () => {
    expect(ids(".github/workflows/libs/useslockfile.json", pins.replace("}\n}", `},\n  "env": { "AWS_SECRET_ACCESS_KEY": "q8Zr3vL0pX7mNd2KsT9hYb4WcE6uJa1GfR5oIx" }\n}`))).toContain("hardcoded-secret");
  });
  it("the same 40-hex value under a secret name outside a pin file is still reported", () => {
    expect(ids("config/settings.json", `{ "api_secret": "bcd2ba49218906704ab6c1aa796996da409d3eb1" }\n`)).toContain("hardcoded-secret");
  });
});

describe("a nosem / nosec comment", () => {
  const code = (tail: string) => `import os\nfrom flask import request\ndef run():\n    os.system("ls " + request.args.get("d"))${tail}\n`;
  it("never hides the finding, and the finding says the author marked it", () => {
    for (const tail of ["  # nosem", "  # nosemgrep: python.lang.security.audit.dangerous-system-call", "  # nosec"]) {
      const f = scan("app/views.py", code(tail)).find(i => i.id === "command-injection");
      expect(f).toBeDefined();
      expect(f!.detail).toMatch(/author marked this line/);
    }
  });
  it("a comment line directly above counts; an unrelated comment does not", () => {
    const above = scan("app/views.py", `import os\nfrom flask import request\ndef run():\n    # nosem\n    os.system("ls " + request.args.get("d"))\n`).find(i => i.id === "command-injection");
    expect(above!.detail).toMatch(/author marked this line/);
    const plain = scan("app/views.py", code("  # TODO tidy")).find(i => i.id === "command-injection");
    expect(plain!.detail ?? "").not.toMatch(/author marked/);
  });
});
