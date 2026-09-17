import { analyzeFile } from "@/lib/scanner";

describe("test-code classification (false-positive reduction)", () => {
  it("tags a finding inside a test file as test_code and does not escalate risk from it alone", () => {
    const content = `
describe("legacy widget", () => {
  it("renders untrusted markup for a snapshot fixture", () => {
    const template = "<div>{{name}}</div>";
    eval(template);
  });
});
`;
    const result = analyzeFile("src/__tests__/widget.spec.ts", content);
    const finding = result.indicators.find(i => i.id === "eval-exec");
    expect(finding).toBeDefined();
    expect(finding?.codeCategory).toBe("test_code");
    expect(result.risk_score).not.toBe("CRITICAL");
  });

  it("still tags a hardcoded secret inside a test file as application (never downgraded)", () => {
    const content = `
describe("payment client", () => {
  it("authenticates", () => {
    const apiKey = "sk_live_${"a".repeat(24)}";
    client.authenticate(apiKey);
  });
});
`;
    const result = analyzeFile("src/__tests__/payment.spec.ts", content);
    const finding = result.indicators.find(i => i.id === "hardcoded-secret");
    expect(finding).toBeDefined();
    expect(finding?.codeCategory).toBe("application");
  });

  it("tags the same eval pattern in a regular application file as application, and risk still escalates", () => {
    const content = `
function renderTemplate(userInput) {
  const template = userInput;
  eval(template);
  return template;
}
module.exports = renderTemplate;
`;
    const result = analyzeFile("src/lib/renderTemplate.ts", content);
    const finding = result.indicators.find(i => i.id === "eval-exec");
    expect(finding).toBeDefined();
    expect(finding?.codeCategory).toBe("application");
    expect(result.risk_score).toBe("CRITICAL");
  });
});
