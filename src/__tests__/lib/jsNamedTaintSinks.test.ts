import { analyzeFile } from "@/lib/scanner";

describe("JS named-taint command injection via exec/execSync (found via real-world OWASP-style Express testing)", () => {
  it("flags a template-literal-built command passed to exec()", () => {
    const content = `
import { exec } from "child_process";
app.get("/api/ping", (req, res) => {
  const host = req.query.host as string;
  const command = \`ping -c 1 \${host}\`;
  exec(command, (error, stdout) => {
    res.send(stdout);
  });
});
`;
    const result = analyzeFile("app.ts", content);
    const finding = result.indicators.find(i => i.id === "command-injection");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  it("flags a concatenation-built command passed to execSync()", () => {
    const content = `
import { execSync } from "child_process";
app.get("/api/system", (req, res) => {
  const command = "cat " + req.query.file;
  const output = execSync(command);
  res.send(output.toString());
});
`;
    const result = analyzeFile("app.ts", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(true);
  });

  it("does not misfire on the common regex.exec() method-call idiom", () => {
    const content = `
function parseLine(pattern, line) {
  const command = pattern.exec(line);
  return command;
}
`;
    const result = analyzeFile("src/parseLine.ts", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(false);
  });
});

describe("Server-side reflected XSS via res.send/write (found via real-world OWASP-style Express testing)", () => {
  it("flags a template-literal HTML response built from a query param", () => {
    const content = `
app.get("/hello", (req, res) => {
  const name = req.query.name as string;
  const html = \`<html><body><h1>Hello \${name}</h1></body></html>\`;
  res.send(html);
});
`;
    const result = analyzeFile("app.ts", content);
    const finding = result.indicators.find(i => i.id === "xss");
    expect(finding).toBeDefined();
    expect(finding?.detail).toContain("html");
  });

  it("does not flag res.send() of a static string", () => {
    const content = `
app.get("/ok", (req, res) => {
  const html = "<html><body>ok</body></html>";
  res.send(html);
});
`;
    const result = analyzeFile("app.ts", content);
    expect(result.indicators.some(i => i.id === "xss")).toBe(false);
  });
});

describe("JS named-taint path traversal via path.join (found via real-world OWASP-style Express testing)", () => {
  it("flags a tainted filename joined into a file path", () => {
    const content = `
import path from "path";
app.get("/download", (req, res) => {
  const filename = req.query.file as string;
  const filePath = path.join("/tmp/uploads", filename);
  res.sendFile(filePath);
});
`;
    const result = analyzeFile("app.ts", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(true);
  });

  it("does not flag path.join() with only static segments", () => {
    const content = `
import path from "path";
function getConfigPath() {
  return path.join("/etc", "myapp", "config.json");
}
`;
    const result = analyzeFile("src/config.ts", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(false);
  });
});

describe("JS named-taint open redirect via res.redirect (found via real-world OWASP-style Express testing)", () => {
  it("flags a tainted redirect target", () => {
    const content = `
app.get("/redirect", (req, res) => {
  const next = req.query.next as string;
  res.redirect(next);
});
`;
    const result = analyzeFile("app.ts", content);
    const finding = result.indicators.find(i => i.id === "open-redirect");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });
});

describe("Hardcoded JWT secret via JS const declaration (found via real-world OWASP-style Express testing)", () => {
  it("flags const JWT_SECRET = \"literal\"", () => {
    const content = `
const JWT_SECRET = "super-secret-trustledger-jwt-key-12345";
app.get("/protected", (req, res) => {
  const decoded = jwt.verify(req.headers.authorization, JWT_SECRET);
  res.json(decoded);
});
`;
    const result = analyzeFile("app.ts", content);
    expect(result.indicators.some(i => i.id === "weak-signing-secret")).toBe(true);
  });
});
