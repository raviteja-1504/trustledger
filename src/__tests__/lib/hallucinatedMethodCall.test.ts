import { analyzeFile } from "@/lib/scanner";

const ID = "hallucinated-method-call";

function findings(content: string, path = "src/example.ts") {
  const result = analyzeFile(path, content);
  return result.indicators.filter(i => i.id === ID);
}

describe("hallucinated method call -- Tier A (allowlist, unambiguous receivers)", () => {
  it("flags a non-existent method called directly on an array literal", () => {
    const content = `
function run() {
  const result = [1, 2, 3].isEmpty();
  return result;
}
`;
    const hits = findings(content);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].severity).toBe("medium");
  });

  it("does not mistake an index access (`m[1].split()`) for an array literal", () => {
    const content = `
function run(m, f) {
  const a = m[1].split(",");
  const b = f()[0].trim();
  const c = rows[i][0].toUpperCase();
  return [a, b, c];
}
`;
    expect(findings(content)).toEqual([]);
    expect(findings(`function run() {\n  return foo([1, 2].isEmpty());\n}\n`).length).toBeGreaterThan(0);
  });

  it("flags a non-existent method on a variable assigned from an array literal", () => {
    const content = `
function run() {
  const arr = [1, 2, 3];
  return arr.flatten();
}
`;
    const hits = findings(content);
    expect(hits.some(h => h.line === 4)).toBe(true);
  });

  it("flags a non-existent static method on the Array namespace", () => {
    const content = `
function checkValue(x) {
  return Array.isObject(x);
}
`;
    expect(findings(content).length).toBeGreaterThan(0);
  });

  it("flags a non-existent static method on JSON", () => {
    const content = `
function check(str) {
  return JSON.validate(str);
}
`;
    expect(findings(content).length).toBeGreaterThan(0);
  });

  it("flags a non-existent method on a string literal", () => {
    const content = `
function check() {
  return "hello world".isBlank();
}
`;
    expect(findings(content).length).toBeGreaterThan(0);
  });

  it("reports the real source line number, not an offset one", () => {
    const content = `
function a() {}
function b() {}
function run() {
  return [1, 2].isEmpty();
}
`;
    const hits = findings(content);
    expect(hits.some(h => h.line === 5)).toBe(true);
  });
});

describe("hallucinated method call -- Tier B (blocklist idioms)", () => {
  it("flags a chained validate-and-save call even on an unresolvable receiver", () => {
    const content = `
function process(result) {
  result.validateAndSave();
  return result;
}
`;
    expect(findings(content).length).toBeGreaterThan(0);
  });

  it("still fires inside a .test.ts file when the receiver isn't a mock", () => {
    const content = `
function run(someHelper) {
  someHelper.validateAndSave();
}
`;
    expect(findings(content, "src/foo.test.ts").length).toBeGreaterThan(0);
  });
});

describe("hallucinated method call -- true negatives (must not fire)", () => {
  it("does not flag real Array.prototype methods", () => {
    const content = `
function run() {
  const arr = [1, 2, 3];
  return arr.filter(x => x > 1).map(x => x * 2).reduce((a, b) => a + b, 0);
}
`;
    expect(findings(content)).toHaveLength(0);
  });

  it("does not flag real Object methods on a variable assigned from an object literal", () => {
    const content = `
function run() {
  const config = {};
  return config.hasOwnProperty("x");
}
`;
    expect(findings(content)).toHaveLength(0);
  });

  it("Object.assign returns its target: a plain object only when the target is an object literal", () => {
    const element = `
function save(href) {
  const a = Object.assign(document.createElement("a"), { href, download: "x.csv" });
  a.click();
}
`;
    expect(findings(element)).toHaveLength(0);
    const literal = `
function run(extra) {
  const opts = Object.assign({}, extra);
  return opts.flatten();
}
`;
    expect(findings(literal)).toHaveLength(1);
  });

  it("does not flag real String/JSON/Math static and instance methods", () => {
    const content = `
function run(x) {
  const upper = "str".toUpperCase();
  const parsed = JSON.parse(x);
  const m = Math.max(1, 2);
  return upper + parsed + m;
}
`;
    expect(findings(content)).toHaveLength(0);
  });

  it("does not flag an ambiguous receiver with no unambiguous constructor evidence", () => {
    const content = `
function run() {
  const x = fetchThing();
  return x.isEmpty();
}
`;
    expect(findings(content)).toHaveLength(0);
  });

  it("does not flag a method the file itself defines (local shadow)", () => {
    const content = `
class Helper {
  isEmpty() {
    return this.items.length === 0;
  }
}
function run() {
  const arr = [];
  return arr.isEmpty();
}
`;
    expect(findings(content)).toHaveLength(0);
  });

  it("does not flag a mock/stub factory receiver on either tier", () => {
    const content = `
function run() {
  const mockApi = { validateAndSave: jest.fn() };
  mockApi.validateAndSave();
}
`;
    expect(findings(content)).toHaveLength(0);
  });

  it("does not escalate risk_score for a hit inside a vendored/minified file", () => {
    const filler = "x".repeat(420);
    const content = `${filler}; const bad = [1,2,3].isEmpty();`;
    const result = analyzeFile("vendor/lib.min.js", content);
    const hit = result.indicators.find(i => i.id === ID);
    expect(hit?.codeCategory).toBe("third_party");
  });

  it("does not fire on non-JS/TS languages", () => {
    const content = `
def run():
    arr = [1, 2, 3]
    return arr.isEmpty()
`;
    expect(findings(content, "src/example.py")).toHaveLength(0);
  });
});

describe("hallucinated method call -- false positives found scanning the Angular repository", () => {
  const hits = (body: string) => findings(`function run(input, update, headers, params, selector) {\n${body}\n}\n`);

  it("Object.hasOwn (ES2022) is a real method; the other recent built-ins too (165 of the 243 findings on Angular)", () => {
    expect(hits(`  return Object.hasOwn(input, 'value');`)).toHaveLength(0);
    expect(hits(`  return Array.fromAsync(input);`)).toHaveLength(0);
    expect(hits(`  return 'x'.isWellFormed();`)).toHaveLength(0);
    // an invented one on the same namespaces is still flagged
    expect(hits(`  return Object.hasOwned(input, 'value');`).length).toBeGreaterThan(0);
  });

  it("a regex literal is not an array: `=[` inside it is no array assignment", () => {
    const body = `  const attributeRegex = /\[([^\]=]+)(?:=[^\]]+)?\]/g;\n  let match;\n  while ((match = attributeRegex.exec(selector)) !== null) { use(match); }`;
    expect(hits(body)).toHaveLength(0);
  });

  it("a parameter followed by another with a default is not assigned that default", () => {
    const content = `class FormArray {\n  push(control: TControl | Array<TControl>, options: {emitEvent?: boolean} = {}): void {\n    if (Array.isArray(control)) {\n      control.forEach((ctrl) => this.add(ctrl));\n    }\n  }\n}\n`;
    expect(findings(content)).toHaveLength(0);
  });

  it("the result of `.reduce(...)` on Object.keys is not an array, and an arrow parameter shadows the outer name", () => {
    const body = `  if (update.setHeaders !== undefined) {\n    headers = Object.keys(update.setHeaders).reduce(\n      (headers, name) => headers.set(name, update.setHeaders[name]),\n      headers,\n    );\n  }`;
    expect(hits(body)).toHaveLength(0);
    // still an array through array-returning methods, and a real mistake on it is still flagged
    expect(hits(`  const names = Object.keys(input).map(k => k.trim());\n  return names.isEmpty();`).length).toBeGreaterThan(0);
    expect(hits(`  const joined = Object.keys(input).join(',');\n  return joined.length;`)).toHaveLength(0);
    // a plain array still gets flagged for a method it lacks
    expect(hits(`  const list = [1, 2, 3];\n  return list.isEmpty();`).length).toBeGreaterThan(0);
  });
});
