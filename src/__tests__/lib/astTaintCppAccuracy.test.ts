/**
 * @jest-environment node
 *
 * C/C++ engine accuracy: real null-check recognition, preprocessor arms as alternatives, pointer aliases and ownership,
 * finding identity per sink call, scan status / parser lifecycle.
 */
import { parseCppSourceSync, scanAstTaintCpp, warmCppTaintEngine, getCppEngineStatus } from "@/lib/astTaintCpp";

beforeAll(async () => { await warmCppTaintEngine(); }, 120000);

const scan = (code: string) => scanAstTaintCpp(code, "src/main.cpp", parseCppSourceSync(code, "src/main.cpp")!);
const ids = (code: string) => scan(code).map(f => f.id as string);
const fn = (body: string, before = "") => `#include <cstdlib>\n#include <cstring>\n${before}void h(char* other) {\n${body}\n}\n`;

describe("null checks must actually test the pointer against null", () => {
  it("comparing to another pointer is not a null check", () => {
    expect(ids(fn(`  char* p = (char*)malloc(100);\n  if (p == other) {\n    *p = 'A';\n  }\n  free(p);`))).toContain("null-dereference");
  });
  it("a comparison with something else entirely is not a null check", () => {
    expect(ids(fn(`  char* p = (char*)malloc(100);\n  if (other != 0) {\n    *p = 'A';\n  }\n  free(p);`))).toContain("null-dereference");
  });
  it.each([
    ["p != NULL", "if (p != NULL) { *p = 'A'; }"],
    ["p != nullptr", "if (p != nullptr) { *p = 'A'; }"],
    ["p == NULL return", "if (p == NULL) { return; }\n  *p = 'A';"],
    ["p == nullptr return", "if (p == nullptr) { return; }\n  *p = 'A';"],
    ["!p return", "if (!p) { return; }\n  *p = 'A';"],
    ["bare p", "if (p) { *p = 'A'; }"],
    ["p == 0 return", "if (p == 0) { return; }\n  *p = 'A';"],
    ["null && use", "if (p != nullptr && other) { *p = 'A'; }"],
  ])("a real null check is accepted: %s", (_n, check) => {
    expect(ids(fn(`  char* p = (char*)malloc(100);\n  ${check}\n  free(p);`))).not.toContain("null-dereference");
  });
  it("no check at all is reported", () => {
    expect(ids(fn(`  char* p = (char*)malloc(100);\n  *p = 'A';\n  free(p);`))).toContain("null-dereference");
  });
});

describe("preprocessor arms are alternatives", () => {
  it("the safe arm written last does not hide the tainted one", () => {
    const code = `#include <cstdlib>\n#include <cstdio>\nint main(int argc, char** argv) {\n  const char* cmd;\n#ifdef USE_INPUT\n  cmd = argv[1];\n#else\n  cmd = "ls";\n#endif\n  system(cmd);\n  return 0;\n}\n`;
    expect(ids(code)).toContain("command-injection");
  });
  it("the tainted arm written last is also seen", () => {
    const code = `#include <cstdlib>\nint main(int argc, char** argv) {\n  const char* cmd;\n#ifdef _WIN32\n  cmd = "dir";\n#else\n  cmd = argv[1];\n#endif\n  system(cmd);\n  return 0;\n}\n`;
    expect(ids(code)).toContain("command-injection");
  });
  it("two safe arms stay safe", () => {
    const code = `#include <cstdlib>\nint main(int argc, char** argv) {\n  const char* cmd;\n#ifdef _WIN32\n  cmd = "dir";\n#else\n  cmd = "ls";\n#endif\n  system(cmd);\n  return 0;\n}\n`;
    expect(ids(code)).not.toContain("command-injection");
  });
});

describe("pointer aliases", () => {
  it("use after free through an alias", () => {
    expect(ids(fn(`  char* p = (char*)malloc(100);\n  if (!p) return;\n  char* q = p;\n  free(p);\n  q[0] = 'A';`))).toContain("use-after-free");
  });
  it("double free through an alias", () => {
    expect(ids(fn(`  char* p = (char*)malloc(100);\n  if (!p) return;\n  char* q = p;\n  free(p);\n  free(q);`))).toContain("double-free");
  });
  it("an alias re-pointed elsewhere is not freed", () => {
    expect(ids(fn(`  char* p = (char*)malloc(100);\n  if (!p) return;\n  char* q = p;\n  q = other;\n  free(p);\n  q[0] = 'A';`))).not.toContain("use-after-free");
  });
  it("a pointer reassigned after free is valid again", () => {
    expect(ids(fn(`  char* p = (char*)malloc(100);\n  if (!p) return;\n  free(p);\n  p = (char*)malloc(10);\n  if (!p) return;\n  p[0] = 'A';\n  free(p);`))).not.toContain("use-after-free");
  });
  it("an unrelated pointer is not affected by the free", () => {
    expect(ids(fn(`  char* p = (char*)malloc(100);\n  char* r = (char*)malloc(100);\n  if (!p || !r) return;\n  free(p);\n  r[0] = 'A';\n  free(r);`))).not.toContain("use-after-free");
  });
});

describe("finding identity", () => {
  it("two sink calls of one class on a line are two findings", () => {
    const code = `#include <cstdlib>\nint main(int argc, char** argv) { system(argv[1]); system(argv[2]); return 0; }\n`;
    expect(scan(code).filter(f => f.id === "command-injection").length).toBe(2);
  });
  it("one call is one finding", () => {
    const code = `#include <cstdlib>\nint main(int argc, char** argv) { system(argv[1]); return 0; }\n`;
    expect(scan(code).filter(f => f.id === "command-injection").length).toBe(1);
  });
});

describe("scan status and parser lifecycle", () => {
  it("is ready after warm-up", () => {
    expect(getCppEngineStatus().status).toBe("ready");
  });
  it("records an analysis failure instead of silently returning clean", () => {
    const root = parseCppSourceSync("int main() {}", "src/a.cpp")!;
    const bad = { get type(): string { throw new Error("boom"); } } as unknown as typeof root;
    expect(scanAstTaintCpp("int main() {}", "src/a.cpp", bad)).toEqual([]);
    expect(getCppEngineStatus().lastError).toMatch(/analysis_failed/);
  });
});
