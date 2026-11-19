/**
 * @jest-environment node
 *
 * A plain function the file defines itself is judged by what its own body returns, never by its NAME.
 *
 * The engine keeps lists of library names that carry their argument's text through (`x.get()`, `.path()`, `QString(x)`,
 * `load`, `parse` ...). Those were applied to ANY call with an argument, before the callee's own return summary was
 * consulted, so a user's `static const char* get(char** a) { return "ls"; }` made `system(get(argv))` a command
 * injection. Found by the capability matrix (benchmarks/capabilityMatrix.test.ts, "return-value").
 *
 * Each name is checked both ways: a function that returns a literal is clean, and one that returns its argument is
 * still flagged (the summary, not the name, decides). A library member call with the same name is unaffected.
 */
import { parseCppSourceSync, scanAstTaintCpp, warmCppTaintEngine } from "@/lib/astTaintCpp";

beforeAll(async () => { await warmCppTaintEngine(); }, 120000);

const ids = (code: string) => scanAstTaintCpp(code, "src/main.cpp", parseCppSourceSync(code, "src/main.cpp")!).map(f => f.id);
const H = "#include <cstdlib>\n#include <string>\n";
// names from STRING_CARRY_METHODS and ANY_ARG_PASSTHROUGH that a project is likely to define for itself
const NAMES = ["get", "path", "text", "first", "load", "parse", "endpoint"];

describe.each(NAMES)("a locally defined function named %s", name => {
  it("returning a literal does not carry the argument's taint", () => {
    expect(ids(H + `static const char* ${name}(char** a) { (void)a; return "ls"; }\nint main(int argc, char** argv) { system(${name}(argv)); return 0; }\n`)).not.toContain("command-injection");
    expect(ids(H + `static const char* ${name}(const char* a) { (void)a; return "ls"; }\nint main(int argc, char** argv) { system(${name}(argv[1])); return 0; }\n`)).not.toContain("command-injection");
  });
  it("returning its argument still does (its own summary decides)", () => {
    expect(ids(H + `static const char* ${name}(const char* a) { return a; }\nint main(int argc, char** argv) { system(${name}(argv[1])); return 0; }\n`)).toContain("command-injection");
    expect(ids(H + `static const char* ${name}(char** a) { return a[0]; }\nint main(int argc, char** argv) { system(${name}(argv)); return 0; }\n`)).toContain("command-injection");
  });
});

describe("the library meaning of these names is kept where there is no local definition", () => {
  it("a std::string's .c_str() / a method call on a tainted object still carries taint", () => {
    expect(ids(H + `int main(int argc, char** argv) { std::string s(argv[1]); system(s.c_str()); return 0; }\n`)).toContain("command-injection");
  });
  it("an undefined free function with a carry name keeps carrying its argument (it is a library call we cannot see)", () => {
    expect(ids(H + `const char* parse(const char*);\nint main(int argc, char** argv) { system(parse(argv[1])); return 0; }\n`)).toContain("command-injection");
  });
});
