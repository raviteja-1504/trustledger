/**
 * @jest-environment node
 *
 * C/C++ taint that crosses a file boundary at a call's RETURN, through an OUT-PARAMETER, or in a FILE-SCOPE variable
 * (NIST Juliet CWE-78 / 134 / 23 / 36 "flow variants" 22, 61, 62, 68), each case with a safe twin:
 *  - a helper in another file that reads input and returns it;
 *  - a helper that passes an argument through to its return;
 *  - a helper that fills a buffer argument with input;
 *  - a variable one file taints and another file reads and sinks.
 * The per-function auxiliary facts are kept beside, never inside, a function's taint-sink facts.
 */
import { parseCppSourceSync, scanAstTaintCpp, computeCppFnSinkFacts, warmCppTaintEngine } from "@/lib/astTaintCpp";
import type { ParamSinkFact } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmCppTaintEngine(); }, 120000);

function converge(files: Record<string, string>): Map<string, ParamSinkFact[]> {
  const trees = Object.entries(files).map(([f, c]) => ({ f, c, t: parseCppSourceSync(c, f)! }));
  let facts = new Map<string, ParamSinkFact[]>();
  for (let round = 0; round < 4; round++) {
    const next = new Map<string, ParamSinkFact[]>();
    for (const { f, c, t } of trees) for (const [k, v] of computeCppFnSinkFacts(c, f, t, facts)) next.set(k, [...(next.get(k) ?? []), ...v]);
    facts = next;
  }
  return facts;
}
function batch(files: Record<string, string>): Record<string, string[]> {
  const facts = converge(files);
  return Object.fromEntries(Object.entries(files).map(([f, c]) => [f, scanAstTaintCpp(c, f, parseCppSourceSync(c, f)!, undefined, { crossFileFacts: facts }).map(x => x.id)]));
}

describe("a helper in another file that returns input", () => {
  const files = (ret: string) => ({
    "src/input.c": `char *read_name(void) {\n  char *s = ${ret};\n  return s;\n}\n`,
    "src/main.c": `char *read_name(void);\nvoid f(void) {\n  char *name = read_name();\n  system(name);\n}\n`,
  });
  it("its result reaches a command", () => {
    expect(batch(files('getenv("USER_CMD")'))["src/main.c"]).toContain("command-injection");
    expect(batch(files('"/bin/true"'))["src/main.c"]).not.toContain("command-injection");
  });
  it("the same through a socket read into a buffer the helper returns", () => {
    const f = (fill: string) => ({
      "src/input.c": `char *read_cmd(char *buf) {\n  ${fill}\n  return buf;\n}\n`,
      "src/main.c": `char *read_cmd(char *buf);\nvoid f(void) {\n  char buf[100];\n  char *cmd = read_cmd(buf);\n  system(cmd);\n}\n`,
    });
    expect(batch(f("recv(sock, buf, 99, 0);"))["src/main.c"]).toContain("command-injection");
    expect(batch(f("strcpy(buf, \"ls\");"))["src/main.c"]).not.toContain("command-injection");
  });
});

describe("a helper that passes its argument through", () => {
  const files = (arg: string) => ({
    "src/util.c": `char *trim(char *s) { return s; }\n`,
    "src/main.c": `char *trim(char *s);\nvoid f(void) {\n  system(trim(${arg}));\n}\n`,
  });
  it("tainted in, tainted out; a constant stays a constant", () => {
    expect(batch(files('getenv("X")'))["src/main.c"]).toContain("command-injection");
    expect(batch(files('"ls"'))["src/main.c"]).not.toContain("command-injection");
  });
  it("a helper that does not pass it through (returns a fixed string) is clean", () => {
    const f = { "src/util.c": `char *fixed(char *s) { (void)s; return "ls"; }\n`, "src/main.c": `char *fixed(char *s);\nvoid f(void) {\n  system(fixed(getenv("X")));\n}\n` };
    expect(batch(f)["src/main.c"]).not.toContain("command-injection");
  });
});

describe("a helper that fills a buffer argument with input", () => {
  const files = (fill: string) => ({
    "src/input.c": `void read_into(char *buf) {\n  ${fill}\n}\n`,
    "src/main.c": `void read_into(char *buf);\nvoid f(void) {\n  char buf[100];\n  read_into(buf);\n  system(buf);\n}\n`,
  });
  it("what it stored is input in the caller", () => {
    expect(batch(files("recv(sock, buf, 99, 0);"))["src/main.c"]).toContain("command-injection");
    expect(batch(files("strcpy(buf, \"ls\");"))["src/main.c"]).not.toContain("command-injection");
  });
  it("a copy from another argument carries that argument's taint", () => {
    const f = (src: string) => ({
      "src/util.c": `void copy_to(char *dst, char *src) { strcpy(dst, src); }\n`,
      "src/main.c": `void copy_to(char *dst, char *src);\nvoid f(void) {\n  char buf[100];\n  copy_to(buf, ${src});\n  system(buf);\n}\n`,
    });
    expect(batch(f('getenv("X")'))["src/main.c"]).toContain("command-injection");
    expect(batch(f('"ls"'))["src/main.c"]).not.toContain("command-injection");
  });
});

describe("a file-scope variable one file taints and another reads", () => {
  const files = (value: string) => ({
    "src/a.c": `char *g;\nvoid set(void) {\n  char *data = ${value};\n  g = data;\n}\n`,
    "src/b.c": `extern char *g;\nvoid sink(void) {\n  system(g);\n}\n`,
  });
  it("the reader's sink is reached", () => {
    expect(batch(files('getenv("X")'))["src/b.c"]).toContain("command-injection");
    expect(batch(files('"ls"'))["src/b.c"]).not.toContain("command-injection");
  });
  it("a variable no other file taints stays clean", () => {
    const f = { "src/a.c": `char *h;\nvoid set(void) { h = getenv("X"); }\n`, "src/b.c": `extern char *g;\nvoid sink(void) {\n  system(g);\n}\n` };
    expect(batch(f)["src/b.c"]).not.toContain("command-injection");
  });
});

describe("the auxiliary facts stay out of a function's sink facts", () => {
  it("a function that both reaches a sink and returns input has its facts under two keys", () => {
    const facts = converge({
      "src/a.c": `char *run(char *cmd) {\n  system(cmd);\n  return getenv("HOME");\n}\n`,
      "src/b.c": `char *run(char *cmd);\nvoid f(void) { run("ls"); }\n`,
    });
    expect((facts.get("run") ?? []).map(f => f.id)).toEqual(["command-injection"]);
    expect((facts.get("m:run") ?? []).map(f => f.id)).toContain("taint-ret");
  });
  it("a function with many sink facts keeps all of them next to memory facts", () => {
    const params = Array.from({ length: 12 }, (_, i) => `char *p${i}`).join(", ");
    const body = Array.from({ length: 12 }, (_, i) => `  system(p${i});`).join("\n");
    const facts = converge({
      "src/a.c": `void many(${params}) {\n${body}\n}\n`,
      "src/b.c": `void many(${params});\nvoid f(void) { many(${Array.from({ length: 12 }, () => "getenv(\"X\")").join(", ")}); }\n`,
    });
    expect((facts.get("many") ?? []).filter(f => f.id === "command-injection")).toHaveLength(12);
  });
  it("a call to a function that only has memory facts does not create a taint finding", () => {
    const f = { "src/a.c": `char *mk(void) { return (char *)malloc(8); }\n`, "src/main.c": `char *mk(void);\nvoid f(void) {\n  char *d = mk();\n  if (d == NULL) { exit(1); }\n  system("ls");\n  free(d);\n}\n` };
    expect(batch(f)["src/main.c"]).not.toContain("command-injection");
  });
});

describe("a struct a helper fills from an argument is not attacker data across files (found scanning curl)", () => {
  // Known limit, taken on purpose: taint stored into a struct member by a helper in ANOTHER file is not followed. On curl,
  // `init(q, size)`-style helpers made every connection struct "tainted" (24 buffer-overflow reports, 3x the scan time).
  const files = {
    "src/q.c": `struct Q { char name[16]; };\nvoid q_set(struct Q *q, const char *name) {\n  strcpy(q->name, name);\n}\n`,
    "src/main.c": `struct Q { char name[16]; };\nvoid q_set(struct Q *q, const char *name);\nvoid f(void) {\n  struct Q q;\n  q_set(&q, getenv("N"));\n  system(q.name);\n}\n`,
  };
  it("a helper that copies a string into a struct does not taint the struct for its callers", () => {
    expect(batch(files)["src/main.c"]).not.toContain("command-injection");
  });
  it("but a helper that fills a char buffer argument with input still does", () => {
    const f = { "src/in.c": `void read_name(char *buf) { recv(sock, buf, 15, 0); }\n`, "src/main.c": `void read_name(char *buf);\nvoid f(void) {\n  char name[16];\n  read_name(name);\n  system(name);\n}\n` };
    expect(batch(f)["src/main.c"]).toContain("command-injection");
  });
});
