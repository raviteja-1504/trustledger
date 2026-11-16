/**
 * @jest-environment node
 *
 * C/C++ buffer sizes across function and file boundaries (NIST Juliet CWE-121 / CWE-122 "flow variants"), each case with
 * its safe twin:
 *  - a helper that returns / fills a buffer hands the caller its capacity and the length of the string it holds;
 *  - a callee that copies N bytes into a buffer it was handed overflows the caller's smaller buffer -- found at the call;
 *  - the same through a pointer-to-pointer, a struct member, an array element, a container element or a global, and
 *    through a chain of callees (also across files);
 *  - a bound written as `(10)` or `sizeof(a) / sizeof(a[0])` is a bound.
 */
import { parseCppSourceSync, scanAstTaintCpp, computeCppFnSinkFacts, warmCppTaintEngine } from "@/lib/astTaintCpp";
import type { ParamSinkFact } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmCppTaintEngine(); }, 120000);

const one = (code: string, file = "src/m.c") => scanAstTaintCpp(code, file, parseCppSourceSync(code, file)!).map(f => f.id);
function batch(files: Record<string, string>): Record<string, string[]> {
  const trees = Object.entries(files).map(([f, c]) => ({ f, c, t: parseCppSourceSync(c, f)! }));
  let facts = new Map<string, ParamSinkFact[]>();
  for (let round = 0; round < 4; round++) {
    const next = new Map<string, ParamSinkFact[]>();
    for (const { f, c, t } of trees) for (const [k, v] of computeCppFnSinkFacts(c, f, t, facts)) next.set(k, [...(next.get(k) ?? []), ...v]);
    facts = next;
  }
  return Object.fromEntries(trees.map(({ f, c, t }) => [f, scanAstTaintCpp(c, f, t, undefined, { crossFileFacts: facts }).map(x => x.id)]));
}
/** `memcpy` of 100 bytes from a filled source: the write every case below makes. */
const COPY = `  char source[100];\n  memset(source, 'C', 99);\n  source[99] = '\\0';\n  memcpy(data, source, 100);\n`;

describe("a callee that writes into a buffer it was handed", () => {
  const caller = (cap: number) => `void f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  sink(data);\n  free(data);\n}\n`;
  const sink = `static void sink(char *data) {\n${COPY}}\n`;
  it("overflows a smaller heap buffer; a large enough one is fine", () => {
    expect(one(sink + caller(50))).toContain("buffer-overflow");
    expect(one(sink + caller(100))).not.toContain("buffer-overflow");
  });
  it("a stack array and an alloca buffer", () => {
    const stack = (n: number) => `${sink}void f(void) {\n  char buf[${n}];\n  char *data = buf;\n  sink(data);\n}\n`;
    expect(one(stack(50))).toContain("buffer-overflow");
    expect(one(stack(100))).not.toContain("buffer-overflow");
    expect(one(`void f(void) {\n  char *data = (char *)ALLOCA(50*sizeof(char));\n${COPY}}\n`)).toContain("buffer-overflow");
    expect(one(`void f(void) {\n  char *data = (char *)ALLOCA(100*sizeof(char));\n${COPY}}\n`)).not.toContain("buffer-overflow");
  });
  it("copy by strcpy of a known-length string, and by a counted loop", () => {
    const cpy = `static void sink(char *data) {\n  char src[100];\n  memset(src, 'A', 99);\n  src[99] = '\\0';\n  strcpy(data, src);\n}\n`;
    expect(one(cpy + caller(50))).toContain("buffer-overflow");
    expect(one(cpy + caller(100))).not.toContain("buffer-overflow");
    const loop = `static void sink(char *data) {\n  size_t i;\n  for (i = 0; i < 100; i++) { data[i] = 'x'; }\n}\n`;
    expect(one(loop + caller(50))).toContain("buffer-overflow");
    expect(one(loop + caller(100))).not.toContain("buffer-overflow");
  });
  it("called through a function pointer", () => {
    const code = (cap: number) => `${sink}void f(void) {\n  void (*fp)(char *) = sink;\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  fp(data);\n  free(data);\n}\n`;
    expect(one(code(50))).toContain("buffer-overflow");
    expect(one(code(100))).not.toContain("buffer-overflow");
  });
  it("a callee that writes less than the buffer holds proves nothing", () => {
    const small = `static void sink(char *data) {\n  char source[10];\n  memset(source, 'C', 9);\n  source[9] = '\\0';\n  memcpy(data, source, 10);\n}\n`;
    expect(one(small + caller(50))).not.toContain("buffer-overflow");
  });
  it("the strongest write wins when a callee copies twice", () => {
    const two = `static void sink(char *data) {\n  char a[10], b[100];\n  memset(a, 'A', 9); a[9] = 0;\n  memset(b, 'B', 99); b[99] = 0;\n  memcpy(data, a, 10);\n  memcpy(data, b, 100);\n}\n`;
    expect(one(two + caller(50))).toContain("buffer-overflow");
  });
});

describe("a helper that returns or fills a buffer", () => {
  it("returns a malloc'd buffer: the caller's later copy is judged against its size", () => {
    const code = (cap: number) => `static char *mk(void) { char *d = (char *)malloc(${cap}); if (d == NULL) { exit(1); } return d; }\nvoid f(void) {\n  char *data = mk();\n${COPY}  free(data);\n}\n`;
    expect(one(code(50))).toContain("buffer-overflow");
    expect(one(code(100))).not.toContain("buffer-overflow");
  });
  it("fills a reference parameter with a stack buffer", () => {
    const code = (n: number) => `static void mk(char *&data) { static char buf[${n}]; data = buf; }\nvoid f() {\n  char *data = NULL;\n  mk(data);\n${COPY}}\n`;
    expect(one(code(50), "src/m.cpp")).toContain("buffer-overflow");
    expect(one(code(100), "src/m.cpp")).not.toContain("buffer-overflow");
  });
  it("the string length the helper filled travels with the buffer: a short string in a big buffer is not an overflow", () => {
    const code = (fill: number) => `static void mk(char *&data) { memset(data, 'A', ${fill}); data[${fill}] = '\\0'; }\nvoid f() {\n  char buf[100];\n  char *data = buf;\n  mk(data);\n  char dest[50] = "";\n  strcpy(dest, data);\n}\n`;
    expect(one(code(98), "src/m.cpp")).toContain("buffer-overflow");
    expect(one(code(48), "src/m.cpp")).not.toContain("buffer-overflow");
  });
  it("a helper whose returns disagree about the buffer proves nothing about it", () => {
    const code = `static char *mk(int c) {\n  char *small = (char *)malloc(50);\n  char *big = (char *)malloc(100);\n  if (small == NULL || big == NULL) { exit(1); }\n  if (c) { return small; }\n  return big;\n}\nvoid f(int c) {\n  char *data = mk(c);\n${COPY}  free(data);\n}\n`;
    expect(one(code)).not.toContain("buffer-overflow");
    // ...and the length of the string it filled is unknown too, so the copy is judged against the whole buffer
    // (the first exit fills 10 characters, the second 98: taking the first would clear a real overflow)
    const len = `static void mk(char *&data, int c) {\n  if (c) { memset(data, 'A', 10); data[10] = '\\0'; return; }\n  memset(data, 'A', 98);\n  data[98] = '\\0';\n}\nvoid f(int c) {\n  char buf[100];\n  char *data = buf;\n  mk(data, c);\n  char dest[50] = "";\n  strcpy(dest, data);\n}\n`;
    expect(one(len, "src/m.cpp")).toContain("buffer-overflow");
  });
  it("a member that holds a filled buffer carries the string length with it", () => {
    const code = (fill: number) => `typedef struct { char *first; } S;\nvoid f(void) {\n  char buf[100];\n  char *data = buf;\n  memset(data, 'A', ${fill});\n  data[${fill}] = '\\0';\n  S s;\n  s.first = data;\n  {\n    char *d = s.first;\n    char dest[50] = "";\n    strcpy(dest, d);\n  }\n}\n`;
    expect(one(code(98))).toContain("buffer-overflow");
    expect(one(code(48))).not.toContain("buffer-overflow");
  });
  it("a reference bound before the variable is re-pointed names the same buffer and the same string", () => {
    const code = (fill: number) => `void f() {\n  char *data;\n  char *&ref = data;\n  char buf[100];\n  data = buf;\n  memset(data, 'A', ${fill});\n  data[${fill}] = '\\0';\n  {\n    char *data = ref;\n    char dest[50] = "";\n    strcpy(dest, data);\n  }\n}\n`;
    expect(one(code(98), "src/m.cpp")).toContain("buffer-overflow");
    expect(one(code(48), "src/m.cpp")).not.toContain("buffer-overflow");
  });
});

describe("through other shapes of the argument", () => {
  const COPYSINK = (param: string, access: string) => `static void sink(${param}) {\n  char *data = ${access};\n${COPY}}\n`;
  it("a pointer-to-pointer", () => {
    const code = (cap: number) => `${COPYSINK("char **pp", "*pp")}void f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  sink(&data);\n  free(data);\n}\n`;
    expect(one(code(50))).toContain("buffer-overflow");
    expect(one(code(100))).not.toContain("buffer-overflow");
  });
  it("a struct member and an array element", () => {
    const st = (cap: number) => `typedef struct { char *first; } S;\n${COPYSINK("S s", "s.first")}void f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  S s;\n  s.first = data;\n  sink(s);\n  free(data);\n}\n`;
    expect(one(st(50))).toContain("buffer-overflow");
    expect(one(st(100))).not.toContain("buffer-overflow");
    const arr = (cap: number) => `${COPYSINK("char **a", "a[2]")}void f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  char *a[5];\n  a[2] = data;\n  sink(a);\n  free(data);\n}\n`;
    expect(one(arr(50))).toContain("buffer-overflow");
    expect(one(arr(100))).not.toContain("buffer-overflow");
  });
  it("a global", () => {
    const code = (cap: number) => `char *g;\nstatic void sink(void) {\n  char *data = g;\n${COPY}}\nvoid f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  g = data;\n  sink();\n  free(data);\n}\n`;
    expect(one(code(50))).toContain("buffer-overflow");
    expect(one(code(100))).not.toContain("buffer-overflow");
  });
  it("an element of a container", () => {
    const code = (cap: number) => `static void sink(std::vector<char *> v) {\n  char *data = v[2];\n${COPY}}\nvoid f() {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  std::vector<char *> v;\n  v.push_back(data);\n  sink(v);\n  free(data);\n}\n`;
    expect(one(code(50), "src/m.cpp")).toContain("buffer-overflow");
    expect(one(code(100), "src/m.cpp")).not.toContain("buffer-overflow");
  });
});

describe("across files", () => {
  const sinkFile = `void sink(char *data) {\n${COPY}}\n`;
  const callerFile = (cap: number) => `void sink(char *data);\nvoid f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  sink(data);\n  free(data);\n}\n`;
  it("a sink in another file that copies 100 bytes", () => {
    expect(batch({ "src/sink.c": sinkFile, "src/main.c": callerFile(50) })["src/main.c"]).toContain("buffer-overflow");
    expect(batch({ "src/sink.c": sinkFile, "src/main.c": callerFile(100) })["src/main.c"]).not.toContain("buffer-overflow");
  });
  it("through a middle function in a third file", () => {
    const files = (cap: number) => ({
      "src/sink.c": sinkFile,
      "src/mid.c": `void sink(char *data);\nvoid mid(char *data) { sink(data); }\n`,
      "src/main.c": `void mid(char *data);\nvoid f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  mid(data);\n  free(data);\n}\n`,
    });
    expect(batch(files(50))["src/main.c"]).toContain("buffer-overflow");
    expect(batch(files(100))["src/main.c"]).not.toContain("buffer-overflow");
  });
  it("a helper in another file returns the buffer", () => {
    const files = (cap: number) => ({
      "src/lib.c": `char *mk(void) { char *d = (char *)malloc(${cap}); if (d == NULL) { exit(1); } return d; }\n`,
      "src/main.c": `char *mk(void);\nvoid f(void) {\n  char *data = mk();\n${COPY}  free(data);\n}\n`,
    });
    expect(batch(files(50))["src/main.c"]).toContain("buffer-overflow");
    expect(batch(files(100))["src/main.c"]).not.toContain("buffer-overflow");
  });
  it("a helper in another file fills a reference parameter with a buffer", () => {
    const files = (cap: number) => ({
      "src/lib.cpp": `void mk(char *&d) { d = (char *)malloc(${cap}); }\n`,
      "src/main.cpp": `void mk(char *&d);\nvoid f() {\n  char *data = NULL;\n  mk(data);\n  if (data == NULL) { exit(1); }\n${COPY}  free(data);\n}\n`,
    });
    expect(batch(files(50))["src/main.cpp"]).toContain("buffer-overflow");
    expect(batch(files(100))["src/main.cpp"]).not.toContain("buffer-overflow");
  });
  it("a middle function forwards a pointer-to-pointer / a struct to the function that writes", () => {
    const pp = (cap: number) => ({
      "src/sink.c": `void sink(char **pp) {\n  char *data = *pp;\n${COPY}}\n`,
      "src/mid.c": `void sink(char **pp);\nvoid mid(char **pp) { sink(pp); }\n`,
      "src/main.c": `void mid(char **pp);\nvoid f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  mid(&data);\n}\n`,
    });
    expect(batch(pp(50))["src/main.c"]).toContain("buffer-overflow");
    expect(batch(pp(100))["src/main.c"]).not.toContain("buffer-overflow");
    const st = (cap: number) => ({
      "src/sink.c": `typedef struct { char *first; } S;\nvoid sink(S s) {\n  char *data = s.first;\n${COPY}}\n`,
      "src/mid.c": `typedef struct { char *first; } S;\nvoid sink(S s);\nvoid mid(S s) { sink(s); }\n`,
      "src/main.c": `typedef struct { char *first; } S;\nvoid mid(S s);\nvoid f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  S s;\n  s.first = data;\n  mid(s);\n}\n`,
    });
    expect(batch(st(50))["src/main.c"]).toContain("buffer-overflow");
    expect(batch(st(100))["src/main.c"]).not.toContain("buffer-overflow");
  });
  it("a sink in another file that writes through a pointer-to-pointer, a member and a global", () => {
    const pp = (cap: number) => ({ "src/sink.c": `void sink(char **pp) {\n  char *data = *pp;\n${COPY}}\n`, "src/main.c": `void sink(char **pp);\nvoid f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  sink(&data);\n}\n` });
    expect(batch(pp(50))["src/main.c"]).toContain("buffer-overflow");
    expect(batch(pp(100))["src/main.c"]).not.toContain("buffer-overflow");
    const st = (cap: number) => ({
      "src/sink.c": `typedef struct { char *first; } S;\nvoid sink(S s) {\n  char *data = s.first;\n${COPY}}\n`,
      "src/main.c": `typedef struct { char *first; } S;\nvoid sink(S s);\nvoid f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  S s;\n  s.first = data;\n  sink(s);\n}\n`,
    });
    expect(batch(st(50))["src/main.c"]).toContain("buffer-overflow");
    expect(batch(st(100))["src/main.c"]).not.toContain("buffer-overflow");
    const gl = (cap: number) => ({
      "src/sink.c": `extern char *g;\nvoid sink(void) {\n  char *data = g;\n${COPY}}\n`,
      "src/main.c": `char *g;\nvoid sink(void);\nvoid f(void) {\n  char *data = (char *)malloc(${cap});\n  if (data == NULL) { exit(1); }\n  g = data;\n  sink();\n}\n`,
    });
    expect(batch(gl(50))["src/main.c"]).toContain("buffer-overflow");
    expect(batch(gl(100))["src/main.c"]).not.toContain("buffer-overflow");
  });
});

describe("a bound written as an expression is a bound", () => {
  const idx = (guard: string) => `void f(void) {\n  int data = -1;\n  char in[14];\n  recv(sock, in, 13, 0);\n  data = atoi(in);\n  int buffer[10] = {0};\n  if (${guard}) { buffer[data] = 1; }\n}\n`;
  it("a parenthesised literal, sizeof arithmetic and a cast", () => {
    expect(one(idx("data >= 0 && data < (10)"))).not.toContain("buffer-overflow");
    expect(one(idx("data >= 0 && data < sizeof(buffer) / sizeof(buffer[0])"))).not.toContain("buffer-overflow");
    expect(one(idx("data >= 0 && data < (int)10"))).not.toContain("buffer-overflow");
  });
  it("an unchecked index is still an overflow; an unrelated comparison does not bound it", () => {
    expect(one(idx("1"))).toContain("buffer-overflow");
    expect(one(idx("data != 3"))).toContain("buffer-overflow");
    // a bound that is itself attacker-controlled (a parameter) is no bound
    expect(one(`void f(int limit) {\n  int data = -1;\n  char in[14];\n  recv(sock, in, 13, 0);\n  data = atoi(in);\n  int buffer[10] = {0};\n  if (data < limit) { buffer[data] = 1; }\n}\n`)).toContain("buffer-overflow");
  });
});
