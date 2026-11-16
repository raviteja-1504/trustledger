/**
 * @jest-environment node
 *
 * C/C++ memory-state flow across function and file boundaries (NIST Juliet CWE-415 / 416 / 690 / 762 "flow variants"),
 * each vulnerable case with its safe twin:
 *  - a helper that returns an allocation, or fills a reference / pointer-to-pointer parameter, hands the caller that
 *    allocation's kind (malloc / new / new[]), its release and whether it may be NULL;
 *  - a pointer stored in a member, an array element, a union or a container is the same allocation when read back;
 *  - a reference or `int **pp = &data` names the variable it was bound to; a file-scope pointer carries its state into
 *    the function that reads it;
 *  - a function in another file releases / reads / dereferences a parameter, what it points at, a member or a global.
 */
import { parseCppSourceSync, scanAstTaintCpp, computeCppFnSinkFacts, warmCppTaintEngine } from "@/lib/astTaintCpp";
import type { ParamSinkFact } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmCppTaintEngine(); }, 120000);

const one = (code: string, file = "src/m.cpp") => scanAstTaintCpp(code, file, parseCppSourceSync(code, file)!).map(f => f.id);
/** Scan several translation units together the way a batch scan does: converge the cross-file facts, then scan each. */
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

describe("a helper that returns an allocation", () => {
  const src = (alloc: string) => `static int *mk() { int *p = ${alloc}; return p; }\nvoid f() { int *d = mk(); %REL% }\n`;
  it("the caller releases it with the wrong routine", () => {
    expect(one(src("new int").replace("%REL%", "free(d);"))).toContain("mismatched-deallocation");
    expect(one(src("(int *)malloc(4)").replace("%REL%", "delete d;"))).toContain("mismatched-deallocation");
    expect(one(src("new int[4]").replace("%REL%", "delete d;"))).toContain("mismatched-deallocation");
  });
  it("the matching routine is fine", () => {
    expect(one(src("new int").replace("%REL%", "delete d;"))).not.toContain("mismatched-deallocation");
    expect(one(src("(int *)malloc(4)").replace("%REL%", "free(d);"))).not.toContain("mismatched-deallocation");
    expect(one(src("new int[4]").replace("%REL%", "delete[] d;"))).not.toContain("mismatched-deallocation");
  });
  it("a helper that already freed what it returns: freeing it again is a double free; one that did not is fine", () => {
    const freed = `int *mk() { int *p = (int *)malloc(4); free(p); return p; }\nvoid f() { int *d = mk(); free(d); }\n`;
    const live = `int *mk() { int *p = (int *)malloc(4); return p; }\nvoid f() { int *d = mk(); free(d); }\n`;
    expect(one(freed)).toContain("double-free");
    expect(one(live)).not.toContain("double-free");
  });
  it("a helper that frees on only some paths proves nothing (no state is assumed)", () => {
    const maybe = `int *mk(int c) { int *p = (int *)malloc(4); if (c) { free(p); return p; } return p; }\nvoid f(int c) { int *d = mk(c); free(d); }\n`;
    expect(one(maybe)).not.toContain("double-free");
  });
  it("a returned NULL does not hide how the other return was allocated", () => {
    const code = `int *mk() { int *p = new int; if (!p) return NULL; return p; }\nvoid f() { int *d = mk(); free(d); }\n`;
    expect(one(code)).toContain("mismatched-deallocation");
  });
  it("a helper that returns the allocation expression itself", () => {
    expect(one(`int *mk() { return new int; }\nvoid f() { int *d = mk(); free(d); }\n`)).toContain("mismatched-deallocation");
    expect(one(`int *mk() { return (int *)malloc(4); }\nvoid f() { int *d = mk(); delete d; }\n`)).toContain("mismatched-deallocation");
    expect(one(`int *mk() { return new int; }\nvoid f() { int *d = mk(); delete d; }\n`)).not.toContain("mismatched-deallocation");
  });
  it("a helper that returns malloc's result unchecked leaves it unchecked in the caller; a checked one does not", () => {
    const unchecked = `char *mk() { char *p = (char *)malloc(8); return p; }\nvoid f() { char *d = mk(); d[0] = 'a'; free(d); }\n`;
    const checked = `char *mk() { char *p = (char *)malloc(8); if (p == NULL) { exit(1); } return p; }\nvoid f() { char *d = mk(); d[0] = 'a'; free(d); }\n`;
    expect(one(unchecked)).toContain("null-dereference");
    expect(one(checked)).not.toContain("null-dereference");
  });
});

describe("a helper that fills a reference or pointer-to-pointer parameter", () => {
  it("reference: the caller's pointer is what the helper stored", () => {
    const code = (rel: string) => `static void mk(int *&d) { d = new int; }\nvoid f() { int *d = NULL; mk(d); ${rel} }\n`;
    expect(one(code("free(d);"))).toContain("mismatched-deallocation");
    expect(one(code("delete d;"))).not.toContain("mismatched-deallocation");
  });
  it("pointer-to-pointer: `mk(&d)` fills d", () => {
    const code = (rel: string) => `static void mk(int **pp) { *pp = new int; }\nvoid f() { int *d = NULL; mk(&d); ${rel} }\n`;
    expect(one(code("free(d);"))).toContain("mismatched-deallocation");
    expect(one(code("delete d;"))).not.toContain("mismatched-deallocation");
  });
  it("pointer-to-pointer passed on as a variable (`mk(pp)` with `pp = &d`)", () => {
    const code = (rel: string) => `static void mk(int **pp) { *pp = new int; }\nvoid f() { int *d = NULL; int **pp = &d; mk(pp); ${rel} }\n`;
    expect(one(code("free(d);"))).toContain("mismatched-deallocation");
    expect(one(code("delete d;"))).not.toContain("mismatched-deallocation");
  });
  it("a reference helper that frees: the caller's second free is a double free", () => {
    const code = (second: string) => `static void mk(int *&d) { d = (int *)malloc(4); free(d); }\nvoid f() { int *d = NULL; mk(d); ${second} }\n`;
    expect(one(code("free(d);"))).toContain("double-free");
    expect(one(code("d = NULL;"))).not.toContain("double-free");
  });
});

describe("aliases of a pointer", () => {
  it("a reference names the same variable, also inside a nested scope that re-declares it", () => {
    // bound first, allocated afterwards: reassigning `data` leaves the reference naming it
    const code = (second: string) => `void f() { int *data; int *&r = data; data = NULL; data = (int *)malloc(4); free(data); { int *data = r; ${second} } }\n`;
    expect(one(code("free(data);"))).toContain("double-free");
    expect(one(code("(void)data;"))).not.toContain("double-free");
  });
  it("a pointer-to-pointer reads and writes the variable it points at", () => {
    const code = (alloc: string) => `void f() { int *data = NULL; int **p1 = &data; int **p2 = &data; { int *data = *p1; data = ${alloc}; *p1 = data; } { int *data = *p2; free(data); } }\n`;
    expect(one(code("new int"))).toContain("mismatched-deallocation");
    expect(one(code("(int *)malloc(4)"))).not.toContain("mismatched-deallocation");
  });
  it("a struct member, an array element and a union member hold the allocation they were given", () => {
    const st = (second: string) => `struct S { int *a; int *b; };\nvoid f() { int *data = (int *)malloc(4); free(data); S s; s.a = data; { int *data = s.a; ${second} } }\n`;
    expect(one(st("free(data);"))).toContain("double-free");
    expect(one(st("(void)data;"))).not.toContain("double-free");
    const arr = (idx: number) => `void f() { int *data = (int *)malloc(4); free(data); int *arr[5]; arr[2] = data; { int *data = arr[${idx}]; free(data); } }\n`;
    expect(one(arr(2))).toContain("double-free");
    expect(one(arr(3))).not.toContain("double-free");   // another element was never stored
    const un = (second: string) => `typedef union { int *first; int *second; } U;\nvoid f() { int *data = (int *)malloc(4); free(data); U u; u.first = data; { int *data = u.second; ${second} } }\n`;
    expect(one(un("free(data);"))).toContain("double-free");
    expect(one(un("(void)data;"))).not.toContain("double-free");
  });
  it("an element of a container is the allocation that was inserted", () => {
    const code = (second: string) => `void f() { int *data = (int *)malloc(4); free(data); std::vector<int *> v; v.push_back(data); { int *data = v[0]; ${second} } }\n`;
    expect(one(code("free(data);"))).toContain("double-free");
    expect(one(code("(void)data;"))).not.toContain("double-free");
    const back = `void f() { int *data = new int; std::list<int *> l; l.push_back(data); { int *data = l.back(); free(data); } }\n`;
    expect(one(back)).toContain("mismatched-deallocation");
  });
  it("two members of a struct are distinct slots; two array elements too", () => {
    const code = `struct S { int *a; int *b; };\nvoid f() { int *x = (int *)malloc(4); int *y = (int *)malloc(4); S s; s.a = x; s.b = y; free(x); { int *d = s.b; free(d); } }\n`;
    expect(one(code)).not.toContain("double-free");
  });
});

describe("a file-scope pointer carries its state into the function that reads it", () => {
  const code = (alloc: string, rel: string) => `int *g;\nstatic void sink() { int *d = g; ${rel} }\nvoid f() { int *d = ${alloc}; g = d; sink(); }\n`;
  it("mismatched release in the callee is reported once", () => {
    const ids = one(code("new int", "free(d);"));
    expect(ids.filter(i => i === "mismatched-deallocation")).toHaveLength(1);
    expect(one(code("new int", "delete d;"))).not.toContain("mismatched-deallocation");
  });
  it("a freed global read by the callee", () => {
    const freed = `int *g;\nstatic void sink() { int *d = g; free(d); }\nvoid f() { int *d = (int *)malloc(4); free(d); g = d; sink(); }\n`;
    const live = `int *g;\nstatic void sink() { int *d = g; free(d); }\nvoid f() { int *d = (int *)malloc(4); g = d; sink(); }\n`;
    expect(one(freed)).toContain("double-free");
    expect(one(live)).not.toContain("double-free");
  });
});

describe("a file-scope pointer that is only read by the callee", () => {
  it("unchecked: dereferenced there; checked first: fine", () => {
    const code = (check: string) => `int *g;\nstatic void sink() { int *d = g; d[0] = 5; }\nvoid f() { int *d = (int *)malloc(4); ${check} g = d; sink(); free(d); }\n`;
    expect(one(code(""))).toContain("null-dereference");
    expect(one(code("if (d == NULL) { exit(1); }"))).not.toContain("null-dereference");
  });
  it("freed before the call: the callee reads freed memory", () => {
    const code = (pre: string) => `int *g;\nstatic void sink() { int *d = g; printf("%d", d[0]); }\nvoid f() { int *d = (int *)malloc(4); if (d == NULL) { exit(1); } ${pre} g = d; sink(); }\n`;
    expect(one(code("free(d);"))).toContain("use-after-free");
    expect(one(code(""))).not.toContain("use-after-free");
  });
});

describe("a callee that frees its parameter still receives whether it may be NULL", () => {
  it("dereferenced before the free", () => {
    const unchecked = `static void sink(int *d) { d[0] = 5; free(d); }\nvoid f() { int *d = (int *)malloc(4); sink(d); }\n`;
    const checked = `static void sink(int *d) { d[0] = 5; free(d); }\nvoid f() { int *d = (int *)malloc(4); if (d == NULL) { exit(1); } sink(d); }\n`;
    expect(one(unchecked)).toContain("null-dereference");
    expect(one(checked)).not.toContain("null-dereference");
  });
  it("called through a function pointer", () => {
    const code = `static void sink(int *d) { d[0] = 5; free(d); }\nvoid f() { void (*fp)(int *) = sink; int *d = (int *)malloc(4); fp(d); }\n`;
    expect(one(code)).toContain("null-dereference");
  });
});

describe("across files", () => {
  it("a helper in another file returns an allocation / a freed pointer", () => {
    const lib = (body: string) => ({ "src/lib.c": `int *mk(void) { ${body} }\n`, "src/main.c": `int *mk(void);\nvoid f(void) { int *d = mk(); free(d); }\n` });
    expect(batch(lib("int *p = (int *)malloc(4); free(p); return p;"))["src/main.c"]).toContain("double-free");
    expect(batch(lib("int *p = (int *)malloc(4); return p;"))["src/main.c"]).not.toContain("double-free");
    const cpp = (alloc: string) => ({ "src/lib.cpp": `int *mk() { int *p = ${alloc}; return p; }\n`, "src/main.cpp": `int *mk();\nvoid f() { int *d = mk(); free(d); }\n` });
    expect(batch(cpp("new int"))["src/main.cpp"]).toContain("mismatched-deallocation");
    expect(batch(cpp("(int *)malloc(4)"))["src/main.cpp"]).not.toContain("mismatched-deallocation");
  });
  it("a helper in another file fills a reference parameter", () => {
    const files = (alloc: string) => ({ "src/lib.cpp": `void mk(int *&d) { d = ${alloc}; }\n`, "src/main.cpp": `void mk(int *&d);\nvoid f() { int *d = NULL; mk(d); free(d); }\n` });
    expect(batch(files("new int"))["src/main.cpp"]).toContain("mismatched-deallocation");
    expect(batch(files("(int *)malloc(4)"))["src/main.cpp"]).not.toContain("mismatched-deallocation");
  });
  it("a sink in another file frees its parameter: a pointer freed before is a double free, a live one is not", () => {
    const files = (pre: string) => ({ "src/sink.c": `void sink(int *d) { free(d); }\n`, "src/main.c": `void sink(int *d);\nvoid f(void) { int *d = (int *)malloc(4); ${pre} sink(d); }\n` });
    expect(batch(files("free(d);"))["src/main.c"]).toContain("double-free");
    expect(batch(files(""))["src/main.c"]).not.toContain("double-free");
  });
  it("a middle function that forwards a pointer-to-pointer to a sink that frees through it", () => {
    const files = (pre: string) => ({
      "src/a.c": `void sink(int **pp) { int *d = *pp; free(d); }\n`,
      "src/b.c": `void sink(int **pp);\nvoid mid(int **pp) { sink(pp); }\n`,
      "src/main.c": `void mid(int **pp);\nvoid f(void) { int *d = (int *)malloc(4); ${pre} mid(&d); }\n`,
    });
    expect(batch(files("free(d);"))["src/main.c"]).toContain("double-free");
    expect(batch(files(""))["src/main.c"]).not.toContain("double-free");
  });
  it("a chain of three files: the release is found through the middle one", () => {
    const files = (pre: string) => ({
      "src/a.c": `void sink(int *d) { free(d); }\n`,
      "src/b.c": `void sink(int *d);\nvoid mid(int *d) { sink(d); }\n`,
      "src/main.c": `void mid(int *d);\nvoid f(void) { int *d = (int *)malloc(4); ${pre} mid(d); }\n`,
    });
    expect(batch(files("free(d);"))["src/main.c"]).toContain("double-free");
    expect(batch(files(""))["src/main.c"]).not.toContain("double-free");
  });
  it("the allocation kind meets the release across files", () => {
    const files = (alloc: string) => ({ "src/sink.cpp": `void sink(int *d) { delete d; }\n`, "src/main.cpp": `void sink(int *d);\nvoid f() { int *d = ${alloc}; sink(d); }\n` });
    expect(batch(files("(int *)malloc(4)"))["src/main.cpp"]).toContain("mismatched-deallocation");
    expect(batch(files("new int"))["src/main.cpp"]).not.toContain("mismatched-deallocation");
  });
  it("a sink that frees what a pointer-to-pointer points at, after a cast through void *", () => {
    const sink = (decl: string) => `void sink(${decl}) { int **pp = (int **)v; int *d = *pp; free(d); }\n`;
    const files = (pre: string) => ({ "src/sink.c": sink("void *v"), "src/main.c": `void sink(void *v);\nvoid f(void) { int *d = (int *)malloc(4); ${pre} sink(&d); }\n` });
    expect(batch(files("free(d);"))["src/main.c"]).toContain("double-free");
    expect(batch(files(""))["src/main.c"]).not.toContain("double-free");
  });
  it("a sink that frees a struct member / an array element / a global", () => {
    const st = (pre: string) => ({
      "src/sink.c": `typedef struct { int *first; } S;\nvoid sink(S s) { int *d = s.first; free(d); }\n`,
      "src/main.c": `typedef struct { int *first; } S;\nvoid sink(S s);\nvoid f(void) { int *d = (int *)malloc(4); S s; ${pre} s.first = d; sink(s); }\n`,
    });
    expect(batch(st("free(d);"))["src/main.c"]).toContain("double-free");
    expect(batch(st(""))["src/main.c"]).not.toContain("double-free");
    const arr = (pre: string) => ({
      "src/sink.c": `void sink(int **a) { int *d = a[2]; free(d); }\n`,
      "src/main.c": `void sink(int **a);\nvoid f(void) { int *d = (int *)malloc(4); int *a[5]; ${pre} a[2] = d; sink(a); }\n`,
    });
    expect(batch(arr("free(d);"))["src/main.c"]).toContain("double-free");
    expect(batch(arr(""))["src/main.c"]).not.toContain("double-free");
    const glob = (pre: string) => ({
      "src/sink.c": `extern int *g;\nvoid sink(void) { int *d = g; free(d); }\n`,
      "src/main.c": `int *g;\nvoid sink(void);\nvoid f(void) { int *d = (int *)malloc(4); ${pre} g = d; sink(); }\n`,
    });
    expect(batch(glob("free(d);"))["src/main.c"]).toContain("double-free");
    expect(batch(glob(""))["src/main.c"]).not.toContain("double-free");
  });
  it("a sink in another file that dereferences an unchecked pointer, directly or through a member / pointer-to-pointer", () => {
    const direct = (check: string) => ({ "src/sink.c": `void sink(int *d) { d[0] = 5; }\n`, "src/main.c": `void sink(int *d);\nvoid f(void) { int *d = (int *)malloc(4); ${check} sink(d); }\n` });
    expect(batch(direct(""))["src/main.c"]).toContain("null-dereference");
    expect(batch(direct("if (d == NULL) { exit(1); }"))["src/main.c"]).not.toContain("null-dereference");
    const viaPtr = (check: string) => ({ "src/sink.c": `void sink(int **pp) { int *d = *pp; d[0] = 5; }\n`, "src/main.c": `void sink(int **pp);\nvoid f(void) { int *d = (int *)malloc(4); ${check} sink(&d); }\n` });
    expect(batch(viaPtr(""))["src/main.c"]).toContain("null-dereference");
    expect(batch(viaPtr("if (d == NULL) { exit(1); }"))["src/main.c"]).not.toContain("null-dereference");
    const member = (check: string) => ({
      "src/sink.c": `typedef struct { char *first; } S;\nvoid sink(S s) { char *d = s.first; d[0] = 'a'; }\n`,
      "src/main.c": `typedef struct { char *first; } S;\nvoid sink(S s);\nvoid f(void) { char *d = (char *)malloc(8); S s; ${check} s.first = d; sink(s); }\n`,
    });
    expect(batch(member(""))["src/main.c"]).toContain("null-dereference");
    expect(batch(member("if (d == NULL) { exit(1); }"))["src/main.c"]).not.toContain("null-dereference");
  });
  it("a sink in another file that dereferences and then frees its parameter", () => {
    const files = (check: string) => ({ "src/sink.c": `void sink(int *d) { d[0] = 5; free(d); }\n`, "src/main.c": `void sink(int *d);\nvoid f(void) { int *d = (int *)malloc(4); ${check} sink(d); }\n` });
    expect(batch(files(""))["src/main.c"]).toContain("null-dereference");
    expect(batch(files("if (d == NULL) { exit(1); }"))["src/main.c"]).not.toContain("null-dereference");
  });
  it("a freed pointer read through a pointer-to-pointer is a use-after-free, not also a NULL dereference", () => {
    const files = { "src/sink.c": `void sink(int **pp) { int *d = *pp; printf("%d", d[0]); }\n`, "src/main.c": `void sink(int **pp);\nvoid f(void) { int *d = (int *)malloc(4); free(d); sink(&d); }\n` };
    const ids = batch(files)["src/main.c"];
    expect(ids).toContain("use-after-free");
    expect(ids).not.toContain("null-dereference");
  });
  it("a sink that checks the pointer before using it is not a dereference fact", () => {
    const files = { "src/sink.c": `void sink(int *d) { if (d != NULL) { d[0] = 5; } }\n`, "src/main.c": `void sink(int *d);\nvoid f(void) { int *d = (int *)malloc(4); sink(d); free(d); }\n` };
    expect(batch(files)["src/main.c"]).not.toContain("null-dereference");
  });
  it("a sink in another file that reads a freed pointer through a pointer-to-pointer", () => {
    const files = (pre: string) => ({ "src/sink.c": `void sink(int **pp) { int *d = *pp; printf("%d", d[0]); }\n`, "src/main.c": `void sink(int **pp);\nvoid f(void) { int *d = (int *)malloc(4); if (d == NULL) { exit(1); } ${pre} sink(&d); }\n` });
    expect(batch(files("free(d);"))["src/main.c"]).toContain("use-after-free");
    expect(batch(files(""))["src/main.c"]).not.toContain("use-after-free");
  });
  it("a callee's uses are judged before its own release (a member it reads and then frees is not a use-after-free)", () => {
    const files = {
      "src/sink.c": `typedef struct { char *first; } S;\nvoid sink(S s) { char *d = s.first; if (d != NULL) { d[0] = 'a'; free(d); } }\n`,
      "src/main.c": `typedef struct { char *first; } S;\nvoid sink(S s);\nvoid f(void) { char *d = (char *)malloc(8); S s; s.first = d; sink(s); }\n`,
    };
    expect(batch(files)["src/main.c"]).not.toContain("use-after-free");
    expect(batch(files)["src/main.c"]).not.toContain("null-dereference");
  });
});
