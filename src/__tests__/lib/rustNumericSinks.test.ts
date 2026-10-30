/**
 * @jest-environment node
 *
 * Rust request-chosen integers: arithmetic that can overflow (`*`, `<<`, `+` of two chosen values, `.pow`, a
 * narrowing `as` cast), raw memory access sized or offset by them inside `unsafe`, and allocations they size.
 * Each has a twin that stays silent: checked_* arithmetic, a bound check, `.min(N)`, or an untainted operand.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmRustTaintEngine } from "@/lib/astTaintRust";

beforeAll(async () => { await warmRustTaintEngine(); }, 120000);

const handler = (body: string) => `pub fn handle(req: &super::shared::BenchmarkRequest) -> super::shared::BenchmarkResponse {
${body}
    super::shared::BenchmarkResponse::ok("ok")
}
`;
const ids = (code: string) => analyzeFile("src/handlers/h.rs", code).indicators.map(i => i.id);
const has = (code: string, id: string) => ids(code).includes(id);
const p = (name: string, ty = "u32") => `    let ${name}: ${ty} = req.param("${name}").parse().unwrap_or(0);\n`;

describe("arithmetic overflow", () => {
  it("a chosen factor, shift amount, or two chosen addends; checked forms and constants are not", () => {
    expect(has(handler(p("a") + p("b") + `    let r = a * b;\n    let _ = r;`), "arithmetic-overflow")).toBe(true);
    expect(has(handler(p("n") + `    let r = n * 4;\n    let _ = r;`), "arithmetic-overflow")).toBe(true);
    expect(has(handler(p("s") + `    let r = 1u32 << s;\n    let _ = r;`), "arithmetic-overflow")).toBe(true);
    expect(has(handler(p("a", "i64") + p("b", "i64") + `    let r = a + b;\n    let _ = r;`), "arithmetic-overflow")).toBe(true);
    expect(has(handler(p("a") + p("b") + `    let r = a.checked_mul(b);\n    let _ = r;`), "arithmetic-overflow")).toBe(false);
    expect(has(handler(p("a") + `    let r = a + 1;\n    let _ = r;`), "arithmetic-overflow")).toBe(false);
    expect(has(handler(p("s") + `    let r = s << 2;\n    let _ = r;`), "arithmetic-overflow")).toBe(false);
  });

  it("pow and compound assignment", () => {
    expect(has(handler(p("e") + `    let r = 2i64.pow(e);\n    let _ = r;`), "arithmetic-overflow")).toBe(true);
    expect(has(handler(p("e") + `    let r = 2i64.checked_pow(e);\n    let _ = r;`), "arithmetic-overflow")).toBe(false);
    expect(has(handler(p("n") + `    let mut total: u32 = 10;\n    total *= n;\n    let _ = total;`), "arithmetic-overflow")).toBe(true);
    expect(has(handler(p("n") + `    let mut total: u32 = 10;\n    total += n;\n    let _ = total;`), "arithmetic-overflow")).toBe(false);
  });

  it("a bound check or .min(N) first clears it", () => {
    expect(has(handler(p("s") + `    let s = s.min(31);\n    let r = 1u32 << s;\n    let _ = r;`), "arithmetic-overflow")).toBe(false);
    expect(has(handler(p("a", "i32") + p("b", "i32") + `    if a.abs() > 46340 || b.abs() > 46340 {\n        return super::shared::BenchmarkResponse::bad_request("range");\n    }\n    let r = a * b;\n    let _ = r;`), "arithmetic-overflow")).toBe(false);
    expect(has(handler(p("a") + p("b") + `    if a > 1000 || b > 1000 {\n        return super::shared::BenchmarkResponse::bad_request("too big");\n    }\n    let r = a * b;\n    let _ = r;`), "arithmetic-overflow")).toBe(false);
  });

  it("a narrowing or sign-changing cast; a widening one is not", () => {
    expect(has(handler(p("v", "u64") + `    let small = v as u32;\n    let _ = small;`), "arithmetic-overflow")).toBe(true);
    expect(has(handler(p("v", "u64") + `    let s = v as isize;\n    let _ = s;`), "arithmetic-overflow")).toBe(true);
    expect(has(handler(p("v", "u32") + `    let w = v as u64;\n    let _ = w;`), "arithmetic-overflow")).toBe(false);
  });

  it("floats and strings are not integers", () => {
    expect(has(handler(p("a", "f64") + p("b", "f64") + `    let r = a * b;\n    let _ = r;`), "arithmetic-overflow")).toBe(false);
    expect(has(handler(`    let a = req.param("a");\n    let r = a.to_string() + "x";\n    let _ = r;`), "arithmetic-overflow")).toBe(false);
    expect(has(handler(`    let a = req.param("a").to_string();\n    let b = req.param("b");\n    let r = a + &b;\n    let _ = r;`), "arithmetic-overflow")).toBe(false);
  });
});

describe("raw memory access", () => {
  it("get_unchecked / ptr.add / copy_nonoverlapping / set_len / from_raw_parts sized by a chosen value", () => {
    expect(has(handler(p("i", "usize") + `    let data = vec![1u8, 2, 3];\n    let v = unsafe { *data.get_unchecked(i) };\n    let _ = v;`), "buffer-overflow")).toBe(true);
    expect(has(handler(p("o", "usize") + `    let data = [0u8; 128];\n    let v = unsafe { *data.as_ptr().add(o) };\n    let _ = v;`), "buffer-overflow")).toBe(true);
    expect(has(handler(p("n", "usize") + `    let src = [0u8; 64];\n    let mut dst = [0u8; 64];\n    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), n) };`), "buffer-overflow")).toBe(true);
    expect(has(handler(p("n", "usize") + `    let mut v: Vec<u8> = Vec::with_capacity(64);\n    unsafe { v.set_len(n) };`), "buffer-overflow")).toBe(true);
    expect(has(handler(p("n", "usize") + `    let data = [0u8; 64];\n    let s = unsafe { std::slice::from_raw_parts(data.as_ptr(), n) };\n    let _ = s;`), "buffer-overflow")).toBe(true);
    expect(has(handler(p("addr", "usize") + `    unsafe { std::ptr::write(addr as *mut u8, 0) };`), "buffer-overflow")).toBe(true);
    // the body of an `unsafe fn` is an unsafe context too
    const unsafeFn = handler(p("o", "usize") + `    let data = [0u8; 128];\n    let v = *data.as_ptr().add(o);\n    let _ = v;`).replace("pub fn handle", "pub unsafe fn handle");
    expect(has(unsafeFn, "buffer-overflow")).toBe(true);
  });

  it("a strict len() bound or a constant length is safe; a capacity() bound or an off-by-one is not", () => {
    const get = (guard: string) => handler(p("i", "usize") + `    let data = vec![1u8, 2, 3];\n${guard}    let v = unsafe { *data.get_unchecked(i) };\n    let _ = v;`);
    const reject = `{\n        return super::shared::BenchmarkResponse::bad_request("oob");\n    }\n`;
    expect(has(get(`    if i >= data.len() ${reject}`), "buffer-overflow")).toBe(false);
    expect(has(get(`    if i > data.len() ${reject}`), "buffer-overflow")).toBe(true);
    expect(has(get(`    if i > data.capacity() ${reject}`), "buffer-overflow")).toBe(true);
    expect(has(handler(p("n", "usize") + `    let data = [0u8; 64];\n    let s = unsafe { std::slice::from_raw_parts(data.as_ptr(), 8) };\n    let _ = (s, n);`), "buffer-overflow")).toBe(false);
    // an index that was never request-chosen is not reported for the off-by-one shape
    expect(has(handler(`    let i: usize = 2;\n    let data = vec![1u8, 2, 3];\n    if i > data.len() {\n        return super::shared::BenchmarkResponse::bad_request("oob");\n    }\n    let v = unsafe { *data.get_unchecked(i) };\n    let _ = v;`), "buffer-overflow")).toBe(false);
  });

  it("a length (not an index) may equal len(); .min(buf.len()) clamps it", () => {
    expect(has(handler(p("n", "usize") + `    let data = [0u8; 64];\n    if n > data.len() {\n        return super::shared::BenchmarkResponse::bad_request("too long");\n    }\n    let s = unsafe { std::slice::from_raw_parts(data.as_ptr(), n) };\n    let _ = s;`), "buffer-overflow")).toBe(false);
    expect(has(handler(p("n", "usize") + `    let src = [0u8; 64];\n    let mut dst = [0u8; 64];\n    let k = n.min(src.len()).min(dst.len());\n    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), k) };`), "buffer-overflow")).toBe(false);
  });
});

describe("allocation size", () => {
  it("Vec::with_capacity sized by a chosen value; capped first is not", () => {
    expect(has(handler(p("n", "usize") + `    let v: Vec<u8> = Vec::with_capacity(n);\n    let _ = v;`), "integer-overflow")).toBe(true);
    expect(has(handler(p("n", "usize") + `    let v: Vec<u8> = Vec::with_capacity(n.min(4096));\n    let _ = v;`), "integer-overflow")).toBe(false);
  });
});
