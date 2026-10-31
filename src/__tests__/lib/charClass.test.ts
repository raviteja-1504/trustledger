/**
 * taint/charClass.ts: what validating against a character-class alphabet proves (shared by the Go, Rust, PHP, Ruby
 * and C# guard recognizers).
 */
import { anchoredPatternClears, charClassClears, classAdmitsDash, delimitedPatternBody, removesLineBreaks } from "@/lib/taint/charClass";
import { INJECTION, SinkClass } from "@/lib/taint/taintCore";

describe("classAdmitsDash", () => {
  it("range hyphens are not literal dashes; leading, trailing, escaped and post-range ones are", () => {
    expect(classAdmitsDash("a-z0-9_")).toBe(false);
    expect(classAdmitsDash("-a-z")).toBe(true);
    expect(classAdmitsDash("a-z-")).toBe(true);
    expect(classAdmitsDash("x-")).toBe(true);
    expect(classAdmitsDash("a-z\\-_")).toBe(true);
    expect(classAdmitsDash("0-9-_")).toBe(true);
  });
});

// an identifier-only value is exactly what eval / send / const_get need: an alphabet never clears EVAL
const WORD = INJECTION & ~SinkClass.EVAL;

describe("charClassClears", () => {
  it("a word alphabet clears every injection class except evaluation and reflection", () => {
    expect(charClassClears("a-zA-Z0-9_")).toBe(WORD);
    expect(charClassClears("\\w.")).toBe(WORD);
    expect(charClassClears("A-Za-z0-9:")! & SinkClass.EVAL).toBe(0);
  });
  it("metacharacters (quotes, ;, whitespace, \\s/\\S/\\W) prove nothing", () => {
    expect(charClassClears("a-z'")).toBeNull();
    expect(charClassClears("a-z;")).toBeNull();
    expect(charClassClears("a-z ")).toBeNull();
    expect(charClassClears("a-z\\s")).toBeNull();
    expect(charClassClears("\\S")).toBeNull();
  });
  it("a dash keeps CMD (argument injection); a slash keeps PATH", () => {
    expect(charClassClears("a-z-")).toBe(WORD & ~SinkClass.CMD);
    expect(charClassClears("a-z/")).toBe(WORD & ~SinkClass.PATH);
  });
});

describe("anchoredPatternClears", () => {
  it("anchored alphabets, escaped punctuation and literal alternatives", () => {
    expect(anchoredPatternClears("^[a-zA-Z0-9_]+$")).toBe(WORD);
    expect(anchoredPatternClears("^[a-z0-9_]+\\.(jpg|png)$")).toBe(WORD);
    // a closed set of literal values is an allow-list: safe to evaluate too; so is a fixed literal namespace
    expect(anchoredPatternClears("^(dev|staging|prod)$")).toBe(INJECTION);
    expect(anchoredPatternClears("^field_[0-9]+$")).toBe(INJECTION);
    expect(anchoredPatternClears("^[a-z]+_field$")).toBe(WORD);
  });
  it("unanchored patterns, negated classes and unknown syntax prove nothing", () => {
    expect(anchoredPatternClears("[a-z]+")).toBeNull();
    expect(anchoredPatternClears("^[^/]+$")).toBeNull();
    expect(anchoredPatternClears("^.+$")).toBeNull();
    expect(anchoredPatternClears("^$")).toBeNull();
  });
  it("an escaped dash outside a class still lets the value be an option", () => {
    expect(anchoredPatternClears("^\\-[a-z]+$")).toBe(WORD & ~SinkClass.CMD);
    expect(anchoredPatternClears("^[a-z]+\\.[a-z]+$")).toBe(WORD);
  });
});

describe("removesLineBreaks", () => {
  it("control-character classes and hex escapes for CR and LF remove line breaks", () => {
    for (const body of ["[[:cntrl:]]", "\\p{Cntrl}", "[\\x00-\\x1f]", "[\\x00-\\x1F\\x7F]", "[\\r\\n\\x00]", "[\\x0d\\x0a]"]) expect(removesLineBreaks(body)).toBe(true);
    // only one of the two, or neither
    for (const body of ["[\\x0a]", "[\\x00]", "[\\r\\x00]", "[\\x00-\\x09]"]) expect(removesLineBreaks(body)).toBe(false);
  });
});

describe("delimitedPatternBody", () => {
  it("strips PHP-style delimiters and flags", () => {
    expect(delimitedPatternBody(`'/^[a-z]+$/i'`)).toBe("^[a-z]+$");
    expect(delimitedPatternBody(`"#^\\d+$#"`)).toBe("^\\d+$");
    expect(delimitedPatternBody(`'not a pattern'`)).toBeNull();
  });
});
