/**
 * taint/charClass.ts: what validating against a character-class alphabet proves (shared by the Go, Rust, PHP, Ruby
 * and C# guard recognizers).
 */
import { anchoredPatternClears, charClassClears, classAdmitsDash, delimitedPatternBody } from "@/lib/taint/charClass";
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

describe("charClassClears", () => {
  it("a word alphabet clears every injection class", () => {
    expect(charClassClears("a-zA-Z0-9_")).toBe(INJECTION);
    expect(charClassClears("\\w.")).toBe(INJECTION);
  });
  it("metacharacters (quotes, ;, whitespace, \\s/\\S/\\W) prove nothing", () => {
    expect(charClassClears("a-z'")).toBeNull();
    expect(charClassClears("a-z;")).toBeNull();
    expect(charClassClears("a-z ")).toBeNull();
    expect(charClassClears("a-z\\s")).toBeNull();
    expect(charClassClears("\\S")).toBeNull();
  });
  it("a dash keeps CMD (argument injection); a slash keeps PATH", () => {
    expect(charClassClears("a-z-")).toBe(INJECTION & ~SinkClass.CMD);
    expect(charClassClears("a-z/")).toBe(INJECTION & ~SinkClass.PATH);
  });
});

describe("anchoredPatternClears", () => {
  it("anchored alphabets, escaped punctuation and literal alternatives", () => {
    expect(anchoredPatternClears("^[a-zA-Z0-9_]+$")).toBe(INJECTION);
    expect(anchoredPatternClears("^[a-z0-9_]+\\.(jpg|png)$")).toBe(INJECTION);
    expect(anchoredPatternClears("^(dev|staging|prod)$")).toBe(INJECTION);
  });
  it("unanchored patterns, negated classes and unknown syntax prove nothing", () => {
    expect(anchoredPatternClears("[a-z]+")).toBeNull();
    expect(anchoredPatternClears("^[^/]+$")).toBeNull();
    expect(anchoredPatternClears("^.+$")).toBeNull();
    expect(anchoredPatternClears("^$")).toBeNull();
  });
  it("an escaped dash outside a class still lets the value be an option", () => {
    expect(anchoredPatternClears("^\\-[a-z]+$")).toBe(INJECTION & ~SinkClass.CMD);
    expect(anchoredPatternClears("^[a-z]+\\.[a-z]+$")).toBe(INJECTION);
  });
});

describe("delimitedPatternBody", () => {
  it("strips PHP-style delimiters and flags", () => {
    expect(delimitedPatternBody(`'/^[a-z]+$/i'`)).toBe("^[a-z]+$");
    expect(delimitedPatternBody(`"#^\\d+$#"`)).toBe("^\\d+$");
    expect(delimitedPatternBody(`'not a pattern'`)).toBeNull();
  });
});
