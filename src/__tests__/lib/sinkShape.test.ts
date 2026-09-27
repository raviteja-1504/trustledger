import { assessSsrfUrl, hostPinned, insideOpenAuthority } from "@/lib/taint/sinkShape";
import type { UrlPart } from "@/lib/taint/sinkShape";
import {
  ALL, applyClears, applySanitizer, isTaintedMask, isUrlEncoderClears, KIND_URL_ENCODED, SinkClass, URL_SAFE, wasCleared,
} from "@/lib/taint/taintCore";

// Where in a URL the untrusted part lands decides whether it is SSRF. These pin the position model and the
// value-kind bit, independent of any engine.

type P = UrlPart<number>;
const lit = (text: string): P => ({ kind: "literal", text });
// An opaque operand is represented by its own mask, so `maskOf` is the identity.
const op = (mask: number): P => ({ kind: "opaque", node: mask });
const verdict = (...parts: P[]) => assessSsrfUrl(parts, m => m).verdict;

const TAINTED = ALL;                                   // straight from a request
const ENCODED = applySanitizer(ALL, URL_SAFE);         // passed through encodeURIComponent
const GUARDED = applyClears(ALL, ALL);                 // cleared by a guard / coercion: no kind bit
const CLEAN = 0;

describe("hostPinned", () => {
  it.each([
    ["https://api.example.com/", true],
    ["https://api.example.com/users/", true],
    ["https://api.example.com?x=", true],
    ["https://api.example.com#", true],
    ["/api/users/", true],                             // relative URL: no host to choose
    ["\u0001/users/", true],                           // config-provided base, then a path
    ["https://", false],                               // the next operand IS the host
    ["https://api.example.com", false],                // `.evil.com` / `@evil.com` could still be appended
    ["https://api.", false],
    ["//", false],
    ["", false],                                       // nothing pinned: the operand is the whole URL
    ["http:", false],
  ])("%j -> %s", (text, expected) => expect(hostPinned(text)).toBe(expected));
});

describe("insideOpenAuthority", () => {
  it.each([
    ["https://", true], ["http://", true], ["//", true], ["https://api.", true], ["https://user@", true],
    ["", false], ["/path/", false], ["https://api.example.com/", false], ["https://a.com/x?y=", false],
  ])("%j -> %s", (text, expected) => expect(insideOpenAuthority(text)).toBe(expected));
});

describe("assessSsrfUrl: attacker-influenced (tainted) operands", () => {
  it("the whole URL is the operand -> vulnerable", () => {
    expect(verdict(op(TAINTED))).toBe("vulnerable");
  });
  it("in host position -> vulnerable", () => {
    expect(verdict(lit("https://"), op(TAINTED), lit("/users"))).toBe("vulnerable");
  });
  it("after a literal that closes the authority -> safe (the common REST-client pattern)", () => {
    expect(verdict(lit("https://api.example.com/users/"), op(TAINTED))).toBe("safe");
  });
  it("directly after an UNCLOSED host -> vulnerable (`.evil.com` / `@evil.com` change the host)", () => {
    expect(verdict(lit("https://api.example.com"), op(TAINTED))).toBe("vulnerable");
  });
  it("a trusted config base followed by a literal path -> safe", () => {
    expect(verdict(op(CLEAN), lit("/users/"), op(TAINTED))).toBe("safe");
  });
  it("a trusted host in the middle of the literal scheme/host still pins it", () => {
    expect(verdict(lit("https://"), op(CLEAN), lit("/u/"), op(TAINTED))).toBe("safe");
  });
  it("several tainted operands: ONE in host position makes the whole URL vulnerable", () => {
    expect(verdict(lit("https://"), op(TAINTED), lit("/"), op(TAINTED))).toBe("vulnerable");
  });
  it("once the host is pinned, later operands stay pinned even if one is tainted before another", () => {
    expect(verdict(lit("https://a.com/"), op(TAINTED), lit(".evil.com"), op(TAINTED))).toBe("safe");
  });
  it("query and fragment terminators pin too", () => {
    expect(verdict(lit("https://a.com/?next="), op(TAINTED))).toBe("safe");
    expect(verdict(lit("https://a.com#"), op(TAINTED))).toBe("safe");
  });
  it("relative URLs (no host to choose)", () => {
    expect(verdict(lit("/api/"), op(TAINTED))).toBe("safe");
  });
  it("scheme-relative `//` + operand is a host position -> vulnerable", () => {
    expect(verdict(lit("//"), op(TAINTED))).toBe("vulnerable");
  });
});

describe("assessSsrfUrl: nothing attacker-influenced", () => {
  it("no operands, literal-only, or only trusted operands -> no-taint (callers use their ordinary logic)", () => {
    expect(verdict()).toBe("no-taint");
    expect(verdict(lit("https://a.com/x"))).toBe("no-taint");
    expect(verdict(lit("https://"), op(CLEAN), lit("/x"))).toBe("no-taint");
  });
  it("an operand cleared by a GUARD or coercion is genuinely safe in host position too", () => {
    expect(verdict(lit("https://"), op(GUARDED), lit("/x"))).toBe("no-taint");
  });
});

describe("assessSsrfUrl: URL-encoded operands (the sanitizer is only as good as the position)", () => {
  it("encoding does NOT stop the host being chosen: `https://` + enc(host) -> vulnerable", () => {
    expect(verdict(lit("https://"), op(ENCODED), lit("/users"))).toBe("vulnerable");
  });
  it("...nor after a partial host: `https://api.` + enc(x)", () => {
    expect(verdict(lit("https://api."), op(ENCODED))).toBe("vulnerable");
  });
  it("encoding IS a defence in a path or query component -> safe", () => {
    expect(verdict(lit("https://api.example.com/users/"), op(ENCODED))).toBe("safe");
    expect(verdict(lit("https://api.example.com/search?q="), op(ENCODED))).toBe("safe");
  });
  it("an encoded value standing alone can't become a host (no scheme/`//` opens one) -> safe", () => {
    expect(verdict(op(ENCODED))).toBe("safe");
    expect(verdict(lit("/api/"), op(ENCODED))).toBe("safe");
  });
  it("a value that is BOTH encoded and still tainted for another reason is judged as tainted", () => {
    expect(verdict(lit("https://api.example.com"), op(ENCODED | SinkClass.SSRF))).toBe("vulnerable");
  });
});

describe("assessSsrfUrl: reports WHICH operand is the problem", () => {
  it("names the culprit operand and whether only the encoding cleared it", () => {
    const tainted = assessSsrfUrl([lit("https://"), op(TAINTED), lit("/x")] as P[], m => m);
    expect(tainted).toMatchObject({ verdict: "vulnerable", culprit: TAINTED, encoded: false });
    const enc = assessSsrfUrl([lit("https://"), op(ENCODED), lit("/x")] as P[], m => m);
    expect(enc).toMatchObject({ verdict: "vulnerable", culprit: ENCODED, encoded: true });
    expect(assessSsrfUrl([lit("https://a.com/"), op(TAINTED)] as P[], m => m).culprit).toBeUndefined();
  });
  it("reports the FIRST offending operand when several qualify", () => {
    const a = assessSsrfUrl([lit("https://"), op(TAINTED), lit("."), op(ENCODED)] as P[], m => m);
    expect(a.culprit).toBe(TAINTED);
  });
});

describe("value kind bit (KIND_URL_ENCODED)", () => {
  it("occupies the one bit neither the class half nor the shadow half uses", () => {
    expect(KIND_URL_ENCODED & ALL).toBe(0);
    expect((KIND_URL_ENCODED >>> 16) & ALL).toBe(0);
    expect(KIND_URL_ENCODED).toBe(1 << 15);
  });
  it("is set by the URL-encoder family only, and only when something was actually cleared", () => {
    expect(isUrlEncoderClears(URL_SAFE)).toBe(true);
    expect(isUrlEncoderClears(ALL)).toBe(false);                       // a coercion
    expect(isUrlEncoderClears(SinkClass.XSS)).toBe(false);             // an HTML escaper
    expect(isUrlEncoderClears(SinkClass.PATH)).toBe(false);            // basename
    expect(applySanitizer(ALL, URL_SAFE) & KIND_URL_ENCODED).toBe(KIND_URL_ENCODED);
    expect(applySanitizer(ALL, SinkClass.XSS) & KIND_URL_ENCODED).toBe(0);
    expect(applySanitizer(0, URL_SAFE)).toBe(0);                       // an untainted value stays plain 0
  });
  it("a full coercion clears the kind too (whatever it was, it is a number now)", () => {
    expect(applySanitizer(ENCODED, ALL) & KIND_URL_ENCODED).toBe(0);
  });
  it("the REAL coercion mask (ALL minus CONTROL, as parseInt/Number use) is a coercion, not an encoder", () => {
    const NUMERIC = ALL & ~SinkClass.CONTROL;
    expect(isUrlEncoderClears(NUMERIC)).toBe(false);
    expect(applySanitizer(ALL, NUMERIC) & KIND_URL_ENCODED).toBe(0);
    expect(applySanitizer(ENCODED, NUMERIC) & KIND_URL_ENCODED).toBe(0);
  });
  it("never makes a value look tainted and never disturbs the class/shadow decisions", () => {
    const onlyKind = KIND_URL_ENCODED;
    expect(isTaintedMask(onlyKind)).toBe(false);
    const enc = applySanitizer(ALL, URL_SAFE);
    expect(wasCleared(enc, SinkClass.SSRF)).toBe(true);
    expect(enc & SinkClass.SSRF).toBe(0);
    expect(enc & SinkClass.SQL).toBe(SinkClass.SQL);                   // URL-encoding does not clear SQL
  });
  it("survives an OR-join (a value that is encoded on one branch and raw on the other stays tainted)", () => {
    const joined = applySanitizer(ALL, URL_SAFE) | ALL;
    expect(joined & SinkClass.SSRF).toBe(SinkClass.SSRF);
    expect(assessSsrfUrl([lit("https://a.com"), op(joined)] as P[], m => m).verdict).toBe("vulnerable");
  });
});
