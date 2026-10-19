/**
 * Phantom-dependency remediation stored server-side: status mapping, notes packed into the single note column, and
 * the one-time upload of what a browser held before.
 */
import { joinNotes, phantomFromServer, phantomPatch, phantomUploads, PHANTOM_PREFIX } from "@/lib/phantomOverrides";

describe("phantom overrides", () => {
  it("PATCH body: prefixed id, remediating → in_review, notes one per line", () => {
    expect(phantomPatch("lodahs|acme/api", { status: "remediating", notes: ["01 Oct 2026: removing", "02 Oct 2026: done"] })).toEqual({
      violation_id: "phantom::lodahs|acme/api", status: "in_review", note: "01 Oct 2026: removing\n02 Oct 2026: done",
    });
    expect(phantomPatch("p|r", { status: "resolved" }).status).toBe("resolved");
    expect(phantomPatch("p|r", {})).toEqual({ violation_id: "phantom::p|r", status: "open", note: "" });
  });

  it("reads back only phantom ids, mapping status and splitting notes", () => {
    expect(phantomFromServer({
      "phantom::p|r": { status: "in_review", note: "a\nb" },
      "phantom::q|r": { status: "resolved", note: null },
      "phantom::z|r": { status: "open" },
      "high::s1::a.ts": { status: "resolved" },
    })).toEqual({
      "p|r": { status: "remediating", notes: ["a", "b"] },
      "q|r": { status: "resolved", notes: [] },
      "z|r": { status: "open", notes: [] },
    });
  });

  it("a round trip keeps status and notes", () => {
    const o = { status: "remediating" as const, notes: ["one", "two"] };
    const p = phantomPatch("p|r", o);
    expect(phantomFromServer({ [p.violation_id]: { status: p.status, note: p.note } })["p|r"]).toEqual(o);
  });

  it("notes: newlines inside a note are flattened; over 2000 characters keeps the newest that fit", () => {
    expect(joinNotes(["a\nb", "  ", "c"])).toBe("a b\nc");
    const notes = ["old ".repeat(300), "mid ".repeat(200), "new ".repeat(200)];
    const j = joinNotes(notes);
    expect(j.length).toBeLessThanOrEqual(2000);
    expect(j.split("\n")).toEqual([notes[1].trim(), notes[2].trim()]);
    expect(joinNotes(["x".repeat(2500)])).toHaveLength(2000);
    // The newline between notes counts: 1000 + 1 + 1000 doesn't fit, so only the newest is kept.
    expect(joinNotes(["a".repeat(1000), "b".repeat(1000)])).toBe("b".repeat(1000));
    expect(joinNotes(["a".repeat(999), "b".repeat(1000)])).toBe(`${"a".repeat(999)}\n${"b".repeat(1000)}`);
    expect(joinNotes([])).toBe("");
  });

  it("uploads browser-held overrides the server doesn't have; skips empty and malformed ones", () => {
    const ups = phantomUploads({ [PHANTOM_PREFIX + "s|r"]: { status: "resolved" } }, {
      "s|r": { status: "remediating" },                // server already has it
      "a|r": { status: "resolved", notes: ["n1", 4] },
      "b|r": { notes: ["only a note"] },
      "c|r": { status: "open" },                       // nothing worth uploading
      "d|r": "garbage",
      "": { status: "resolved" },
    });
    expect(ups).toEqual([
      { violation_id: "phantom::a|r", status: "resolved", note: "n1" },
      { violation_id: "phantom::b|r", status: "open", note: "only a note" },
    ]);
  });
});
