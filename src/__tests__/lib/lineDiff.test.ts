/**
 * @jest-environment node
 *
 * The demo's side-by-side fix view: the vulnerable and fixed versions aligned line by line, with what the fix changed
 * marked -- a replaced line as one changed row, new lines as additions, deleted lines as removals, and every other line
 * unchanged on both sides.
 */
import { diffLines, changedLineCount } from "@/lib/lineDiff";
import { DEMO_SAMPLES } from "@/lib/demoSamples";

describe("every demo sample's fix shows up in the comparison", () => {
  for (const s of DEMO_SAMPLES) {
    it(s.id, () => {
      const changed = s.files.map(f => changedLineCount(diffLines(f.vulnerable, f.fixed)));
      expect(Math.max(...changed)).toBeGreaterThan(0);
    });
  }
});

describe("diffLines", () => {
  it("identical files: every row unchanged", () => {
    const rows = diffLines("a\nb\nc", "a\nb\nc");
    expect(rows.map(r => r.kind)).toEqual(["same", "same", "same"]);
    expect(changedLineCount(rows)).toBe(0);
  });

  it("a replaced line is one changed row, aligned with its replacement", () => {
    const before = `const id = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + id);\nres.send("ok");`;
    const after = `const id = req.query.id;\ndb.query("SELECT * FROM t WHERE id = ?", [id]);\nres.send("ok");`;
    const rows = diffLines(before, after);
    expect(rows.map(r => r.kind)).toEqual(["same", "changed", "same"]);
    expect(rows[1]).toMatchObject({ left: `db.query("SELECT * FROM t WHERE id = " + id);`, right: `db.query("SELECT * FROM t WHERE id = ?", [id]);`, leftNo: 2, rightNo: 2 });
    expect(changedLineCount(rows)).toBe(1);
  });

  it("inserted lines are additions; the lines after them keep their own numbers on each side", () => {
    const rows = diffLines("a\nb\nc", "a\nx\ny\nb\nc");
    expect(rows.map(r => r.kind)).toEqual(["same", "added", "added", "same", "same"]);
    expect(rows[3]).toMatchObject({ kind: "same", leftNo: 2, rightNo: 4 });
  });

  it("deleted lines are removals", () => {
    const rows = diffLines("a\nb\nc\nd", "a\nd");
    expect(rows.map(r => r.kind)).toEqual(["same", "removed", "removed", "same"]);
    expect(changedLineCount(rows)).toBe(2);
  });

  it("more removed than added: the extra removals stay removals after the paired changes", () => {
    const rows = diffLines("a\nb1\nb2\nb3\nz", "a\nc1\nz");
    expect(rows.map(r => r.kind)).toEqual(["same", "changed", "removed", "removed", "same"]);
  });

  it("covers every line of both versions exactly once", () => {
    const before = "1\n2\n3\n4\n5\n6", after = "1\n3\nx\n4\n6\n7";
    const rows = diffLines(before, after);
    const left = rows.flatMap(r => ("leftNo" in r ? [r.leftNo] : []));
    const right = rows.flatMap(r => ("rightNo" in r ? [r.rightNo] : []));
    expect(left).toEqual([1, 2, 3, 4, 5, 6]);
    expect(right).toEqual([1, 2, 3, 4, 5, 6]);
  });
});
