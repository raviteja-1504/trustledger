/** @jest-environment node */
/** The Python missing-ownership-check (BOLA/IDOR) finding carries its path: id parameter -> lookup -> use of the record. */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

type Step = { file: string; line: number; kind: string };
const bola = (content: string) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "app/user/views.py", content }] })
  .files.flatMap(f => f.indicators.filter(i => i.id === "bola-missing-ownership-check").map(i => ({ line: i.line!, trace: ((i as { trace?: Step[] }).trace ?? []) })));

const view = (body: string) => `from flask import Blueprint\nuser = Blueprint('user', __name__)\n\n\n@user.route('/delete/<int:id>', methods=['GET'])\n@login_required\ndef delete(id):\n${body}\n`;

describe("BOLA trace (Python)", () => {
  it("runs from the id parameter through the lookup to the record's destructive use", () => {
    const [h] = bola(view(`    user = User.query.filter_by(id=id).first_or_404()\n    user.delete()\n    flash('gone')`));
    expect(h).toBeDefined();
    expect(h.line).toBe(8);
    expect(h.trace.map(t => [t.kind, t.line])).toEqual([["source", 7], ["call", 8], ["sink", 9]]);
  });

  it("ignores an earlier use of a re-used variable name: the sink is the use after the lookup", () => {
    const [h] = bola(view(`    user = Placeholder.make()\n    user.touch()\n    user = User.query.filter_by(id=id).first_or_404()\n    user.delete()`));
    expect(h).toBeDefined();
    expect(h.trace.at(-1)).toMatchObject({ kind: "sink", line: 11 });
  });

  it("with no use of the record after the lookup, the lookup itself is the end of the path", () => {
    const [h] = bola(view(`    return User.query.filter_by(id=id).first_or_404().to_json()`));
    expect(h).toBeDefined();
    expect(h.trace[0]).toMatchObject({ kind: "source", line: 7 });
    expect(h.trace.at(-1)).toMatchObject({ kind: "sink", line: 8 });
  });

  it("an ownership comparison against the current user removes the finding", () => {
    expect(bola(view(`    user = User.query.filter_by(id=id, owner_id=current_user.id).first_or_404()\n    user.delete()`))).toHaveLength(0);
  });
});
