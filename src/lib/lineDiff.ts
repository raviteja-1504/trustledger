/**
 * A line diff for showing a fix side by side: the two versions' lines aligned row by row (longest common subsequence),
 * each row an unchanged line, a removed one, an added one, or a changed line (a removal paired with the addition that
 * replaced it). Small inputs only -- the demo's sample files -- so the O(n·m) table is fine.
 */
export type DiffRow =
  | { kind: "same"; left: string; right: string; leftNo: number; rightNo: number }
  | { kind: "changed"; left: string; right: string; leftNo: number; rightNo: number }
  | { kind: "removed"; left: string; leftNo: number }
  | { kind: "added"; right: string; rightNo: number };

export function diffLines(before: string, after: string): DiffRow[] {
  const a = before.split("\n"), b = after.split("\n");
  // lcs[i][j] = length of the longest common subsequence of a[i..] and b[j..]
  const lcs: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
  }
  const rows: DiffRow[] = [];
  let removed: Array<{ text: string; no: number }> = [], added: Array<{ text: string; no: number }> = [];
  // a run of removals followed by a run of additions: pair them up as changed lines, the rest stay removed / added
  const flush = () => {
    const n = Math.min(removed.length, added.length);
    for (let k = 0; k < n; k++) rows.push({ kind: "changed", left: removed[k].text, right: added[k].text, leftNo: removed[k].no, rightNo: added[k].no });
    for (const r of removed.slice(n)) rows.push({ kind: "removed", left: r.text, leftNo: r.no });
    for (const r of added.slice(n)) rows.push({ kind: "added", right: r.text, rightNo: r.no });
    removed = []; added = [];
  };
  let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      flush();
      rows.push({ kind: "same", left: a[i], right: b[j], leftNo: i + 1, rightNo: j + 1 });
      i++; j++;
    } else if (j < b.length && (i >= a.length || lcs[i][j + 1] >= lcs[i + 1][j])) {
      added.push({ text: b[j], no: j + 1 }); j++;
    } else {
      removed.push({ text: a[i], no: i + 1 }); i++;
    }
  }
  flush();
  return rows;
}

/** How many lines the fix touches: changed rows count once, a pure removal or addition once each. */
export function changedLineCount(rows: readonly DiffRow[]): number {
  return rows.filter(r => r.kind !== "same").length;
}
