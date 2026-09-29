/**
 * Which findings a pull request INTRODUCED, from the PR's own diff.
 *
 * GitHub's "list pull request files" API returns each file's unified diff (`patch`) against the PR's base.
 * A finding is introduced by the PR when its line -- or, for a data flow, any step of the flow in the same
 * file -- is on a line the PR adds or changes; otherwise it was already there (pre-existing in a file the PR
 * touches). A file the PR adds is introduced in full. When GitHub omits a patch (very large or binary diffs)
 * nothing is claimed either way.
 * Client-safe: no imports beyond types.
 */

export interface PrFileDiff { filename: string; status: string; patch?: string }

/** Added-line numbers (new-file side) of a unified diff; "all" for a whole new file; null when unknown. */
export type AddedLines = Set<number> | "all" | null;

export function addedLines(file: PrFileDiff): AddedLines {
  if (file.status === "added") return "all";
  if (!file.patch) return null;
  const out = new Set<number>();
  let newLine = 0;
  for (const raw of file.patch.split("\n")) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) { newLine = Number(hunk[1]); continue; }
    if (raw.startsWith("+")) { out.add(newLine); newLine++; }
    else if (raw.startsWith("-")) { /* removed: no new-side line */ }
    else if (raw.startsWith("\\")) { /* "\ No newline at end of file" */ }
    else newLine++;                                                    // context line
  }
  return out;
}

export function addedLinesByPath(files: readonly PrFileDiff[]): Map<string, AddedLines> {
  return new Map(files.map(f => [f.filename, addedLines(f)]));
}

interface MarkableIndicator { line?: number; introduced?: boolean; trace?: ReadonlyArray<{ line?: number; file?: string }> }

/** Set `introduced` on each indicator of `filePath` (in place). Indicators without a line are left alone. */
export function markIntroduced(indicators: MarkableIndicator[], filePath: string, added: AddedLines | undefined): void {
  if (added == null) return;
  for (const ind of indicators) {
    if (ind.line == null) continue;
    if (added === "all") { ind.introduced = true; continue; }
    const lines = [ind.line, ...(ind.trace ?? []).filter(s => !s.file || s.file === filePath).map(s => s.line).filter((l): l is number => l != null)];
    ind.introduced = lines.some(l => added.has(l));
  }
}
