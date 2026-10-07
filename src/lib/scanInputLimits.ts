/**
 * Repository content is untrusted input to hundreds of regex rules. Many rules start with an unanchored `\w+` or
 * contain `\s*` next to a lazy group, which costs O(run length^2) on one unbroken run of word characters or
 * spaces: a single 400 KB file of `aaaa...` or of spaces took minutes, past the scan worker's time budget.
 *
 * No real code has a 256-character identifier or 256 spaces in a row, so each such run is cut to MAX_RUN
 * characters before any rule sees it. Newlines are never touched (line numbers stay exact), and secrets,
 * hashes and base64 blobs keep their first 256 characters -- far more than any detector looks at.
 */
export const MAX_RUN = 256;

const WORD = 1, SPACE = 2;
function classOf(c: number): number {
  if ((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95) return WORD;
  if (c === 32 || c === 9) return SPACE;
  return 0;
}

/** `content` with every run of more than MAX_RUN word characters (or spaces/tabs) cut to MAX_RUN. Linear time. */
export function tameLongRuns(content: string): string {
  const n = content.length;
  let parts: string[] | null = null;
  let kept = 0;
  let i = 0;
  while (i < n) {
    const cls = classOf(content.charCodeAt(i));
    if (!cls) { i++; continue; }
    let j = i + 1;
    while (j < n && classOf(content.charCodeAt(j)) === cls) j++;
    if (j - i > MAX_RUN) {
      (parts ??= []).push(content.slice(kept, i + MAX_RUN));
      kept = j;
    }
    i = j;
  }
  return parts ? parts.join("") + content.slice(kept) : content;
}
