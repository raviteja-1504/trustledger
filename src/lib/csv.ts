/**
 * CSV writing that is safe to open in a spreadsheet, and the exact inverse for anything that has to read the values back.
 *
 * Two problems the hand-rolled versions had:
 *  - Escaping: a value with a quote, comma or line break must be wrapped in quotes with inner quotes doubled, or one
 *    cell spills into the next column (several exports didn't escape at all).
 *  - Formula injection: a cell that starts with = + - @ (or a tab / carriage return) is run as a formula by Excel, Sheets
 *    and LibreOffice, so a finding titled `=HYPERLINK("https://evil", "click")` attacks whoever opens the export.
 *    Such a cell gets a leading apostrophe, which the spreadsheet reads as "this is text" and does not display.
 *
 * Neutralising is reversible so a signed export can still be checked: a cell is prefixed with `'` when it starts with a
 * formula character OR with `'` itself, and csvUnneutralize() strips exactly that one apostrophe. (Without the second
 * case, the text `'=x` and the neutralised `=x` would both read back as `=x`.)
 *
 * Numbers, booleans and null are written as themselves: a real number such as -5 is not a formula and keeps its type.
 * Client-safe: pure.
 */

const FORMULA = /^[\t\r ]*[=+\-@]/;

/** True when a spreadsheet could run this text as a formula. */
export function looksLikeFormula(s: string): boolean {
  return FORMULA.test(s) || /^[\t\r]/.test(s);
}

/** A value ready to put in a CSV cell, quoted only when it has to be. */
export function csvCell(v: unknown): string {
  let s: string;
  if (v == null) s = "";
  else if (typeof v === "number") s = Number.isFinite(v) ? String(v) : "";
  else if (typeof v === "boolean" || typeof v === "bigint") s = String(v);
  else if (v instanceof Date) s = Number.isNaN(v.getTime()) ? "" : v.toISOString();
  else {
    s = typeof v === "string" ? v : JSON.stringify(v) ?? "";
    if (looksLikeFormula(s) || s.startsWith("'")) s = `'${s}`;
  }
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** One CSV record (no trailing line break). */
export function csvLine(cells: readonly unknown[]): string {
  return cells.map(csvCell).join(",");
}

/** A header and its rows as CSV text. `eol` defaults to "\n"; RFC 4180 asks for "\r\n". */
export function toCsv(header: readonly string[], rows: readonly (readonly unknown[])[], eol = "\n"): string {
  return [csvLine(header), ...rows.map(csvLine)].join(eol);
}

/** The original text of a cell that csvCell wrote as a string: strips the one apostrophe neutralising added. */
export function csvUnneutralize(cell: string): string {
  return cell.startsWith("'") ? cell.slice(1) : cell;
}

/** Parses CSV text (RFC 4180: quoted cells, doubled quotes, line breaks inside quotes) into records of raw cells. */
export function parseCsv(text: string): string[][] {
  const out: string[][] = [];
  let row: string[] = [], cell = "", quoted = false, i = 0, any = false;
  while (i < text.length) {
    const c = text[i];
    if (quoted) {
      if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i += 2; continue; } quoted = false; i++; continue; }
      cell += c; i++; continue;
    }
    if (c === '"' && cell === "") { quoted = true; any = true; i++; continue; }
    if (c === ",") { row.push(cell); cell = ""; any = true; i++; continue; }
    if (c === "\r" || c === "\n") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(cell); out.push(row); row = []; cell = ""; any = false; i++; continue;
    }
    cell += c; any = true; i++;
  }
  if (any || cell !== "" || row.length) { row.push(cell); out.push(row); }
  return out;
}
