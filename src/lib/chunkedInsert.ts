/**
 * Inserts rows in batches. A 2,800-file PR's scan_files rows (each carrying the file's source) went out as a
 * single insert -- one request body of tens of MB that could stall or be rejected at the very end of a scan.
 * Batches close at `maxRows` rows or about `maxBytes` of row text, whichever comes first.
 */
export interface Inserter {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  from(table: string): { insert(rows: any[]): PromiseLike<{ error: { message: string } | null }> };
}

export function chunkRows<T>(rows: T[], maxRows: number, maxBytes: number, size: (row: T) => number): T[][] {
  const batches: T[][] = [];
  let cur: T[] = [];
  let bytes = 0;
  for (const row of rows) {
    const n = size(row);
    if (cur.length > 0 && (cur.length >= maxRows || bytes + n > maxBytes)) { batches.push(cur); cur = []; bytes = 0; }
    cur.push(row);
    bytes += n;
  }
  if (cur.length > 0) batches.push(cur);
  return batches;
}

/** Inserts every batch (a failed batch doesn't stop the rest); returns the failures' messages, empty when all landed. */
export async function insertInChunks<T>(
  db: Inserter, table: string, rows: T[],
  opts: { maxRows?: number; maxBytes?: number; size?: (row: T) => number } = {},
): Promise<string[]> {
  const errors: string[] = [];
  const batches = chunkRows(rows, opts.maxRows ?? 200, opts.maxBytes ?? 4 * 1024 * 1024, opts.size ?? (() => 0));
  for (const batch of batches) {
    const { error } = await db.from(table).insert(batch);
    if (error) errors.push(error.message);
  }
  return errors;
}
