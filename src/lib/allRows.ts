/**
 * Every row of a query, page by page. PostgREST (Supabase) returns at most 1000 rows per request however many
 * match, so a 1,242-file scan read with one plain select showed "1000 files" on its PR page and in its trust
 * record. `page(from, to)` must apply `.range(from, to)` to a query with a stable `.order(...)` (a unique key
 * last), or rows can repeat or go missing between pages.
 *
 * Returns the rows read so far and the first error, so a caller keeps its own error handling: one that read
 * `data ?? []` before still does, one that failed on `error` still can.
 */
export const PAGE_SIZE = 1000;
// 200k rows: far past any real scan, and a stop for a query whose page callback ignores its range.
const MAX_PAGES = 200;

type Page<T> = PromiseLike<{ data: T[] | null; error?: unknown }>;

export async function allRows<T>(page: (from: number, to: number) => Page<T>): Promise<{ data: T[]; error: unknown }> {
  const out: T[] = [];
  for (let i = 0; i < MAX_PAGES; i++) {
    const { data, error } = await page(i * PAGE_SIZE, i * PAGE_SIZE + PAGE_SIZE - 1);
    if (error) return { data: out, error };
    out.push(...(data ?? []));
    if (!data || data.length < PAGE_SIZE) break;
  }
  return { data: out, error: null };
}
