/**
 * Read a request body as text, enforcing a size cap WHILE streaming. A Content-Length header can be absent (chunked
 * transfer) or wrong, so checking it alone, or measuring after req.text() has buffered everything, does not bound memory.
 * Returns null when the body is larger than maxBytes; the rest of the stream is cancelled, not read.
 */
export async function readTextLimited(req: Request, maxBytes: number): Promise<string | null> {
  const declared = Number(req.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) return null;
  if (!req.body) return "";

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) { await reader.cancel().catch(() => {}); return null; }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { all.set(c, off); off += c.byteLength; }
  return new TextDecoder().decode(all);
}
