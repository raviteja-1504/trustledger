/**
 * A minimal reader for the gzipped tarballs GitHub serves (GET /repos/{o}/{r}/tarball/{ref}), so a large pull
 * request is fetched in one request instead of one contents-API call per file (2,800 of those used up the
 * installation's hourly quota and the function's time limit). Node's zlib only, no dependency.
 *
 * Handles what GitHub's archives contain: ustar entries (name + prefix), a pax global header (the commit id),
 * pax per-file headers (long or non-ASCII paths) and GNU long names. Only regular files are returned; the
 * archive's top-level "owner-repo-sha/" directory is stripped so paths match the repository's own.
 */
import { gunzipSync } from "zlib";

const BLOCK = 512;

export interface TarLimits {
  /** Largest decompressed archive accepted (bytes); past it the read fails rather than exhausting memory. */
  maxUnpackedBytes: number;
  /** Files larger than this are left out (the contents API doesn't return them either). */
  maxFileBytes: number;
}

function field(buf: Buffer, start: number, len: number): string {
  const raw = buf.subarray(start, start + len);
  const end = raw.indexOf(0);
  return raw.subarray(0, end === -1 ? raw.length : end).toString("utf8");
}

function octal(buf: Buffer, start: number, len: number): number {
  const s = field(buf, start, len).trim();
  return s ? parseInt(s, 8) : 0;
}

// pax records are "<len> <key>=<value>\n"; the length counts the whole record.
function paxPath(data: Buffer): string | null {
  let i = 0;
  while (i < data.length) {
    const sp = data.indexOf(0x20, i);
    if (sp === -1) break;
    const len = parseInt(data.subarray(i, sp).toString("ascii"), 10);
    if (!len || len <= 0) break;
    const rec = data.subarray(sp + 1, i + len - 1).toString("utf8");
    const eq = rec.indexOf("=");
    if (eq !== -1 && rec.slice(0, eq) === "path") return rec.slice(eq + 1);
    i += len;
  }
  return null;
}

const stripTop = (p: string) => { const s = p.indexOf("/"); return s === -1 ? "" : p.slice(s + 1); };

/**
 * The regular files in `tar` (already decompressed) whose path is in `wanted`, keyed by path. Files over
 * `maxFileBytes` are left out. Throws on a malformed archive.
 */
export function readTar(tar: Buffer, wanted: Set<string>, maxFileBytes: number): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  let off = 0;
  let longName: string | null = null;
  while (off + BLOCK <= tar.length) {
    const header = tar.subarray(off, off + BLOCK);
    if (header.every(b => b === 0)) break;   // end-of-archive marker
    const size = octal(header, 124, 12);
    const type = String.fromCharCode(header[156] || 0x30);
    const dataStart = off + BLOCK;
    const dataEnd = dataStart + size;
    if (!Number.isFinite(size) || size < 0 || dataEnd > tar.length) throw new Error("truncated tar archive");
    const data = tar.subarray(dataStart, dataEnd);
    off = dataStart + Math.ceil(size / BLOCK) * BLOCK;

    if (type === "x") { longName = paxPath(data); continue; }
    if (type === "L") { longName = field(data, 0, data.length); continue; }
    const name = longName ?? (() => {
      const prefix = field(header, 345, 155);
      const base = field(header, 0, 100);
      return prefix ? `${prefix}/${base}` : base;
    })();
    longName = null;
    if (type !== "0" && type !== "7") continue;   // directories, links, devices (a NUL type reads as "0")
    const path = stripTop(name);
    if (path && wanted.has(path) && size <= maxFileBytes) out.set(path, data);
  }
  return out;
}

/** Decompress a .tar.gz and read it (see readTar); throws past `maxUnpackedBytes` or on a bad archive. */
export function readTarGz(gz: Buffer, wanted: Set<string>, limits: TarLimits): Map<string, Buffer> {
  const tar = gunzipSync(gz, { maxOutputLength: limits.maxUnpackedBytes });
  return readTar(tar, wanted, limits.maxFileBytes);
}
