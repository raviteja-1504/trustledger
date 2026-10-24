/**
 * @jest-environment node
 *
 * A 2,800-file pull request (OWASP BenchmarkJava) ended as "No scannable files" -- a passing check on a PR that
 * was never scanned. One contents-API call per file, times the queue's retries, exhausted GitHub's hourly quota;
 * every read then failed and "read nothing" was reported as "nothing to read". These cover the three fixes:
 *   - large PRs are fetched as one tarball (tarArchive.ts, fetchFileContents), per-file reads as the fallback
 *   - "couldn't read" never reports as "nothing to scan" (scanCoverage.ts, used by the GitLab/Bitbucket hooks)
 *   - scan_files rows are inserted in batches (chunkedInsert.ts)
 */
import { gzipSync } from "zlib";
import { readTar, readTarGz } from "@/lib/tarArchive";
import { fetchFileContents, ARCHIVE_MIN_FILES, unreadSummary } from "@/lib/github";
import { scanCoverage, coverageFailure } from "@/lib/scanCoverage";
import { chunkRows, insertInChunks } from "@/lib/chunkedInsert";

// ── a tiny tar writer for fixtures ────────────────────────────────────────────
function header(name: string, size: number, type: string, prefix = ""): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, "utf8");
  h.write("0000644\0", 100);
  h.write(size.toString(8).padStart(11, "0") + "\0", 124);
  h.write(type, 156);
  h.write("ustar\0", 257);
  h.write("00", 263);
  if (prefix) h.write(prefix, 345, 155, "utf8");
  return h;
}
const pad = (b: Buffer) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);
const entry = (name: string, body: string | Buffer, type = "0", prefix = "") => {
  const data = typeof body === "string" ? Buffer.from(body) : body;
  return Buffer.concat([header(name, data.length, type, prefix), pad(data)]);
};
const pax = (key: string, value: string) => {
  const rec = (n: number) => `${n} ${key}=${value}\n`;
  let n = rec(0).length; while (rec(n).length !== n) n = rec(n).length;
  return Buffer.from(rec(n));
};
const tar = (...entries: Buffer[]) => Buffer.concat([...entries, Buffer.alloc(1024)]);

const TOP = "acme-app-0123abc/";

describe("readTar", () => {
  it("returns wanted regular files with the archive's top directory stripped", () => {
    const t = tar(
      entry("pax_global_header", pax("comment", "0123abc"), "g"),
      entry(TOP, "", "5"),
      entry(`${TOP}src/A.java`, "class A {}"),
      entry(`${TOP}src/B.java`, "class B {}"),
      entry(`${TOP}README.md`, "# hi"),
    );
    const out = readTar(t, new Set(["src/A.java", "README.md"]), 1 << 20);
    expect([...out.keys()].sort()).toEqual(["README.md", "src/A.java"]);
    expect(out.get("src/A.java")!.toString()).toBe("class A {}");
  });

  it("joins the ustar prefix, and honours pax and GNU long names for the next entry only", () => {
    const longPath = `${TOP}${"deep/".repeat(30)}Long.java`;
    const t = tar(
      entry("Prefixed.java", "p", "0", `${TOP}src/main/java/org/owasp`),
      entry("PaxHeaders/x", pax("path", longPath), "x"),
      entry("truncated-name", "long"),
      entry("././@LongLink", Buffer.from(`${TOP}gnu/${"n".repeat(120)}.py\0`), "L"),
      entry("short", "gnu"),
      entry(`${TOP}after.py`, "after"),
    );
    const wanted = new Set(["src/main/java/org/owasp/Prefixed.java", longPath.slice(TOP.length), `gnu/${"n".repeat(120)}.py`, "after.py", "truncated-name"]);
    const out = readTar(t, wanted, 1 << 20);
    expect(out.get("src/main/java/org/owasp/Prefixed.java")!.toString()).toBe("p");
    expect(out.get(longPath.slice(TOP.length))!.toString()).toBe("long");
    expect(out.get(`gnu/${"n".repeat(120)}.py`)!.toString()).toBe("gnu");
    expect(out.get("after.py")!.toString()).toBe("after");   // the long name didn't leak onto it
    expect(out.has("truncated-name")).toBe(false);
  });

  it("skips metadata entries, directories, symlinks and files over the size cap", () => {
    const t = tar(
      entry(`${TOP}meta.py`, pax("comment", "x"), "g"),
      entry(`${TOP}dir/`, "", "5"),
      entry(`${TOP}link.py`, "", "2"),
      entry(`${TOP}big.py`, "x".repeat(2000)),
      entry(`${TOP}ok.py`, "x".repeat(1000)),
    );
    const out = readTar(t, new Set(["meta.py", "dir/", "link.py", "big.py", "ok.py"]), 1500);
    expect([...out.keys()]).toEqual(["ok.py"]);
  });

  it("throws on a truncated archive", () => {
    const whole = tar(entry(`${TOP}a.py`, "x".repeat(3000)));
    expect(() => readTar(whole.subarray(0, 1024), new Set(["a.py"]), 1 << 20)).toThrow(/truncated/);
  });

  it("readTarGz refuses an archive that decompresses past the cap", () => {
    const gz = gzipSync(tar(entry(`${TOP}a.py`, "a".repeat(200_000))));
    expect(readTarGz(gz, new Set(["a.py"]), { maxUnpackedBytes: 1 << 20, maxFileBytes: 1 << 20 }).get("a.py")!.length).toBe(200_000);
    expect(() => readTarGz(gz, new Set(["a.py"]), { maxUnpackedBytes: 50_000, maxFileBytes: 1 << 20 })).toThrow();
  });
});

describe("fetchFileContents: one tarball for a large PR", () => {
  const realFetch = global.fetch;
  let urls: string[] = [];
  afterEach(() => { global.fetch = realFetch; });

  const paths = Array.from({ length: ARCHIVE_MIN_FILES }, (_, i) => `src/F${i}.java`);
  const archive = gzipSync(tar(...paths.map(p => entry(`${TOP}${p}`, `// ${p}`))));
  const contents = (url: string) => new Response(JSON.stringify({ content: Buffer.from(`// ${decodeURIComponent(new URL(url).pathname.split("/contents/")[1])}`).toString("base64"), encoding: "base64" }));
  const serve = (tarball: () => Response) => {
    urls = [];
    global.fetch = (async (url: string) => {
      urls.push(url);
      return url.includes("/tarball/") ? tarball() : contents(url);
    }) as typeof fetch;
  };

  it(`${ARCHIVE_MIN_FILES}+ files: a single tarball request, every file read`, async () => {
    serve(() => new Response(archive, { status: 200 }));
    const files = await fetchFileContents("t", "acme", "app", "0123abc", paths);
    expect(urls).toEqual(["https://api.github.com/repos/acme/app/tarball/0123abc"]);
    expect(files.length).toBe(paths.length);
    expect(files.find(f => f.path === "src/F7.java")!.content).toBe("// src/F7.java");
  });

  it("fewer files: per-file reads, no tarball", async () => {
    serve(() => new Response(archive));
    const files = await fetchFileContents("t", "acme", "app", "0123abc", paths.slice(0, ARCHIVE_MIN_FILES - 1));
    expect(urls.some(u => u.includes("/tarball/"))).toBe(false);
    expect(files.length).toBe(ARCHIVE_MIN_FILES - 1);
  });

  it("tarball unavailable, corrupt or over the download cap: falls back to per-file reads", async () => {
    for (const bad of [
      () => new Response("not found", { status: 404 }),
      () => new Response("definitely not gzip", { status: 200 }),
      () => new Response(archive, { status: 200, headers: { "content-length": String(500 * 1024 * 1024) } }),
    ]) {
      serve(bad);
      const files = await fetchFileContents("t", "acme", "app", "0123abc", paths);
      expect(files.length).toBe(paths.length);
      expect(urls.filter(u => u.includes("/contents/")).length).toBe(paths.length);
    }
  });
});

describe("scanCoverage: couldn't read is not nothing to scan", () => {
  it("classifies each case", () => {
    expect(scanCoverage(false, 0, 0)).toBe("unlisted");
    expect(scanCoverage(true, 0, 0)).toBe("none");
    expect(scanCoverage(true, 2800, 0)).toBe("unreadable");
    expect(scanCoverage(true, 2800, 50)).toBe("partial");
    expect(scanCoverage(true, 50, 50)).toBe("complete");
  });

  it("only complete and none let the scan report its own (possibly passing) result", () => {
    expect(coverageFailure("none", 0, 0)).toBeNull();
    expect(coverageFailure("complete", 5, 5)).toBeNull();
    expect(coverageFailure("unlisted", 0, 0)).toMatch(/couldn't list/);
    expect(coverageFailure("unreadable", 2800, 0)).toMatch(/any of 2800 files/);
    expect(coverageFailure("partial", 2800, 50)).toMatch(/scanned 50 of 2800/);
  });

  it("the GitHub check text says how many weren't read", () => {
    expect(unreadSummary(2800, 2800)).toMatch(/couldn't read 2800 of 2800 files.*nothing was scanned/);
    expect(unreadSummary(3, 2800)).toMatch(/couldn't read 3 of 2800 files.*those files weren't scanned/);
  });
});

describe("insertInChunks", () => {
  it("closes a batch at the row count or the byte budget", () => {
    expect(chunkRows([1, 2, 3, 4, 5], 2, 1e9, () => 0)).toEqual([[1, 2], [3, 4], [5]]);
    expect(chunkRows([5, 5, 5, 20, 1], 100, 10, n => n)).toEqual([[5, 5], [5], [20], [1]]);
    expect(chunkRows([], 2, 10, () => 1)).toEqual([]);
  });

  it("inserts every batch, keeps going past a failed one, and reports the failures", async () => {
    const seen: number[][] = [];
    const db = { from: (t: string) => ({ insert: async (rows: number[]) => {
      expect(t).toBe("scan_files");
      seen.push(rows);
      return { error: rows.includes(3) ? { message: "payload too large" } : null };
    } }) };
    const errors = await insertInChunks(db, "scan_files", [1, 2, 3, 4, 5], { maxRows: 2 });
    expect(seen).toEqual([[1, 2], [3, 4], [5]]);
    expect(errors).toEqual(["payload too large"]);
    expect(await insertInChunks(db, "scan_files", [1, 2], { maxRows: 2 })).toEqual([]);
  });
});
