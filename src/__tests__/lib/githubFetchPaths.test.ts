/**
 * @jest-environment node
 *
 * fetchFileContents builds a GitHub contents-API URL from repository file names, which the repository's author
 * controls. A name containing `?`, `#` or `%` must stay part of the path, not rewrite the query (`?ref=`).
 */
import { fetchFileContents } from "@/lib/github";

const realFetch = global.fetch;
let urls: string[] = [];
beforeEach(() => {
  urls = [];
  global.fetch = (async (url: string) => {
    urls.push(url);
    return new Response(JSON.stringify({ content: Buffer.from("x = 1").toString("base64"), encoding: "base64" }), { status: 200 });
  }) as typeof fetch;
});
afterEach(() => { global.fetch = realFetch; });

it("encodes each path segment and the ref; keeps directory slashes", async () => {
  const files = await fetchFileContents("t", "acme", "app", "feature/x", ["src/a b.py", "evil?ref=main#.py", "dir/100%.py", "src/ok.py"]);
  expect(urls.sort()).toEqual([
    "https://api.github.com/repos/acme/app/contents/dir/100%25.py?ref=feature%2Fx",
    "https://api.github.com/repos/acme/app/contents/evil%3Fref%3Dmain%23.py?ref=feature%2Fx",
    "https://api.github.com/repos/acme/app/contents/src/a%20b.py?ref=feature%2Fx",
    "https://api.github.com/repos/acme/app/contents/src/ok.py?ref=feature%2Fx",
  ]);
  for (const u of urls) expect(new URL(u).searchParams.getAll("ref")).toEqual(["feature/x"]);
  // results keep the repository's own path names
  expect(files.map(f => f.path).sort()).toEqual(["dir/100%.py", "evil?ref=main#.py", "src/a b.py", "src/ok.py"]);
});
