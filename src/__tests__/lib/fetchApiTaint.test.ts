/**
 * @jest-environment node
 *
 * What dynast-bench (j3ssie/dynast-bench, 19 intentionally vulnerable apps) taught us about Next.js route handlers, which read the
 * request through the Fetch API (`new URL(req.url).searchParams.get("q")`, `await req.json()`) instead of Express's `req.query`:
 *  - those reads are request input, so they reach SQL / fetch / filesystem / redirect sinks
 *  - Prisma's `$queryRawUnsafe(string)` is a SQL sink; `$queryRaw` / `Prisma.sql` tagged templates are parameterized and are not
 *  - `NextResponse.redirect(x)` is a redirect sink, and a same-site path check (`startsWith("/") && !startsWith("//")`) clears it
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

beforeAll(async () => { await ensureTaintEngines(); }, 180000);

const ids = (path: string, content: string) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] })
    .files.flatMap(f => f.indicators.filter(i => i.line != null).map(i => i.id));

const route = (body: string) => `import { NextResponse } from "next/server";\nexport async function GET(req: Request) {\n${body}\n}\n`;

describe("Fetch-API request input is a taint source", () => {
  it("new URL(req.url).searchParams.get() reaches fetch (SSRF)", () => {
    expect(ids("app/api/p/route.ts", route(`  const url = new URL(req.url).searchParams.get("url") ?? "";\n  const r = await fetch(url);\n  return NextResponse.json({ s: r.status });`))).toContain("ssrf");
  });
  it("it reaches the filesystem (path traversal)", () => {
    expect(ids("app/api/d/route.ts", `import { promises as fs } from "fs";\nimport path from "path";\n` + route(`  const name = new URL(req.url).searchParams.get("name") ?? "";\n  const data = await fs.readFile(path.join("/srv/uploads", name));\n  return new NextResponse(data);`))).toContain("path-traversal");
  });
  it("await req.json() reaches a Prisma $queryRawUnsafe (SQL injection)", () => {
    expect(ids("app/api/q/route.ts", route(`  const { q } = await req.json();\n  const sql = "SELECT * FROM posts WHERE title = '" + q + "'";\n  const rows = await prisma.$queryRawUnsafe(sql);\n  return NextResponse.json(rows);`))).toContain("sql-injection");
  });
  it("a URL held in a variable keeps the request's text", () => {
    expect(ids("app/api/p/route.ts", route(`  const u = new URL(req.url);\n  const target = u.searchParams.get("u");\n  return NextResponse.json(await (await fetch(target!)).json());`))).toContain("ssrf");
  });
  it("a URL built from a constant is not input", () => {
    expect(ids("app/api/p/route.ts", route(`  const u = new URL("https://api.example.com/v1/items");\n  return NextResponse.json(await (await fetch(u)).json());`))).not.toContain("ssrf");
  });
});

describe("open redirect", () => {
  it("NextResponse.redirect(<request value>) is reported", () => {
    expect(ids("app/goto/route.ts", route(`  const next = new URL(req.url).searchParams.get("next") ?? "/";\n  return NextResponse.redirect(next);`))).toContain("open-redirect");
  });
  it("a same-site path check clears it: starts with '/' and not '//'", () => {
    expect(ids("app/goto/route.ts", route(`  const next = new URL(req.url).searchParams.get("next") ?? "/";\n  const safe = next.startsWith("/") && !next.startsWith("//") ? next : "/";\n  return NextResponse.redirect(new URL(safe, req.url));`))).not.toContain("open-redirect");
  });
  it("only a '/' prefix check is not enough ('//evil.example' passes it)", () => {
    expect(ids("app/goto/route.ts", route(`  const next = new URL(req.url).searchParams.get("next") ?? "/";\n  const safe = next.startsWith("/") ? next : "/";\n  return NextResponse.redirect(safe);`))).toContain("open-redirect");
  });
});

describe("tagged-template SQL is parameterized", () => {
  it("Prisma.sql`...${x}` is not string-spliced SQL", () => {
    expect(ids("lib/search.ts", `import { Prisma } from "@prisma/client";\nexport async function find(prisma: any, like: string) {\n  return prisma.$queryRaw(\n    Prisma.sql\`SELECT id FROM "Post" WHERE title ILIKE \${like} ORDER BY id\`\n  );\n}\n`)).not.toContain("sql-injection");
  });
  it("an untagged template with the same text is still reported", () => {
    expect(ids("lib/search.ts", `export async function find(prisma: any, q: string) {\n  const text = \`SELECT id FROM "Post" WHERE title ILIKE '\${q}' ORDER BY id\`;\n  return prisma.$queryRawUnsafe(text);\n}\n`)).toContain("sql-injection");
  });
});

describe("the request's own address is not a destination", () => {
  it("redirecting to a login page built on this site is not an open redirect", () => {
    expect(ids("middleware.ts", route(`  const pathname = req.nextUrl.pathname;
  const loginUrl = new URL("/login", req.url);
  loginUrl.searchParams.set("next", pathname);
  return NextResponse.redirect(loginUrl);`))).not.toContain("open-redirect");
  });
  it("what the client puts INSIDE the URL still is (searchParams)", () => {
    expect(ids("app/goto/route.ts", route(`  const url = new URL(req.url);
  return NextResponse.redirect(url.searchParams.get("next")!);`))).toContain("open-redirect");
  });
});

describe("a fixed-host URL held in a variable is judged by position", () => {
  it("a ternary of fixed-host templates with a request-derived path is not SSRF", () => {
    expect(ids("app/api/c/route.ts", route(`  const { repo, id } = await req.json();
  const u = id ? \`https://api.github.com/repos/\${repo}/issues/comments/\${id}\` : \`https://api.github.com/repos/\${repo}/issues\`;
  await fetch(u);
  return NextResponse.json({ ok: true });`))).not.toContain("ssrf");
  });
  it("a ternary where one arm lets the request pick the host is SSRF", () => {
    expect(ids("app/api/c/route.ts", route(`  const { host, id } = await req.json();
  const u = id ? \`https://\${host}/a\` : \`https://api.github.com/b\`;
  await fetch(u);
  return NextResponse.json({ ok: true });`))).toContain("ssrf");
  });
});

