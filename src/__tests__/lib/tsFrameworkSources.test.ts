/**
 * @jest-environment node
 *
 * TypeScript frameworks: request sources and sinks of Remix / React Router, SvelteKit, Astro, Hono, Angular (ActivatedRoute), plus the ORMs and
 * HTTP clients. Precision matters as much as recall: React's escaped text, Angular's sanitiser and constant values, parameterised queries and
 * Drizzle / Prisma tagged templates are SAFE and must stay quiet.
 * (Angular's HttpClient runs in the browser, so a visitor's own URL reaching it is not a server-side request forgery and is not a case here.)
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

jest.setTimeout(180_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

// [name, file, code, expectation]: "VULN:<rule>" must be found; "SAFE" must have no xss / ssrf / sql-injection / open-redirect finding
const CASES: Array<[string, string, string, string]> = [
  // --- sources
  ["remix action json->sql", "r1.ts", `export async function action({ request }: ActionFunctionArgs) { const b = await request.json(); return db.query("SELECT * FROM t WHERE n = '" + b.name + "'"); }`, "VULN:sql-injection"],
  ["remix loader url->ssrf", "r2.ts", `export async function loader({ request }: LoaderFunctionArgs) { const u = new URL(request.url).searchParams.get('u'); const r = await fetch(u!); return r.text(); }`, "VULN:ssrf"],
  ["remix loader params->redirect", "r3.ts", `export async function loader({ request }: LoaderFunctionArgs) { const next = new URL(request.url).searchParams.get('next'); return redirect(next!); }`, "VULN:open-redirect"],
  ["sveltekit server json->ssrf", "s1.ts", `export async function POST({ request }: RequestEvent) { const { url } = await request.json(); const r = await fetch(url); return new Response(await r.text()); }`, "VULN:ssrf"],
  ["sveltekit url param->ssrf", "s2.ts", `export async function GET({ url }: RequestEvent) { const u = url.searchParams.get('u'); const r = await fetch(u!); return new Response(await r.text()); }`, "VULN:ssrf"],
  ["sveltekit params->sql", "s3.ts", `export async function GET({ params }: RequestEvent) { return json(await db.query("SELECT * FROM t WHERE id = " + params.id)); }`, "VULN:sql-injection"],
  ["astro endpoint json->ssrf", "a1.ts", `export async function POST({ request }: APIContext) { const b = await request.json(); const r = await fetch(b.url); return new Response(await r.text()); }`, "VULN:ssrf"],
  ["astro url->redirect", "a2.ts", `export async function GET({ url, redirect }: APIContext) { return redirect(url.searchParams.get('next')!); }`, "VULN:open-redirect"],
  ["astro global->ssrf", "a3.ts", `const u = Astro.url.searchParams.get('u');\nconst r = await fetch(u!);`, "VULN:ssrf"],
  ["hono query->ssrf", "h1.ts", `app.get('/a', async (c) => { const r = await fetch(c.req.query('url')!); return c.text(await r.text()); });`, "VULN:ssrf"],
  ["hono json->sql", "h2.ts", `app.post('/a', async (c) => { const b = await c.req.json(); return c.json(await db.query("SELECT * FROM t WHERE n = '" + b.name + "'")); });`, "VULN:sql-injection"],
  ["hono param->redirect", "h3.ts", `app.get('/a/:next', (c) => c.redirect(c.req.param('next')));`, "VULN:open-redirect"],
  ["hono query->html xss", "h4.ts", `app.get('/a', (c) => c.html('<h1>' + c.req.query('name') + '</h1>'));`, "VULN:xss"],
  ["fastify query->ssrf", "f1.ts", `fastify.get('/a', async (request, reply) => { const r = await fetch((request.query as any).url); return r.text(); });`, "VULN:ssrf"],
  ["fastify body->sql", "f2.ts", `fastify.post('/a', async (request, reply) => { return db.query("SELECT * FROM t WHERE n = '" + (request.body as any).name + "'"); });`, "VULN:sql-injection"],
  ["express body->exec", "e1.ts", `import { exec } from 'child_process';\napp.post('/a', (req, res) => { exec('ls ' + req.body.dir); res.end(); });`, "VULN:command-injection"],
  ["nest query->sql", "n1.ts", `@Controller('a') export class A { constructor(private ds: DataSource) {} @Get() run(@Query('n') n: string) { return this.ds.query("SELECT * FROM t WHERE n = '" + n + "'"); } }`, "VULN:sql-injection"],
  ["angular route->bypass", "ng1.ts", `export class C { constructor(private route: ActivatedRoute, private s: DomSanitizer) {} ngOnInit() { const h = this.route.snapshot.queryParams['html']; this.safe = this.s.bypassSecurityTrustHtml(h); } }`, "VULN:xss"],
  ["angular route subscribe->bypass", "ng2.ts", `export class C { constructor(private route: ActivatedRoute, private s: DomSanitizer) {} ngOnInit() { this.route.queryParams.subscribe(p => { this.safe = this.s.bypassSecurityTrustHtml(p['html']); }); } }`, "VULN:xss"],
  ["angular paramMap->bypassUrl", "ng3.ts", `export class C { constructor(private route: ActivatedRoute, private s: DomSanitizer) {} ngOnInit() { this.url = this.s.bypassSecurityTrustResourceUrl(this.route.snapshot.paramMap.get('u')!); } }`, "VULN:xss"],
  ["urlsearchparams->innerHTML", "u1.ts", `const q = new URLSearchParams(window.location.search).get('x');\ndocument.getElementById('a')!.innerHTML = q!;`, "VULN:xss"],
  // --- React / Vue sinks
  ["react dangerouslySetInnerHTML tainted", "x1.tsx", `export function C({ searchParams }: any) { const h = new URLSearchParams(window.location.search).get('h'); return <div dangerouslySetInnerHTML={{ __html: h! }} />; }`, "VULN:xss"],
  ["react dangerouslySetInnerHTML prop from request", "x2.tsx", `export default async function Page({ searchParams }: { searchParams: { h: string } }) { return <div dangerouslySetInnerHTML={{ __html: searchParams.h }} />; }`, "VULN:xss"],
  ["react escaped text", "x3.tsx", `export function C() { const h = new URLSearchParams(window.location.search).get('h'); return <div>{h}</div>; }`, "SAFE"],
  ["react dangerouslySetInnerHTML DOMPurify", "x4.tsx", `import DOMPurify from 'dompurify';\nexport function C() { const h = new URLSearchParams(window.location.search).get('h')!; return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(h) }} />; }`, "SAFE"],
  ["react dangerouslySetInnerHTML constant", "x5.tsx", `export function C() { return <div dangerouslySetInnerHTML={{ __html: '<b>Hello</b>' }} />; }`, "SAFE"],
  ["react dangerouslySetInnerHTML JSON.stringify jsonld", "x6.tsx", `export function C({ data }: { data: object }) { return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />; }`, "SAFE"],
  // --- Angular safe
  ["angular bypass constant", "ngs1.ts", `export class C { constructor(private s: DomSanitizer) {} ngOnInit() { this.h = this.s.bypassSecurityTrustHtml('<b>Static</b>'); } }`, "SAFE"],
  ["angular bypass of sanitized", "ngs2.ts", `export class C { constructor(private route: ActivatedRoute, private s: DomSanitizer) {} ngOnInit() { const h = this.route.snapshot.queryParams['html']; this.h = this.s.bypassSecurityTrustHtml(DOMPurify.sanitize(h)); } }`, "SAFE"],
  ["angular sanitize()", "ngs3.ts", `export class C { constructor(private route: ActivatedRoute, private s: DomSanitizer) {} ngOnInit() { const h = this.route.snapshot.queryParams['html']; this.h = this.s.sanitize(SecurityContext.HTML, h); } }`, "SAFE"],
  ["angular route into plain property", "ngs4.ts", `export class C { constructor(private route: ActivatedRoute) {} ngOnInit() { this.name = this.route.snapshot.queryParams['name']; } }`, "SAFE"],
  // --- ORM
  ["typeorm DataSource.query tainted", "o1.ts", `app.get('/a', async (req, res) => { res.json(await dataSource.query("SELECT * FROM t WHERE n = '" + req.query.n + "'")); });`, "VULN:sql-injection"],
  ["typeorm manager.query tainted", "o2.ts", `app.get('/a', async (req, res) => { res.json(await manager.query(\`SELECT * FROM t WHERE n = '\${req.query.n}'\`)); });`, "VULN:sql-injection"],
  ["typeorm queryBuilder where tainted", "o3.ts", `app.get('/a', async (req, res) => { res.json(await repo.createQueryBuilder('t').where("t.n = '" + req.query.n + "'").getMany()); });`, "VULN:sql-injection"],
  ["typeorm parameterised", "o4.ts", `app.get('/a', async (req, res) => { res.json(await dataSource.query("SELECT * FROM t WHERE n = $1", [req.query.n])); });`, "SAFE"],
  ["typeorm queryBuilder parameterised", "o5.ts", `app.get('/a', async (req, res) => { res.json(await repo.createQueryBuilder('t').where("t.n = :n", { n: req.query.n }).getMany()); });`, "SAFE"],
  ["drizzle sql.raw tainted", "d1.ts", `app.get('/a', async (req, res) => { res.json(await db.execute(sql.raw("SELECT * FROM t WHERE n = '" + req.query.n + "'"))); });`, "VULN:sql-injection"],
  ["drizzle sql template (parameterised)", "d2.ts", `app.get('/a', async (req, res) => { res.json(await db.execute(sql\`SELECT * FROM t WHERE n = \${req.query.n}\`)); });`, "SAFE"],
  ["drizzle query builder", "d3.ts", `app.get('/a', async (req, res) => { res.json(await db.select().from(t).where(eq(t.n, req.query.n as string))); });`, "SAFE"],
  ["prisma $queryRawUnsafe tainted", "p1.ts", `app.get('/a', async (req, res) => { res.json(await prisma.$queryRawUnsafe("SELECT * FROM t WHERE n = '" + req.query.n + "'")); });`, "VULN:sql-injection"],
  ["prisma $queryRaw tagged (safe)", "p2.ts", `app.get('/a', async (req, res) => { res.json(await prisma.$queryRaw\`SELECT * FROM t WHERE n = \${req.query.n}\`); });`, "SAFE"],
  // --- SSRF clients
  ["axios ssrf", "c1.ts", `app.get('/a', async (req, res) => { res.json((await axios.get(req.query.u as string)).data); });`, "VULN:ssrf"],
  ["ky ssrf", "c2.ts", `import ky from 'ky';
app.get('/a', async (req, res) => { res.json(await ky.get(req.query.u as string).json()); });`, "VULN:ssrf"],
  ["got ssrf", "c3.ts", `import got from 'got';
app.get('/a', async (req, res) => { res.json(await got(req.query.u as string).json()); });`, "VULN:ssrf"],
  ["undici ssrf", "c4.ts", `import { request } from 'undici';\napp.get('/a', async (req, res) => { const r = await request(req.query.u as string); res.json(await r.body.json()); });`, "VULN:ssrf"],
  ["fetch fixed url", "c5.ts", `app.get('/a', async (req, res) => { res.json(await (await fetch('https://api.example.com/x?q=' + encodeURIComponent(req.query.q as string))).json()); });`, "SAFE"],
];

const found = (file: string, code: string) =>
  [...new Set(runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: `t/${file}`, content: code }] })
    .files[0].indicators.filter(i => i.line != null && /critical|high|medium/.test(i.severity)).map(i => i.id))];

describe("vulnerable code is found", () => {
  it.each(CASES.filter(c => c[3].startsWith("VULN:")))("%s", (_n, file, code, expectation) => {
    expect(found(file, code)).toContain(expectation.slice(5));
  });
});

describe("safe code stays quiet", () => {
  it.each(CASES.filter(c => c[3] === "SAFE"))("%s", (_n, file, code) => {
    const bad = found(file, code).filter(i => /xss|ssrf|sql-injection|open-redirect/.test(i));
    expect(bad).toEqual([]);
  });
});
