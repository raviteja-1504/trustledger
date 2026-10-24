/**
 * Precision fixes from testing OWASP crAPI (Python / Go / Java microservices), each with the real bug it must keep
 * catching:
 *   - verify=False on an HTTP client is TLS verification disabled, not JWT algorithm confusion
 *   - JSON responses (Spring ResponseEntity<Dto>.body, DRF Response, Go json.Marshal) are not XSS
 *   - a constant cursor.execute("...") is not SQL injection
 *   - a connection-string TEMPLATE ("mongodb://%s:%s@...") is not a hardcoded credential
 *   - Java JWT: claims read without verifying the signature, and a key fetched from the token's jku header
 */
import { analyzeFile } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

jest.setTimeout(60_000);
beforeAll(async () => { await ensureTaintEngines(); });

const ids = (path: string, src: string, id: string) => analyzeFile(path, src).indicators.filter(i => i.id === id).map(i => i.line);

describe("TLS verification disabled vs JWT", () => {
  it("verify=False on requests / httpx is TLS verification disabled, not a JWT finding", () => {
    const src = `import requests, httpx\n\ndef call(url):\n    r = requests.get(url, verify=False)\n    c = httpx.AsyncClient(verify=False)\n    return r\n`;
    expect(ids("svc/client.py", src, "tls-verification-disabled")).toEqual([4, 5]);
    expect(ids("svc/client.py", src, "jwt-none-alg")).toEqual([]);
  });

  it("Go InsecureSkipVerify and Node rejectUnauthorized are too", () => {
    expect(ids("gw/main.go", `package main\n\nvar cfg = &tls.Config{InsecureSkipVerify: true}\n`, "tls-verification-disabled")).toEqual([3]);
    expect(ids("src/agent.ts", `const agent = new https.Agent({ rejectUnauthorized: false });\n`, "tls-verification-disabled")).toEqual([1]);
  });

  it("a JWT decoded without verifying its signature is still the JWT finding (crAPI workshop/utils/jwt.py)", () => {
    const src = `import jwt\n\ndef user_of(token):\n    decoded = jwt.decode(token, options={"verify_signature": False})\n    old = jwt.decode(token, verify=False)\n    return decoded\n`;
    expect(ids("utils/jwt.py", src, "jwt-none-alg")).toEqual([4, 5]);
    expect(ids("utils/jwt.py", src, "tls-verification-disabled")).toEqual([]);
  });

  it("TLS kept on is nothing", () => {
    expect(ids("svc/client.py", `import requests\n\ndef call(url):\n    return requests.get(url, verify=True)\n`, "tls-verification-disabled")).toEqual([]);
  });
});

describe("JSON responses are not XSS", () => {
  it("Spring: ResponseEntity<Dto>.body(dto) -- a generic is not an HTML tag; HTML in a string literal still is", () => {
    const json = `@RestController\npublic class AuthController {\n  @PostMapping("/login")\n  public ResponseEntity<JwtResponse> login(@RequestBody LoginForm form, HttpServletRequest request) {\n    String name = request.getParameter("name");\n    JwtResponse jwtResponse = service.login(name);\n    return ResponseEntity.status(HttpStatus.OK).body(jwtResponse);\n  }\n}\n`;
    expect(ids("AuthController.java", json, "xss")).toEqual([]);
    const html = `@RestController\npublic class Hello {\n  @GetMapping("/hi")\n  public ResponseEntity<String> hi(HttpServletRequest request) {\n    String name = request.getParameter("name");\n    String page = "<div>Hello " + name;\n    return ResponseEntity.ok().body(page);\n  }\n}\n`;
    expect(ids("Hello.java", html, "xss").length).toBeGreaterThan(0);
  });

  it("Django REST Framework's Response is JSON; Flask's Response is HTML", () => {
    const view = (imp: string) => `${imp}\n\ndef view(request):\n    name = request.GET.get("name")\n    return Response(name)\n`;
    expect(ids("shop/views.py", view("from rest_framework.response import Response"), "xss")).toEqual([]);
    expect(ids("app/views.py", view("from flask import Response"), "xss")).toEqual([5]);
  });

  it("Go: json.Marshal output written to the response can't carry markup; the raw value still can", () => {
    const handler = (body: string) => `package main\n\nimport (\n  "encoding/json"\n  "net/http"\n)\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n  name := r.URL.Query().Get("name")\n${body}\n}\n`;
    expect(ids("gw/main.go", handler(`  out, _ := json.Marshal(name)\n  w.Write(out)`), "xss")).toEqual([]);
    expect(ids("gw/main.go", handler(`  w.Write([]byte(name))`), "xss").length).toBeGreaterThan(0);
  });
});

describe("SQL built on the line, not any cursor.execute", () => {
  it("a constant query is not injection; concatenation, % and .format() are", () => {
    const at = (stmt: string) => ids("crapi/apps.py", `def seed(cursor, v):\n    ${stmt}\n`, "sql-injection");
    expect(at(`cursor.execute("select nextval('user_login_id_seq')")`)).toEqual([]);
    expect(at(`cursor.execute("SELECT * FROM t WHERE id = %s", (v,))`)).toEqual([]);
    expect(at(`cursor.execute("SELECT * FROM t WHERE id = '%s'" % v)`)).toEqual([2]);
    expect(at(`cursor.execute("SELECT * FROM t WHERE id = {}".format(v))`)).toEqual([2]);
  });
});

describe("connection-string templates are not credentials", () => {
  it("%s / Sprintf placeholders and {braces} name no credential; a literal user:password still does", () => {
    expect(ids("chatbot/db.py", `MONGO_URI = "mongodb://%s:%s@%s:%s/?directConnection=true" % (u, p, h, port)\n`, "hardcoded-secret")).toEqual([]);
    expect(ids("config/mongo.go", `package config\n\nvar DBURL = fmt.Sprintf("mongodb://%s:%s@%s:%s", DbUser, DbPassword, DbHost, DbPort)\n`, "hardcoded-secret")).toEqual([]);
    const settings = (url: string) => ids("app/settings.py", `DATABASE_URL = "${url}"\nDEBUG = False\n`, "hardcoded-secret");
    expect(settings("postgresql://{user}:{password}@db/app")).toEqual([]);
    expect(ids("app/settings.py", `DATABASE_URL = "postgresql://%s:%s@%s/app" % (u, p, h)\nDEBUG = False\n`, "hardcoded-secret")).toEqual([]);
    expect(settings("mongodb://admin:S3cretPass@db:27017/app")).toEqual([1]);
    expect(settings("postgresql://app:p%40ssw0rd@db/app")).toEqual([1]);   // URL-encoded real password
  });
});

describe("Java JWT: unverified claims and a token-chosen key (crAPI JwtProvider)", () => {
  it("JWTParser.parse(t).getJWTClaimsSet(), parseClaimsJwt and header.getJWKURL() are signature bypasses", () => {
    const src = `public class JwtProvider {\n  public String user(String token) throws ParseException {\n    return JWTParser.parse(token).getJWTClaimsSet().getSubject();\n  }\n  RSAKey key(JWSHeader header) {\n    URI jku = header.getJWKURL();\n    return load(jku);\n  }\n  Claims c(String t) { return Jwts.parser().parseClaimsJwt(t).getBody(); }\n}\n`;
    const f = analyzeFile("JwtProvider.java", src).indicators.filter(i => i.id === "jwt-none-alg");
    expect(f.map(i => i.line)).toEqual([3, 6, 9]);
    expect(f[1].detail).toMatch(/jku/);
    expect(f[0].detail).toMatch(/without verifying the token's signature/);
  });

  it("verified parsing is not", () => {
    const src = `public class JwtProvider {\n  public Claims claims(String token) {\n    return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();\n  }\n}\n`;
    expect(ids("JwtProvider.java", src, "jwt-none-alg")).toEqual([]);
  });
});
