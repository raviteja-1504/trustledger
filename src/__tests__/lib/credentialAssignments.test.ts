/**
 * Credentials assigned to a name that says what they are. The name is the evidence, so the tests are about telling a
 * credential from the many strings that sit beside such a name.
 */
import { findCredentialAssignment, plausibleCredentialValue } from "@/lib/credentialAssignments";
import { analyzeFile } from "@/lib/scanner";

const hit = (line: string, path = "config/app.js") => findCredentialAssignment(line, path);
const keyOf = (line: string, path?: string) => hit(line, path)?.key ?? null;

describe("quoted values, whatever the shape of the key", () => {
  it.each([
    ['"consumerSecret": "E+JtA-ls$-%@2Xv0",', "consumerSecret"],
    ['"secret-key": "70948725754237bdf3fafdd4e1041322",', "secret-key"],
    ["'cookieValidationKey' => 'Q5i127brjr4c-K71_3JxnZo-9JFaqMCg',", "cookieValidationKey"],
    ["HMACSecret:       \"rFWCJec49in1RzTOVKoVa1xfaIEr3NIX\",", "HMACSecret"],
    ["session = create(login: ben.login, password: \"wopduzmm9\")", "password"],
    ["'PASSWORD': 'iutnjmdvesnufkx9',", "PASSWORD"],
  ])("%s", (line, key) => { expect(keyOf(line)).toBe(key); });

  it("a key in quotes does not make the line look like a label (the bug that silenced most JSON secrets)", () => {
    const f = analyzeFile("config/auth.json", '{\n  "consumerSecret": "E+JtA-ls$-%@2Xv0aB",\n  "name": "demo"\n}\n');
    expect(f.indicators.filter(i => i.id === "hardcoded-secret").map(i => i.line)).toEqual([2]);
  });
});

describe("unquoted settings, in files where that is how they are written", () => {
  it.each([
    ["GANDI_API_KEY=uuvclbfguuiyupykppwliwnn1", ".env"],
    ["MYSQL_ROOT_PASSWORD: pqksbskl9", "docker/compose.yml"],
    ["  secret_key = yLryKGwcGc3ez9G8YAnjeYMQOc # Sensitive", "cloud/.s3cfg"],
    ["export API_TOKEN=3b6311afca5bd8aac647b316704e9c6d", "deploy.sh"],
  ])("%s (%s)", (line, path) => { expect(hit(line, path)).not.toBeNull(); });

  it("but not in source code, where an unquoted assignment is a variable", () => {
    expect(hit("config.Password = values[EnvPassword]", "pkg/config.go")).toBeNull();
    expect(hit("password = opts.Password", "pkg/config.go")).toBeNull();
    expect(hit("MYSQL_ROOT_PASSWORD=pqksbskl9", "src/app.ts")).toBeNull();
  });

  it("a command line flag is a credential too", () => {
    expect(hit("mysql --user=root --password=2mPnZ9z5rx --host db", "Makefile")).not.toBeNull();
    expect(hit("redis-server --requirepass r3dis_Pw_9z", "docker-compose.sh")).not.toBeNull();
  });
});

describe("what sits beside a credential name but is not one", () => {
  it.each([
    ["credentials: 'include',", "a fetch option"],
    ["TRANSIP_PRIVATE_KEY_PATH = \"transip.key\"", "a path"],
    ["\"SECRET_HASH\": \"oT5ZkS8ctnrhYeeGsGTvOzPhoc/Jd1cO5fueBWFVmp8=\",", "a hash"],
    ["const AWS_SECRET_ID = \"prod/database/password-v2\";", "an identifier of a secret"],
    ["\"SessionSecret\": \"session.secret\",", "a config key path"],
    ["const EXPRESS_TOKEN = 'paypal_express_token';", "snake_case words"],
    ["const ResetPasswordAction = \"ResetPassword\"", "an identifier"],
    ["const NCRYPT_KDF_SECRET_VALUE = \"KDFKeySecret\";", "CamelCase words"],
    ["apiKey: 'base64EncodedKey',", "a placeholder word"],
    ["password: ${DB_PASSWORD}", "a template"],
    ["password: {{ .Values.db.password }}", "a template"],
    ["token: process.env.API_TOKEN,", "a reference"],
    ["'id-ce-privateKeyUsagePeriod' => '2.5.29.16',", "an OID"],
    ["password: \"your-password-here\"", "a placeholder"],
    ["User.objects.filter(password__startswith='sha1$$')", "a Django lookup"],
    ["secret: \"<paste secret>\"", "a template"],
    ["token = 'changeme'", "a placeholder"],
  ])("%s (%s)", (line) => { expect(hit(line)).toBeNull(); });

  it("the same line is not judged in a test file (generic rules read production code)", () => {
    const f = analyzeFile("src/__tests__/auth.test.ts", `const password = "Zk2pQm9LxV7r";\n`);
    expect(f.indicators.filter(i => i.id === "hardcoded-secret")).toEqual([]);
  });
});

describe("plausibleCredentialValue", () => {
  it("needs more length for names that are not obviously passwords", () => {
    expect(plausibleCredentialValue("Zk2pQm9L", "password")).toBe(true);
    expect(plausibleCredentialValue("Zk2pQm9L", "dbPassword")).toBe(true);
    expect(plausibleCredentialValue("Zk2pQ", "password")).toBe(false);
    expect(plausibleCredentialValue("Zk2pQm9", "apiKey")).toBe(false);
    expect(plausibleCredentialValue("Zk2pQm9LxV", "apiKey")).toBe(true);
  });
  it("a short all-letter value is a word, a long random one is not", () => {
    expect(plausibleCredentialValue("tgztih", "password")).toBe(false);
    expect(plausibleCredentialValue("tgztihfqfw", "password")).toBe(true);
  });
  it("random mixed-case letters are not an identifier, real identifiers are", () => {
    expect(plausibleCredentialValue("vhZsvokmid", "password")).toBe(true);
    expect(plausibleCredentialValue("someVariableName", "password")).toBe(false);
  });
  it("sequences and repeated filler are examples", () => {
    expect(plausibleCredentialValue("1234567890abcdef", "api_key")).toBe(false);
    expect(plausibleCredentialValue("aaaaaaaaaaaa", "api_key")).toBe(false);
  });
  it("uses the scanner's own placeholder wording when given", () => {
    const sample = (v: string) => /sample/.test(v);
    expect(plausibleCredentialValue("sampleSecret9x", "password", { isPlaceholder: sample })).toBe(false);
    expect(plausibleCredentialValue("sampleSecret9x", "password")).toBe(true);
  });
});

describe("safety on hostile input", () => {
  it("a very long line is skipped, not scanned (bounded work)", () => {
    const long = `password = "${"a1".repeat(5000)}"`;
    const t0 = Date.now();
    expect(hit(long)).toBeNull();
    expect(Date.now() - t0).toBeLessThan(200);
  });
  it("a line full of repeated key-like text does not blow up", () => {
    const evil = "secret-".repeat(400) + "=" + "x".repeat(50);
    const t0 = Date.now();
    hit(evil);
    expect(Date.now() - t0).toBeLessThan(500);
  });
});

describe("a literal that only starts a runtime-built value", () => {
  it("is not the credential (string concatenation continues the value)", () => {
    expect(hit(`String apiKey = "API_KEY=" + java.util.UUID.randomUUID();`, "src/Keys.java")).toBeNull();
    expect(hit(`const secret = "Bearer-prefix-" + process.env.TOKEN;`, "src/a.js")).toBeNull();
  });
  it("a whole literal still is", () => {
    expect(hit(`String apiKey = "Zx9Kq2Lm7Pw4Rt8Vb3Nc";`, "src/Keys.java")).not.toBeNull();
  });
});

describe("status maps, colour tables and labels (found by scanning this repository's own source)", () => {
  it.each([
    ['secrets: "Credentials", compliance: "Compliance",', "a label map"],
    ['const DOT = { pass: "bg-emerald-500", partial: "bg-amber-400" };', "CSS classes"],
    ['  pass: "text-emerald-700", partial: "text-amber-700",', "CSS classes"],
    ['  "secret-exposed":   "#dc2626",', "a colour"],
    ['"hardcoded-secret":"#ef4444","eval-exec":"#ef4444",', "a colour table"],
    ['r("ai_policy", "Approved AI tools policy", ok ? "pass" : "partial", 80)', "a ternary"],
  ])("%s (%s)", (line) => { expect(hit(line)).toBeNull(); });

  it("a password-suffixed name is still a credential name: IMAP_PASS and db-pass", () => {
    expect(hit("IMAP_PASS=eetfvaeb9", "mail/.env")).not.toBeNull();
    expect(hit('"db-pass": "Zk2pQm9LxV7r"', "config/a.json")).not.toBeNull();
  });
  it("but a bare 'pass' is not", () => {
    expect(hit('"pass": "Zk2pQm9LxV7r"', "config/a.json")).toBeNull();
  });
});
