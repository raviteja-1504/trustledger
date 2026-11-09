/**
 * Provider-format secrets, and the filters that decide whether a match is a credential or a placeholder.
 *
 * Every token is ASSEMBLED at run time from a prefix and a deterministic pseudo-random body, so no complete token-shaped
 * literal sits in the source (the same reason these repository-scanning fixtures never trip a secret scanner).
 */
import { analyzeFile } from "@/lib/scanner";

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX = "0123456789abcdef";
/** Deterministic body of `n` characters from `alphabet` (a mixed-in digit and letter guaranteed when the alphabet has both). */
function body(n: number, alphabet = ALNUM, seed = 7): string {
  let x = seed * 2654435761 % 4294967296, out = "";
  for (let i = 0; i < n; i++) { x = (x * 1664525 + 1013904223) % 4294967296; out += alphabet[Math.floor((x / 4294967296) * alphabet.length)]; }
  return out;
}
const labels = (content: string, path = "src/app.js") =>
  analyzeFile(path, content).indicators.filter(i => i.id === "hardcoded-secret").map(i => i.label);

describe("provider formats are detected, in code and in prose", () => {
  const cases: Array<[string, string]> = [
    ["Anthropic API key", ["sk", "ant", "api03", body(90, ALNUM + "_-")].join("-")],
    ["OpenAI API key", "sk-" + body(48)],
    ["OpenAI API key", "sk-proj-" + body(60, ALNUM + "_-", 3)],
    ["Slack webhook URL", ["https:/", "hooks.slack.com", "services", "T" + body(9, "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789", 2), "B" + body(9, "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789", 4), body(24)].join("/")],
    ["Telegram bot token", "123456789:" + body(35, ALNUM + "_-", 5)],
    ["DigitalOcean token", "dop_v1_" + body(64, HEX)],
    ["Hugging Face token", "hf_" + body(34)],
    ["GitHub fine-grained token", "github_pat_" + body(70, ALNUM + "_", 8)],
    ["PyPI upload token", "pypi-AgEIcHlwaS5vcmc" + body(70, ALNUM + "_-", 9)],
    ["Stripe restricted key", "rk_live_" + body(30)],
    ["Groq API key", "gsk_" + body(52)],
    ["Azure storage account key", "AccountKey=" + body(86) + "=="],
    ["Discord bot token", "M" + body(23, ALNUM + "0123456789", 6) + "." + body(6, ALNUM, 7) + "." + body(30, ALNUM + "_-", 8)],
    ["Mailchimp API key", body(32, HEX, 4) + "-us12"],
  ];
  it.each(cases)("%s", (label, token) => {
    // as an assignment in code...
    expect(labels(`const key = "${token}";\n`)).toContain(`Hardcoded ${label}`);
    // ...and pasted into prose, where a person would paste it
    expect(labels(`Rotate the key ${token} before Friday.\n`, "docs/runbook.txt")).toContain(`Hardcoded ${label}`);
  });

  it("an Anthropic key is reported once, not also as an OpenAI key", () => {
    const l = labels(`k = "${["sk", "ant", "api03", body(90, ALNUM + "_-")].join("-")}"\n`);
    expect(l).toEqual(["Hardcoded Anthropic API key"]);
  });
});

describe("a token with placeholder wording is not a credential", () => {
  it.each([
    "sk-" + "x".repeat(48),
    "sk-" + "your-api-key-here-".repeat(3),
    "hf_" + "X".repeat(34),
    "gsk_" + "*".repeat(20) + body(32),
    "dop_v1_" + "0".repeat(64),
  ])("%s", token => {
    expect(labels(`const key = "${token}";\n`)).toEqual([]);
  });
  it("ordinary words that merely start with sk- or hf_ are not tokens", () => {
    expect(labels(`const risk = "task-assessment-for-the-quarterly-review-meeting";\nconst desk = "hf_short";\n`)).toEqual([]);
  });
});

describe("the placeholder filter judges the token, not unrelated words on the line", () => {
  it("a leaked key next to an unrelated quoted word is still reported", () => {
    const key = "sk_live_" + body(30);
    expect(labels(`const stripe = require('stripe')('${key}');\n`)).toContain("Hardcoded Stripe API key");
  });
  it("an AWS key made only of letters is not mistaken for a label", () => {
    expect(labels(`const c = { accessKeyId: 'AKIA${"JINRRGLLJSIJUJYI"}', region: 'us-east-1' };\n`)).toContain("Hardcoded AWS Access Key ID");
  });
  it("AWS's documented example key stays suppressed", () => {
    expect(labels(`const k = "AKIAIOSFODNN7EXAMPLE";\n`)).toEqual([]);
  });
  it("a connection string whose user is called testuser is still a credential", () => {
    expect(labels(`uri: "mongodb://testuser:${body(10)}@db.internal:27017/main"\n`, "config/db.yml")).toContain("Hardcoded MongoDB credentials");
  });
});

describe("a provider token in a comment is still a leak", () => {
  it("is reported in // and # comments", () => {
    const key = "ghp_" + body(36);
    expect(labels(`// TODO remove this token ${key} before release\nrun();\n`)).toContain("Hardcoded GitHub token");
    expect(labels(`# temporary token ${key}\nX=1\n`, "deploy.sh")).toContain("Hardcoded GitHub token");
  });
  it("but a generic word=value in a comment is only a description", () => {
    expect(labels(`// set password = "${body(14)}" in the config\nrun();\n`)).toEqual([]);
  });
});

describe("database URLs", () => {
  it("postgres:// (the common scheme) is detected, not only postgresql://", () => {
    expect(labels(`DATABASE_URL = "postgres://app:${body(12)}@db.internal:5432/main"\n`, "src/db.py")).toContain("Hardcoded Postgres credentials");
  });
  it("a documented example password is not", () => {
    for (const url of ["postgres://user:pass@host:5432/dbname", "mysql://root:pw@localhost:3306/app", "mongodb://admin:password@localhost/db"]) {
      expect(labels(`$ connect ${url}\n`, "docs/usage.md")).toEqual([]);
    }
  });
});

describe("Basic authorization headers", () => {
  it("a short header that decodes to user:password is reported", () => {
    const b64 = Buffer.from("deploy:" + body(10)).toString("base64");
    expect(labels(`Authorization: Basic ${b64}\n`, "scripts/call.sh")).toContain("Hardcoded HTTP Basic Auth header");
  });
  it("the word Basic followed by something that is not user:password is not", () => {
    expect(labels(`The Basic ${Buffer.from("just some words with no colon at all").toString("base64")} plan\n`, "docs/a.txt")).toEqual([]);
  });
});

describe("service-account JSON and key-named values", () => {
  it("a GCP key id is reported, and \"private_key\": \"pk\" is not", () => {
    expect(labels(`{ "type": "service_account", "private_key_id": "${body(40, HEX)}" }\n`, "creds.json")).toContain("Hardcoded GCP service account key");
    expect(labels(`{ "private_key": "pk" }\n`, "a.json")).toEqual([]);
  });
  it("an AWS secret key next to its name is reported, with the value as its own placeholder check", () => {
    expect(labels(`aws_secret_access_key = ${body(40, ALNUM + "/+", 11)}\n`, "creds")).toContain("Hardcoded AWS secret access key");
    expect(labels(`aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n`, "creds")).toEqual([]);
  });
  it("a Datadog key is reported next to its name and not elsewhere", () => {
    expect(labels(`DD_API_KEY=${body(32, HEX, 12)}\n`, "env.sh")).toContain("Hardcoded Datadog API key");
    expect(labels(`const checksum = "${body(32, HEX, 12)}";\n`)).toEqual([]);
  });
  it("PASETO and PASERK keys are reported; their all-A zero padding is not", () => {
    expect(labels(`{ "paserk": "k4.secret.${body(60, ALNUM + "_-", 13)}" }\n`, "keys.json")).toContain("Hardcoded PASERK key");
    expect(labels(`{ "paserk": "k4.secret.${"A".repeat(60)}" }\n`, "keys.json")).toEqual([]);
  });
});

describe("a bare long hex value assigned to a key name", () => {
  const key = body(48, HEX, 21);
  it("is reported (Key = <hex>, secret: <hex>)", () => {
    expect(analyzeFile("conf/app.txt", `Key = ${key}\n`).indicators.some(i => i.id === "high-entropy-secret")).toBe(true);
    expect(analyzeFile("conf/app.yml", `secret: ${key}\n`).indicators.some(i => i.id === "hardcoded-secret" || i.id === "high-entropy-secret")).toBe(true);
  });
  it("is not when the line is about a hash, a digest or an id", () => {
    for (const l of [`cache key (sha256) = ${key}`, `Key = ${key} # checksum`, `commit key: ${key}`]) {
      expect(analyzeFile("conf/app.txt", l + "\n").indicators.some(i => i.id === "high-entropy-secret")).toBe(false);
    }
  });
  it("is not when it is short or repetitive", () => {
    expect(analyzeFile("conf/app.txt", `Key = ${body(16, HEX, 3)}\n`).indicators.some(i => i.id === "high-entropy-secret")).toBe(false);
    expect(analyzeFile("conf/app.txt", `Key = ${"ab".repeat(24)}\n`).indicators.some(i => i.id === "high-entropy-secret")).toBe(false);
  });
});

describe("infrastructure files keep their own, more specific secret findings", () => {
  const ids = (path: string, text: string) => analyzeFile(path, text).indicators.map(i => i.id);
  it("a Kubernetes Secret reports the Kubernetes rule, not a generic one on the same line", () => {
    const k8s = `apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  password: ${Buffer.from("Zk2pQm9LxV7r").toString("base64")}\n`;
    expect(ids("k8s/secret.yaml", k8s)).toContain("iac-k8s-committed-secret");
    expect(ids("k8s/secret.yaml", k8s)).not.toContain("hardcoded-secret");
  });
  it("a Terraform default and a Dockerfile ENV are left to their own rules", () => {
    expect(ids("infra/variables.tf", `variable "db_password" {\n  default = "Zk2pQm9LxV7r"\n}\n`)).not.toContain("hardcoded-secret");
  });
});

describe("JSON and dict keys do not hide the secret beside them", () => {
  it("is reported under the generic rule's own label, not a fallback one", () => {
    expect(labels(`{ "api_key": "${body(16, ALNUM, 31)}" }\n`, "config/app.json")).toEqual(["Hardcoded API key"]);
    expect(labels(`{ "password": "${body(14, ALNUM, 32)}" }\n`, "config/app.json")).toEqual(["Hardcoded password"]);
    // a letters-only key reads like a UI label; it must not silence the line (the older rule labels this one "secret")
    expect(labels(`{ "consumerSecret": "${body(14, ALNUM, 34)}" }\n`, "config/app.json")).toEqual(["Hardcoded secret"]);
  });
  it("PASETO tokens are reported and their all-A padding is not", () => {
    expect(labels(`{ "token": "v4.local.${body(60, ALNUM + "_-", 33)}" }\n`, "keys.json")).toContain("Hardcoded PASETO token");
    expect(labels(`{ "token": "v4.local.${"A".repeat(60)}" }\n`, "keys.json")).toEqual([]);
  });
});
