/**
 * Files that exist to hold credentials: the format is the evidence, so even a short password counts.
 */
import { findCredentialFileFormats } from "@/lib/credentialFiles";
import { analyzeFile } from "@/lib/scanner";

const run = (path: string, text: string) => findCredentialFileFormats(text.split("\n"), path);
const labelsOf = (path: string, text: string) => run(path, text).map(f => `${f.label}@${f.line}`);

describe(".netrc", () => {
  it("every machine's password is reported, short or not", () => {
    const t = "machine imap.example.com login me password pass123\nmachine smtp.example.com login me password hunter2\n";
    expect(labelsOf("home/.netrc", t)).toEqual(["Hardcoded password in .netrc@1", "Hardcoded password in .netrc@2"]);
  });
  it("a reference is not a password, and a file without one is clean", () => {
    expect(run(".netrc", "machine a login me password ${NETRC_PASSWORD}\n")).toEqual([]);
    expect(run(".netrc", "machine a login me\n")).toEqual([]);
  });
  it("the same line in another file is not a .netrc finding", () => {
    expect(run("notes.txt", "machine a login me password pass123\n")).toEqual([]);
  });
});

describe(".pgpass", () => {
  it("a host:port:db:user:password line is reported; comments and wildcard passwords' lines too only when they have a password field", () => {
    const t = "#hostname:port:database:username:password\nlocalhost:5432:main:app:Zk2pQm9L\n";
    expect(labelsOf("db/.pgpass", t)).toEqual(["Hardcoded password in .pgpass@2"]);
  });
  it("a line with too few fields is not", () => {
    expect(run(".pgpass", "localhost:5432:main\n")).toEqual([]);
  });
});

describe(".git-credentials", () => {
  it("a URL with a user and password is reported even when the user is an email address", () => {
    expect(labelsOf(".git-credentials", "https://me@example.com:Zk2pQm9L@github.com\n")).toEqual(["Stored Git credentials@1"]);
    expect(labelsOf(".git-credentials", "https://me:Zk2pQm9L@github.com\n")).toEqual(["Stored Git credentials@1"]);
  });
  it("a URL without a password is not", () => {
    expect(run(".git-credentials", "https://github.com/org/repo\n")).toEqual([]);
  });
});

describe(".npmrc", () => {
  it("an auth token, _auth or _password is reported", () => {
    expect(labelsOf(".npmrc", "registry=https://registry.example.com/\n//registry.example.com/:_authToken=Zk2pQm9LxV7rTnWb\n")).toEqual(["npm auth token in .npmrc@2"]);
    expect(labelsOf(".npmrc", "_auth=Zk2pQm9LxV7rTnWb\n")).toEqual(["npm auth token in .npmrc@1"]);
  });
  it("an environment reference is not", () => {
    expect(run(".npmrc", "//registry.example.com/:_authToken=${NPM_TOKEN}\n")).toEqual([]);
  });
});

describe("password hashes", () => {
  it("htpasswd / shadow lines are reported in any file, whatever its name", () => {
    expect(labelsOf("proftpdpasswd", "root:$6$LnUhhUi45srUKt9i$4Hp6VRTOB2mxvsYH8mwsCfBryg6hCbm4:3044:304\n")).toEqual(["Password hash (htpasswd / shadow)@1"]);
    expect(labelsOf("public_html/.htpasswd", "admin:$apr1$tp8glkbm$fjg65tI1eipoBh62aEjIy0\n")).toEqual(["Password hash (htpasswd / shadow)@1"]);
  });
  it("accounts with no password hash are not", () => {
    expect(run("etc/shadow", "root::17431:0:99999:7:::\ndaemon:*:17431:0:99999:7:::\n")).toEqual([]);
  });
  it("a bcrypt hash in data is reported at medium severity", () => {
    const hash = "$2y$12$" + ("s.YfVZdfvAuO/Iz6fte5iO..ZbbEgreZnDcYOGvX4NGJskYQIstc" + "Aq7".repeat(5)).slice(0, 53);
    const f = run("db/dump.sql", `INSERT INTO users VALUES (1, 'rogers63', '${hash}', 1);\n`);
    expect(f).toEqual([{ line: 1, label: "bcrypt password hash", severity: "medium" }]);
  });
});

describe("keys", () => {
  it("a Rails master.key is reported; other files named differently are not", () => {
    expect(labelsOf("config/master.key", "3ebf21f8e5d1ab86b27a720842c3bb56\n")).toEqual(["Rails master key@1"]);
    expect(run("config/notes.txt", "3ebf21f8e5d1ab86b27a720842c3bb56\n")).toEqual([]);
  });
  it("an unencrypted PuTTY private key is reported on its header; an encrypted one is not", () => {
    const open = "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: k\nPublic-Lines: 1\nAAAA\nPrivate-Lines: 1\nBBBB\n";
    expect(labelsOf("keys/id.ppk", open)).toEqual(["Unencrypted PuTTY private key@1"]);
    expect(run("keys/id.ppk", open.replace("Encryption: none", "Encryption: aes256-cbc"))).toEqual([]);
  });
});

describe("registry and configuration files", () => {
  it("a Docker auth entry that decodes to user:password is reported; an arbitrary base64 string is not", () => {
    const auth = Buffer.from("deploy:Zk2pQm9LxV7r").toString("base64");
    expect(labelsOf(".docker/config.json", `{ "auths": { "reg.example.com": { "auth": "${auth}" } } }\n`)).toEqual(["Docker registry credentials@1"]);
    expect(run(".docker/config.json", `{ "auth": "${Buffer.from("no colon in this one at all").toString("base64")}" }\n`)).toEqual([]);
  });
  it("an XML password element is reported, a template is not", () => {
    expect(labelsOf("filezilla.xml", `<Server>\n  <Pass encoding="base64">Zk2pQm9LxV7rTnWb</Pass>\n</Server>\n`)).toEqual(["Password in XML configuration@2"]);
    expect(run("web.config", `<add key="x"><Password>\${DB_PASSWORD}</Password></add>\n`)).toEqual([]);
  });
  it("credentials passed straight to login() are reported", () => {
    expect(labelsOf("sf.js", "conn.login('me@example.com', 'salesforcepw9', cb);\n")).toEqual(["Credentials passed to login()@1"]);
    expect(run("sf.js", "conn.login(user, pass, cb);\n")).toEqual([]);
  });
});

describe("through the scanner", () => {
  const found = (path: string, text: string) => analyzeFile(path, text).indicators.filter(i => i.id === "hardcoded-secret").map(i => `${i.label}@${i.line}`);
  it("is reported as a hardcoded secret with its label and line", () => {
    expect(found("home/.netrc", "machine a login me password pass123\n")).toEqual(["Hardcoded password in .netrc@1"]);
  });
  it("is not applied in test directories (fixtures are not leaks)", () => {
    expect(found("src/__tests__/fixtures/.netrc", "machine a login me password pass123\n")).toEqual([]);
  });
  it("does not duplicate a line another rule already reported", () => {
    expect(found(".git-credentials", "https://me:Zk2pQm9LxV7r@github.com\n").length).toBe(1);
  });
});
