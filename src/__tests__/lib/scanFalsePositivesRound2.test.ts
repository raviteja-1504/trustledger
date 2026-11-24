/**
 * @jest-environment node
 *
 * False positives found scanning ten public repositories (ms, eve, kit, arc-remote-signer, arc-node, workerd, vinext, ...),
 * each with the counterpart that must still be reported:
 *  - a project's own LICENSE file and the header every one of its files carries are not "license contamination";
 *  - `compiled.re.exec(path)` runs a regular expression, not a command;
 *  - a hand-decoded token whose file checks an HMAC with a constant-time compare is verified;
 *  - `IN (${keys.map(() => "?").join(", ")})` interpolates bind placeholders, not data;
 *  - `dangerouslySetInnerHTML={{ __html: constantScript }}` injects a constant, not request data.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";
jest.setTimeout(300_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

const scanMany = (files: Array<{ path: string; content: string }>) =>
  runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files })
    .files.map(f => ({ path: f.file_path, ids: f.indicators.filter(i => i.line != null && i.id !== "ai-model-attribution").map(i => i.id) }));
const ids = (path: string, content: string) => scanMany([{ path, content }])[0].ids;

describe("license contamination", () => {
  const MIT = `The MIT License (MIT)\n\nCopyright (c) 2025 Acme, Inc.\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the "Software"), to deal\nin the Software without restriction.\n`;
  const header = (holder: string) => `// Copyright (c) 2025 ${holder}\n// Licensed under the Apache License, Version 2.0 (the "License");\n// you may not use this file except in compliance with the License.\n`;
  const src = (n: number) => `export const value${n} = ${n};\n`;

  it("a project's own LICENSE / NOTICE file is not contamination, the same text in source still is", () => {
    for (const name of ["LICENSE", "LICENSE.md", "COPYING", "NOTICE", "licenses/MIT.txt"]) {
      expect(ids(name, MIT)).not.toContain("license-header-contamination");
    }
    expect(ids("src/vendor.ts", `/*\n${MIT}*/\n${src(1)}`)).toContain("license-header-contamination");
  });
  it("a header that the project puts on many of its files is its own; on one or two files it is still reported", () => {
    const three = scanMany([1, 2, 3].map(n => ({ path: `src/f${n}.ts`, content: header("Acme, Inc.") + src(n) })));
    for (const f of three) expect(f.ids).not.toContain("license-header-contamination");
    const two = scanMany([1, 2].map(n => ({ path: `src/f${n}.ts`, content: header("Acme, Inc.") + src(n) })));
    for (const f of two) expect(f.ids).toContain("license-header-contamination");
  });
  it("three files that each carry a different holder are not 'the same project header'", () => {
    const mixed = scanMany(["Alpha Ltd", "Beta GmbH", "Gamma Corp"].map((h, n) => ({ path: `src/f${n}.ts`, content: header(h) + src(n) })));
    for (const f of mixed) expect(f.ids).toContain("license-header-contamination");
  });
});

describe("a regular expression's exec() is not a command", () => {
  it("compiled.re.exec(pathname) is not command injection; child_process.exec(cmd) still is", () => {
    const re = `export async function handler(request: Request, compiled: { re: RegExp }) {\n  const pathname = new URL(request.url).pathname;\n  return compiled.re.exec(pathname);\n}\n`;
    expect(ids("src/match.ts", re)).not.toContain("command-injection");
    const cmd = `import { exec } from "child_process";\nexport async function handler(request: Request) {\n  const name = new URL(request.url).searchParams.get("n");\n  exec("ls " + name);\n}\n`;
    expect(ids("src/run.ts", cmd)).toContain("command-injection");
  });
});

describe("a hand-decoded token whose file verifies an HMAC", () => {
  const decode = (verify: string) => `${verify ? 'import { createHmac, timingSafeEqual } from "node:crypto";\n' : ""}${verify}\nexport function readClaims(token: string) {\n  const [payload] = token.split(".");\n  return JSON.parse(Buffer.from(payload, "base64url").toString());\n}\n`;
  it("is verified; without any check it is still reported", () => {
    const verified = decode(`export function check(payload: string, mac: Buffer, key: Buffer) {\n  return timingSafeEqual(mac, createHmac("sha256", key).update(payload).digest());\n}`);
    expect(ids("src/token.ts", verified)).not.toContain("jwt-none-alg");
    expect(ids("src/token.ts", decode(""))).toContain("jwt-none-alg");
  });
});

describe("SQL built from a list of bind placeholders", () => {
  const q = (list: string) => `export function drop(db: any, keys: string[]) {\n  db.exec(\`DELETE FROM pending WHERE object_key IN (\${${list}})\`, ...keys);\n}\n`;
  it("interpolating only '?' placeholders is parameterised; interpolating the values is not", () => {
    expect(ids("src/store.ts", q(`keys.map(() => "?").join(", ")`))).not.toContain("sql-injection");
    expect(ids("src/store.ts", q(`keys.join(", ")`))).toContain("sql-injection");
  });
  it("db.exec() with a template literal is not command injection; exec() alone still is", () => {
    // db.exec / sqlite3.exec are SQL calls, not shell commands; child_process.exec is still caught by its own rule
    expect(ids("src/store.ts", q(`keys.join(", ")`))).not.toContain("command-injection");
    const shell = `import { exec } from "child_process";\nconst n = req.query.name;\nexec(\`ls \${n}\`);\n`;
    expect(ids("src/run.ts", shell)).toContain("command-injection");
  });
  it("a placeholder list held in a variable counts the same", () => {
    const code = `export function drop(db: any, keys: string[]) {\n  const placeholders = keys.map(() => "?").join(", ");\n  db.exec(\`DELETE FROM pending WHERE object_key IN (\${placeholders})\`, ...keys);\n}\n`;
    expect(ids("src/store.ts", code)).not.toContain("sql-injection");
  });
  it("a concatenated value next to an unrelated placeholder list is still reported", () => {
    const code = `export function find(db: any, name: string, keys: string[]) {\n  const marks = keys.map(() => "?").join(", ");\n  db.exec("SELECT * FROM t WHERE name = '" + name + "' AND k IN (" + marks + ")", ...keys);\n}\n`;
    expect(ids("src/store.ts", code)).toContain("sql-injection");
  });
});

describe("Go md5/sha1 used as a non-security cache key", () => {
  it("md5.Sum for a cache key is not flagged; md5.Sum of a password is", () => {
    const cacheKey = `package main\n\nimport (\n\t"crypto/md5"\n\t"fmt"\n)\n\nfunc cacheKey(url string) string {\n\treturn fmt.Sprintf("%x", md5.Sum([]byte(url)))\n}\n`;
    expect(ids("store.go", cacheKey)).not.toContain("weak-crypto");
    const password = `package main\n\nimport (\n\t"crypto/md5"\n\t"fmt"\n)\n\nfunc hashPw(pw string) string {\n\treturn fmt.Sprintf("%x", md5.Sum([]byte(pw)))\n}\n`;
    expect(ids("auth.go", password)).toContain("weak-crypto");
  });
  it("sha1 ETag computation is not flagged; sha1 of a secret still is", () => {
    const etag = `package main\n\nimport (\n\t"crypto/sha1"\n\t"fmt"\n)\n\nfunc etag(content []byte) string {\n\treturn fmt.Sprintf("%x", sha1.Sum(content))\n}\n`;
    expect(ids("etag.go", etag)).not.toContain("weak-crypto");
    const token = `package main\n\nimport (\n\t"crypto/sha1"\n\t"fmt"\n)\n\nfunc sign(secret string) string {\n\treturn fmt.Sprintf("%x", sha1.Sum([]byte(secret)))\n}\n`;
    expect(ids("sign.go", token)).toContain("weak-crypto");
  });
});

describe("TOCTOU in JS: same-variable and mkdir exclusion", () => {
  it("existsSync + writeFile on a request-derived path is a race; on a constant/param path it is not", () => {
    // request-derived path: req.body.path → tainted → TOCTOU
    const tainted = `import fs from "fs";\napp.post("/upload", (req, res) => {\n  const p = req.body.path;\n  if (!fs.existsSync(p)) {\n    fs.writeFileSync(p, req.body.data);\n  }\n});\n`;
    expect(ids("src/upload.ts", tainted)).toContain("toctou");
    // constant config path not from request: no TOCTOU (build-tool/config pattern)
    const constant = `import fs from "fs";\nfunction save(p, data) {\n  if (!fs.existsSync(p)) {\n    fs.writeFileSync(p, data);\n  }\n}\n`;
    expect(ids("src/save.ts", constant)).not.toContain("toctou");
    // different variables: even when tainted, different-variable pair is not a race
    const diff = `import fs from "fs";\napp.get("/check", (req, res) => {\n  const dir = req.query.dir;\n  if (!fs.existsSync(dir)) {\n    fs.writeFileSync("other.txt", "init");\n  }\n});\n`;
    expect(ids("src/setup.ts", diff)).not.toContain("toctou");
  });
  it("existsSync + mkdirSync is idiomatic 'create if not exists', not a race", () => {
    const mkdir = `import fs from "fs";\nfunction ensureDir(dir) {\n  if (!fs.existsSync(dir)) {\n    fs.mkdirSync(dir, { recursive: true });\n  }\n}\n`;
    expect(ids("src/ensureDir.ts", mkdir)).not.toContain("toctou");
  });
});

describe("dangerouslySetInnerHTML with a constant script", () => {
  it("a script string built from constants is not XSS; request data is", () => {
    const constant = `const THEME_KEY = "theme";\nconst themeScript = \`try{var t=localStorage.getItem(\${JSON.stringify(THEME_KEY)});}catch(e){}\`;\nexport default function Layout() {\n  return <script dangerouslySetInnerHTML={{ __html: themeScript }} />;\n}\n`;
    expect(ids("app/layout.tsx", constant)).not.toContain("xss");
    const dynamic = `export default function Card({ html }: { html: string }) {\n  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n`;
    expect(ids("app/card.tsx", dynamic)).toContain("xss");
  });
  it("a script that interpolates a variable is still reported", () => {
    const code = `export default function Layout({ name }: { name: string }) {\n  const script = \`window.user = "\${name}";\`;\n  return <script dangerouslySetInnerHTML={{ __html: script }} />;\n}\n`;
    expect(ids("app/layout.tsx", code)).toContain("xss");
  });
});

describe("Node.js and Python md5/sha1 used as a non-security cache key", () => {
  it("createHash('md5') inside a cacheKey function is not flagged", () => {
    const cacheKey = `import crypto from "node:crypto";\nfunction cacheKey(url: string) {\n  return crypto.createHash("md5").update(url).digest("hex");\n}\n`;
    expect(ids("src/cache.ts", cacheKey)).not.toContain("weak-crypto");
  });
  it("createHash('md5') for an etag is not flagged", () => {
    const etag = `import { createHash } from "crypto";\nfunction etag(body: Buffer): string {\n  return createHash("md5").update(body).digest("hex");\n}\n`;
    expect(ids("src/etag.ts", etag)).not.toContain("weak-crypto");
  });
  it("createHash('md5') in an unrelated context is still flagged", () => {
    const noCtx = `import { createHash } from "crypto";\nfunction sign(payload: string) {\n  return createHash("md5").update(payload).digest("hex");\n}\n`;
    expect(ids("src/sign.ts", noCtx)).toContain("weak-crypto");
  });
  it("hashlib.md5 inside a get_cache_key function is not flagged (Python)", () => {
    const cacheKey = `import hashlib\n\ndef get_cache_key(path: str) -> str:\n    return hashlib.md5(path.encode()).hexdigest()\n`;
    expect(ids("utils/cache.py", cacheKey)).not.toContain("weak-crypto");
  });
  it("hashlib.md5 of a password argument is still flagged (Python password-context gate)", () => {
    const password = `import hashlib\n\ndef hash_password(password: str) -> str:\n    return hashlib.md5(password.encode()).hexdigest()\n`;
    expect(ids("auth/hash.py", password)).toContain("weak-crypto");
  });
});
