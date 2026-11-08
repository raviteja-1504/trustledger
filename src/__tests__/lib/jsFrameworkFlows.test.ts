/** @jest-environment node */
/**
 * Framework-shaped flows the JS/TS engine resolves (each case paired with its safe twin where one exists):
 * Vue `ref()` declarations and `v-html`, React state set from a response, NestJS `@Redirect()` handlers,
 * template-engine source compilation, LLM completions over request messages, handlers held in class fields,
 * ORM whole-object writes (mass assignment), HTTP parameter type confusion, and Flask-WTF `populate_obj`.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

type Step = { file: string; line: number; kind: string };
type Hit = { file: string; id: string; line: number; trace: Step[] };
const scan = (files: Array<{ path: string; content: string }>): Hit[] =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files }).files.flatMap(f => f.indicators
    .filter(i => i.sourceExpr && i.line != null)
    .map(i => ({ file: f.file_path, id: i.id, line: i.line!, trace: (i as { trace?: Step[] }).trace ?? [] })));
const one = (path: string, content: string) => scan([{ path, content }]);
const of = (hits: Hit[], id: string) => hits.filter(h => h.id === id);
const lines = (h: Hit | undefined) => (h?.trace ?? []).map(t => t.line);

describe("trace provenance", () => {
  it("a Vue ref declared from the URL query starts there, not at a later handler write", () => {
    const vue = `<script setup>\nimport { ref } from 'vue'\nimport axios from 'axios'\n\nconst query = new URLSearchParams(window.location.search)\nconst x = 1\nconst welcomeMessage = ref(query.get('welcome') || 'Explore.')\nasync function previewLogo() {\n  const response = await axios.get('/api/x', { responseType: 'text' })\n  welcomeMessage.value = response.data\n}\n</script>\n<template>\n  <div v-html="welcomeMessage"></div>\n</template>\n`;
    const [h] = of(one("webapp/src/App.vue", vue), "xss");
    expect(h).toBeDefined();
    expect(lines(h)).toContain(5);    // through `new URLSearchParams(window.location.search)`
    expect(lines(h)).not.toContain(10);
  });

  it("a Vue SFC with CRLF line endings is analysed like an LF one (v-html fed by a computed URL value)", () => {
    const vue = `<script lang="ts" setup>\nimport { computed } from 'vue'\n\nconst folderPath = computed(() => {\n  const href = window.location.href.split('?')\n  return new URLSearchParams(href[1]).get('name') || 'UNKNOWN'\n})\n</script>\n\n<template>\n  <div v-html="folderPath" />\n</template>\n`;
    const lf = of(one("app/T.vue", vue), "xss");
    const crlf = of(one("app/T.vue", vue.replace(/\n/g, "\r\n")), "xss");
    expect(lf).toHaveLength(1);
    expect(crlf.map(h => h.line)).toEqual(lf.map(h => h.line));
    expect(lines(crlf[0])).toContain(5);
  });

  it("a React state variable beside a constant: the trace follows the state to its setter", () => {
    const js = `import React, { useState, useEffect } from 'react';\nimport axios from 'axios';\nconst authorUrl = "https://x/y.png"\nexport default function S() {\n  function clean(s) {\n    return s.replace('<script>', '');\n  }\n  let [desc, setDesc] = useState('');\n  useEffect(() => {\n    axios.get('https://api/x')\n      .then(response => {\n        setDesc(response.data.desc);\n      })\n  }, []);\n  return (<div dangerouslySetInnerHTML={\n    {__html: \`\n    <img src=\${authorUrl}\n         alt=\${clean(desc)} />\n    \`}} />);\n}\n`;
    const [h] = of(one("src/S.js", js), "xss");
    expect(lines(h)).toContain(12);   // setDesc(response.data.desc)
    expect(lines(h)).toContain(18);   // clean(desc)
  });
});

describe("NestJS", () => {
  const ctl = (body: string) => `import { Controller, Get, Post, Query, Body, Redirect } from '@nestjs/common';\nimport * as dot from 'dot';\n@Controller('auth')\nexport class AuthController {\n${body}\n}\n`;
  it("@Redirect() returning a request-chosen url is an open redirect; a fixed url is not", () => {
    expect(of(one("a.controller.ts", ctl(`  @Get('c')\n  @Redirect()\n  c(@Query('next') next?: string) {\n    return { url: next || '/dashboard' };\n  }`)), "open-redirect")).toHaveLength(1);
    expect(of(one("a.controller.ts", ctl(`  @Get('c')\n  @Redirect()\n  c(@Query('next') next?: string) {\n    return { url: '/dashboard', statusCode: 302 };\n  }`)), "open-redirect")).toHaveLength(0);
  });
  it("a request body compiled by doT is template injection; a constant template rendering it is not", () => {
    expect(of(one("a.controller.ts", ctl(`  @Post('p')\n  p(@Body('template') template: string): string {\n    return dot.template(template)({ appName: 'X' });\n  }`)), "ssti")).toHaveLength(1);
    expect(of(one("a.controller.ts", ctl(`  @Post('p')\n  p(@Body('name') name: string): string {\n    return dot.template('<p>{{=it.name}}</p>')({ name });\n  }`)), "ssti")).toHaveLength(0);
  });
});

describe("template engines (Express)", () => {
  const app = (line: string) => `const ejs = require('ejs');\nconst _ = require('lodash');\nconst express = require('express');\nconst app = express();\napp.get('/t', (req, res) => {\n  res.send(${line});\n});\n`;
  it("request data as the template source is flagged, as template data it is not", () => {
    expect(of(one("t.js", app(`ejs.render(req.query.tpl, {})`)), "ssti")).toHaveLength(1);
    expect(of(one("t.js", app(`_.template(req.body.t)({})`)), "ssti")).toHaveLength(1);
    expect(of(one("t.js", app(`ejs.render('<p><%= name %></p>', { name: req.query.n })`)), "ssti")).toHaveLength(0);
  });
});

describe("LLM output", () => {
  it("a completion over request messages carries their taint into a query", () => {
    const js = `const express = require('express');\nconst app = express();\napp.post('/chat', async (req, res) => {\n  const { messages } = req.body;\n  const response = await openai.chat.completions.create({ model: "m", messages: [...messages] });\n  const ai = response.choices[0].message.content;\n  await pool.query('INSERT INTO log (r) VALUES ("' + ai + '")');\n  res.json({});\n});\n`;
    const [h] = of(one("chat.js", js), "sql-injection");
    expect(h).toBeDefined();
    expect(lines(h)).toContain(5);
  });
  it("through a connection accessor (`db().exec(sql)`), with a parameterized twin", () => {
    const js = (q: string) => `import express from 'express';\nexport const r = express.Router();\nr.post('/finchat', async (req, res) => {\n  const { messages } = req.body;\n  const chatMessages = [{ role: "system", content: "x" }, ...messages];\n  const response = await openai.chat.completions.create({\n    model: "gpt",\n    messages: chatMessages,\n  });\n  const aiResponse = response.choices[0].message.content;\n  const userId = res.locals.user.id;\n  const stamp = new Date().toISOString();\n  ${q}\n  res.json({});\n});\n`;
    // three non-literal operands in the query: the trace must still pick the one that came from the completion
    const [h] = of(one("finchat.ts", js(`await db().exec('INSERT INTO t VALUES ("' + userId + '", "' + stamp + '", "' + aiResponse + '")');`)), "sql-injection");
    expect(h).toBeDefined();
    expect(lines(h)).toEqual(expect.arrayContaining([4, 5, 6, 10, 13]));   // destructured body, message array, the completion call, its answer, the query
    expect(of(one("finchat.ts", js(`await db().run('INSERT INTO t VALUES (?, ?, ?)', [userId, stamp, aiResponse]);`)), "sql-injection")).toHaveLength(0);
  });
  it("a long chain (spread message array, completion, answer, five-operand query) still traces back to the request", () => {
    const js = `import express from 'express';\nexport const r = express.Router();\nr.post('/finchat', async (req, res) => {\n    const { messages } = req.body;\n    const userId = res.locals.user.id;\n    const systemPrompt = \`You are a financial assistant\`\n    const chatMessages = [\n        {\n            role: "system",\n            content: systemPrompt,\n        },\n        ...messages,\n    ]\n    const response = await openai.chat.completions.create({\n        model: "gpt-3.5-turbo",\n        messages: chatMessages,\n    });\n    const aiResponse = response.choices[0].message.content;\n    const timestamp = new Date().toISOString();\n    const auditSQL = 'INSERT INTO t (a, b, c) VALUES ("' + userId + '", "' + timestamp + '", "' + aiResponse + '")';\n    await db().exec(auditSQL);\n    res.json({});\n});\n`;
    const [h] = of(one("backend/finchat.ts", js), "sql-injection");
    expect(h).toBeDefined();
    expect(lines(h)).toEqual(expect.arrayContaining([4, 7, 14, 18, 20, 21]));   // request body ... chat array, completion, answer, query, sink
  });
  it("a completion over constant messages does not", () => {
    const js = `const express = require('express');\nconst app = express();\napp.post('/chat', async (req, res) => {\n  const response = await openai.chat.completions.create({ model: "m", messages: [{ role: "user", content: "hi" }] });\n  const ai = response.choices[0].message.content;\n  await pool.query('INSERT INTO log (r) VALUES ("' + ai + '")');\n  res.json({});\n});\n`;
    expect(of(one("chat.js", js), "sql-injection")).toHaveLength(0);
  });
});

describe("handlers held in class fields + ORM mass assignment", () => {
  const svc = { path: "src/api/user/userService.ts", content: `export class UserService {\nasync saveUser(user: User): Promise<any> {\n  return db.update(usersTable).set(user);\n}\nasync rename(id: number, name: string) {\n  return db.update(usersTable).set({ name }).where(eq(usersTable.id, id));\n}\n}\nexport const userService = new UserService();\n` };
  const ctl = (body: string) => ({ path: "src/api/user/userController.ts", content: `import type { Request, RequestHandler, Response } from "express";\nimport { userService } from "./userService";\nclass UserController {\n  public save: RequestHandler = async (req: Request, res: Response) => {\n${body}\n    return res.json({});\n  };\n}\nexport const userController = new UserController();\n` });
  it("req.body written whole through an imported service from a class-field handler is mass assignment", () => {
    const [h] = of(scan([svc, ctl(`    const userObject = req.body;\n    await userService.saveUser(userObject);`)]), "mass-assignment");
    expect(h).toBeDefined();
    expect(h.trace.some(t => t.file.endsWith("userService.ts") && t.line === 3)).toBe(true);
    expect(lines(h)).toContain(5);
  });
  it("one named field written as a column is not", () => {
    expect(of(scan([svc, ctl(`    await userService.rename(1, req.body.name);`)]), "mass-assignment")).toHaveLength(0);
  });
  it("Drizzle .set / Prisma data: whole body flagged, an object literal of fields not", () => {
    const r = one("src/r.ts", `import express from 'express';\nconst app = express();\napp.post('/u', async (req, res) => {\n  await db.update(users).set(req.body);\n  await prisma.user.update({ where: { id: 1 }, data: req.body });\n  await prisma.user.update({ where: { id: 1 }, data: { name: req.body.name } });\n  await db.update(users).set({ name: req.body.name });\n  res.json({});\n});\n`);
    expect(of(r, "mass-assignment").map(h => h.line).sort()).toEqual([4, 5]);
  });
});

describe("HTTP parameter type confusion", () => {
  const ctl = (body: string, extra = "") => `import type { Request, RequestHandler, Response } from "express";\nclass C {\n  public h: RequestHandler = async (_req: Request, res: Response) => {\n${body}\n    return res.send("ok");\n  };\n}\n${extra}export const c = new C();\n`;
  it("a blocklist check by .includes in a helper, fed a query value, is flagged through the call", () => {
    const helper = `function sanitize(name: string): boolean {\n  const bad = ["<", ">"];\n  return !bad.some((b) => name.includes(b));\n}\n`;
    const [h] = of(one("c.ts", ctl(`    const userName = _req.query.name || "World";\n    if (!sanitize(userName)) return res.status(400).send("bad");`, helper)), "type-confusion");
    expect(h).toBeDefined();
    expect(lines(h)).toEqual(expect.arrayContaining([4, 5, 11]));   // source, call, sink in the helper
  });
  it("a typeof check first makes it safe", () => {
    expect(of(one("c.ts", ctl(`    const n = _req.query.name;\n    if (typeof n !== "string" || n.includes("<")) return res.send("bad");`)), "type-confusion")).toHaveLength(0);
  });
  it("a membership test that is not a blocklist check is not flagged", () => {
    expect(of(one("c.ts", ctl(`    const tags = _req.query.tags;\n    if (tags.includes("featured")) return res.send("f");`)), "type-confusion")).toHaveLength(0);
  });
  it("`req.query.x as string` is flagged; a browser value or a non-string cast is not", () => {
    expect(of(one("c.ts", ctl(`    const f: string = _req.query.filter as string || '';\n    await svc.find(f);`)), "type-confusion")).toHaveLength(1);
    expect(of(one("c.ts", ctl(`    const f = _req.query.filter as unknown;\n    await svc.find(f);`)), "type-confusion")).toHaveLength(0);
    expect(of(one("src/P.tsx", `export function P() {\n  const q = new URLSearchParams(location.search).get('q');\n  if (q && q.includes("<")) return null;\n  return <div>{q}</div>;\n}\n`), "type-confusion")).toHaveLength(0);
  });
});

describe("Flask-WTF populate_obj", () => {
  it("in a routed handler it is mass assignment through the model's lookup; outside a route it is not", () => {
    const py = `from flask import Blueprint\nuser = Blueprint('user', __name__)\n\n\n@user.route('/edit/<int:id>', methods=['GET', 'POST'])\ndef edit(id):\n    user = User.query.filter_by(id=id).first_or_404()\n    form = EditUserForm(obj=user)\n    if form.validate_on_submit():\n        form.populate_obj(user)\n    m = Mapper()\n    m.populate_obj(user)\n    return render_template('e.html', form=form)\n\ndef helper(u):\n    f = EditUserForm()\n    f.populate_obj(u)\n`;
    const hits = of(one("app/user/views.py", py), "mass-assignment");
    expect(hits.map(h => h.line)).toEqual([10]);
    expect(lines(hits[0])).toContain(7);
  });
});
