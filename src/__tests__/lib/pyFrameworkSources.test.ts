/**
 * @jest-environment node
 *
 * Python frameworks: request sources and sinks of Flask, Django, FastAPI, Starlette, Tornado, Pyramid, Sanic, aiohttp, Falcon, Bottle,
 * SQLAlchemy, Jinja2 and Celery tasks. Each vulnerable case is traced from the framework's request to the dangerous call; the safe cases
 * (ORM filters, bound parameters, fixed URLs and paths, send_from_directory, static_file, constant templates) must stay quiet.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

jest.setTimeout(240_000);
beforeAll(async () => { await ensureTaintEngines(); }, 180_000);

// [name, code, expectation]: "VULN:<rule>" must be found; "SAFE" must have no injection / ssrf / path-traversal / redirect / xss / ssti / eval finding
const CASES: Array<[string, string, string]> = [
  // --- Flask
  ["flask args->os.system", `from flask import Flask, request\nimport os\napp = Flask(__name__)\n@app.route('/a')\ndef a():\n    os.system('ls ' + request.args.get('d'))\n    return 'ok'`, "VULN:command-injection"],
  ["flask form->subprocess shell", `from flask import request\nimport subprocess\ndef a():\n    subprocess.run('ls ' + request.form['d'], shell=True)\n    return 'ok'`, "VULN:command-injection"],
  ["flask json->cursor.execute", `from flask import request\ndef a(cursor):\n    cursor.execute("SELECT * FROM t WHERE n = '" + request.json['n'] + "'")\n    return 'ok'`, "VULN:sql-injection"],
  ["flask args->render_template_string", `from flask import request, render_template_string\ndef a():\n    return render_template_string('<h1>' + request.args.get('n') + '</h1>')`, "VULN:ssti"],
  ["flask args->eval", `from flask import request\ndef a():\n    return str(eval(request.args.get('x')))`, "VULN:eval-exec"],
  ["flask args->open", `from flask import request\ndef a():\n    return open('/data/' + request.args.get('f')).read()`, "VULN:path-traversal"],
  ["flask args->send_file", `from flask import request, send_file\ndef a():\n    return send_file('/data/' + request.args.get('f'))`, "VULN:path-traversal"],
  ["flask args->send_from_directory", `from flask import request, send_from_directory\ndef a():\n    return send_from_directory('/data', request.args.get('f'))`, "SAFE"],
  ["flask args->requests.get", `from flask import request\nimport requests\ndef a():\n    return requests.get(request.args.get('u')).text`, "VULN:ssrf"],
  ["flask args->httpx.get", `from flask import request\nimport httpx\ndef a():\n    return httpx.get(request.args.get('u')).text`, "VULN:ssrf"],
  ["flask args->urlopen", `from flask import request\nimport urllib.request\ndef a():\n    return urllib.request.urlopen(request.args.get('u')).read()`, "VULN:ssrf"],
  ["flask args->redirect", `from flask import request, redirect\ndef a():\n    return redirect(request.args.get('next'))`, "VULN:open-redirect"],
  ["flask args->Markup xss", `from flask import request, Markup\ndef a():\n    return Markup('<b>' + request.args.get('n') + '</b>')`, "VULN:xss"],
  // --- Django
  ["django GET->cursor.execute", `def a(request):\n    from django.db import connection\n    c = connection.cursor()\n    c.execute("SELECT * FROM t WHERE n = '" + request.GET['n'] + "'")\n    return None`, "VULN:sql-injection"],
  ["django POST->subprocess", `import subprocess\ndef a(request):\n    subprocess.call('ls ' + request.POST['d'], shell=True)`, "VULN:command-injection"],
  ["django GET->raw()", `def a(request):\n    return list(User.objects.raw("SELECT * FROM u WHERE n = '" + request.GET['n'] + "'"))`, "VULN:sql-injection"],
  ["django GET->HttpResponse xss", `from django.http import HttpResponse\ndef a(request):\n    return HttpResponse('<h1>' + request.GET['n'] + '</h1>')`, "VULN:xss"],
  ["django GET->mark_safe", `from django.utils.safestring import mark_safe\ndef a(request):\n    return mark_safe('<b>' + request.GET['n'] + '</b>')`, "VULN:xss"],
  ["django GET->redirect", `from django.shortcuts import redirect\ndef a(request):\n    return redirect(request.GET['next'])`, "VULN:open-redirect"],
  ["django GET->requests", `import requests\ndef a(request):\n    return requests.get(request.GET['u']).text`, "VULN:ssrf"],
  ["django ORM filter (safe)", `def a(request):\n    return list(User.objects.filter(name=request.GET['n']))`, "SAFE"],
  ["django parameterised execute (safe)", `def a(request, cursor):\n    cursor.execute("SELECT * FROM t WHERE n = %s", [request.GET['n']])`, "SAFE"],
  ["django GET->open", `def a(request):\n    return open('/data/' + request.GET['f']).read()`, "VULN:path-traversal"],
  // --- FastAPI / Starlette
  ["fastapi query param->os.system", `from fastapi import FastAPI\nimport os\napp = FastAPI()\n@app.get('/a')\ndef a(d: str):\n    os.system('ls ' + d)\n    return 'ok'`, "VULN:command-injection"],
  ["fastapi Query->cursor", `from fastapi import FastAPI, Query\napp = FastAPI()\n@app.get('/a')\ndef a(n: str = Query(...)):\n    cursor.execute("SELECT * FROM t WHERE n = '" + n + "'")\n    return 'ok'`, "VULN:sql-injection"],
  ["fastapi body model->ssrf", `from fastapi import FastAPI\nfrom pydantic import BaseModel\nimport httpx\napp = FastAPI()\nclass B(BaseModel):\n    url: str\n@app.post('/a')\nasync def a(b: B):\n    return httpx.get(b.url).text`, "VULN:ssrf"],
  ["fastapi path param->open", `from fastapi import FastAPI\napp = FastAPI()\n@app.get('/f/{name}')\ndef a(name: str):\n    return open('/data/' + name).read()`, "VULN:path-traversal"],
  ["fastapi RedirectResponse", `from fastapi import FastAPI\nfrom fastapi.responses import RedirectResponse\napp = FastAPI()\n@app.get('/a')\ndef a(next: str):\n    return RedirectResponse(next)`, "VULN:open-redirect"],
  ["fastapi HTMLResponse xss", `from fastapi import FastAPI\nfrom fastapi.responses import HTMLResponse\napp = FastAPI()\n@app.get('/a')\ndef a(n: str):\n    return HTMLResponse('<h1>' + n + '</h1>')`, "VULN:xss"],
  ["starlette query_params->exec", `async def a(request):\n    exec(request.query_params['c'])\n    return None`, "VULN:eval-exec"],
  ["starlette query_params->subprocess", `import subprocess\nasync def a(request):\n    subprocess.run('ls ' + request.query_params['d'], shell=True)`, "VULN:command-injection"],
  ["starlette await json->sql", `async def a(request):\n    b = await request.json()\n    cursor.execute("SELECT * FROM t WHERE n = '" + b['n'] + "'")`, "VULN:sql-injection"],
  // --- Tornado
  ["tornado get_argument->os.system", `import tornado.web, os\nclass H(tornado.web.RequestHandler):\n    def get(self):\n        os.system('ls ' + self.get_argument('d'))`, "VULN:command-injection"],
  ["tornado get_argument->sql", `import tornado.web\nclass H(tornado.web.RequestHandler):\n    def get(self):\n        cursor.execute("SELECT * FROM t WHERE n = '" + self.get_argument('n') + "'")`, "VULN:sql-injection"],
  ["tornado get_argument->redirect", `import tornado.web\nclass H(tornado.web.RequestHandler):\n    def get(self):\n        self.redirect(self.get_argument('next'))`, "VULN:open-redirect"],
  ["tornado get_argument->write xss", `import tornado.web\nclass H(tornado.web.RequestHandler):\n    def get(self):\n        self.write('<h1>' + self.get_argument('n') + '</h1>')`, "VULN:xss"],
  ["tornado request.body->ssrf", `import tornado.web, requests\nclass H(tornado.web.RequestHandler):\n    def post(self):\n        requests.get(self.request.body)`, "VULN:ssrf"],
  // --- Pyramid
  ["pyramid params->os.system", `from pyramid.view import view_config\nimport os\n@view_config(route_name='a')\ndef a(request):\n    os.system('ls ' + request.params['d'])`, "VULN:command-injection"],
  ["pyramid matchdict->open", `from pyramid.view import view_config\n@view_config(route_name='a')\ndef a(request):\n    return open('/data/' + request.matchdict['f']).read()`, "VULN:path-traversal"],
  ["pyramid GET->sql", `from pyramid.view import view_config\n@view_config(route_name='a')\ndef a(request):\n    cursor.execute("SELECT * FROM t WHERE n = '" + request.GET['n'] + "'")`, "VULN:sql-injection"],
  // --- Sanic
  ["sanic args->os.system", `from sanic import Sanic\nimport os\napp = Sanic('x')\n@app.get('/a')\nasync def a(request):\n    os.system('ls ' + request.args.get('d'))`, "VULN:command-injection"],
  ["sanic json->sql", `from sanic import Sanic\napp = Sanic('x')\n@app.post('/a')\nasync def a(request):\n    cursor.execute("SELECT * FROM t WHERE n = '" + request.json['n'] + "'")`, "VULN:sql-injection"],
  ["sanic query_args->ssrf", `from sanic import Sanic\nimport httpx\napp = Sanic('x')\n@app.get('/a')\nasync def a(request):\n    return httpx.get(request.args.get('u'))`, "VULN:ssrf"],
  // --- aiohttp
  ["aiohttp query->os.system", `from aiohttp import web\nimport os\nasync def a(request):\n    os.system('ls ' + request.query['d'])\n    return web.Response(text='ok')`, "VULN:command-injection"],
  ["aiohttp match_info->open", `from aiohttp import web\nasync def a(request):\n    return web.Response(text=open('/data/' + request.match_info['f']).read())`, "VULN:path-traversal"],
  ["aiohttp query->ClientSession ssrf", `from aiohttp import web, ClientSession\nasync def a(request):\n    async with ClientSession() as s:\n        r = await s.get(request.query['u'])\n    return web.Response(text='ok')`, "VULN:ssrf"],
  ["aiohttp query->web.Response xss", `from aiohttp import web\nasync def a(request):\n    return web.Response(text='<h1>' + request.query['n'] + '</h1>', content_type='text/html')`, "VULN:xss"],
  ["aiohttp HTTPFound redirect", `from aiohttp import web\nasync def a(request):\n    raise web.HTTPFound(request.query['next'])`, "VULN:open-redirect"],
  // --- Falcon
  ["falcon get_param->os.system", `import falcon, os\nclass R:\n    def on_get(self, req, resp):\n        os.system('ls ' + req.get_param('d'))`, "VULN:command-injection"],
  ["falcon media->sql", `import falcon\nclass R:\n    def on_post(self, req, resp):\n        b = req.media\n        cursor.execute("SELECT * FROM t WHERE n = '" + b['n'] + "'")`, "VULN:sql-injection"],
  ["falcon params->ssrf", `import falcon, requests\nclass R:\n    def on_get(self, req, resp):\n        requests.get(req.params['u'])`, "VULN:ssrf"],
  // --- Bottle
  ["bottle query->os.system", `from bottle import route, request\nimport os\n@route('/a')\ndef a():\n    os.system('ls ' + request.query.d)`, "VULN:command-injection"],
  ["bottle forms->sql", `from bottle import post, request\n@post('/a')\ndef a():\n    cursor.execute("SELECT * FROM t WHERE n = '" + request.forms.get('n') + "'")`, "VULN:sql-injection"],
  ["bottle query->static_file", `from bottle import route, request, static_file\n@route('/a')\ndef a():\n    return static_file(request.query.f, root='/data')`, "SAFE"],
  ["bottle query->redirect", `from bottle import route, request, redirect\n@route('/a')\ndef a():\n    redirect(request.query.next)`, "VULN:open-redirect"],
  // --- SQLAlchemy / Jinja2 / Celery
  ["sqlalchemy text() concat", `from sqlalchemy import text\ndef a(request, session):\n    return session.execute(text("SELECT * FROM t WHERE n = '" + request.args.get('n') + "'"))`, "VULN:sql-injection"],
  ["sqlalchemy text() bound (safe)", `from sqlalchemy import text\ndef a(request, session):\n    return session.execute(text("SELECT * FROM t WHERE n = :n"), {"n": request.args.get('n')})`, "SAFE"],
  ["sqlalchemy filter (safe)", `def a(request, session):\n    return session.query(User).filter(User.name == request.args.get('n')).all()`, "SAFE"],
  ["sqlalchemy execute fstring", `def a(request, engine):\n    engine.execute(f"SELECT * FROM t WHERE n = '{request.args.get('n')}'")`, "VULN:sql-injection"],
  ["jinja2 Template(user)", `from jinja2 import Template\nfrom flask import request\ndef a():\n    return Template(request.args.get('t')).render()`, "VULN:ssti"],
  ["jinja2 constant template (safe)", `from jinja2 import Template\ndef a():\n    return Template('Hello {{ name }}').render(name='x')`, "SAFE"],
  ["flask render_template (safe)", `from flask import request, render_template\ndef a():\n    return render_template('a.html', n=request.args.get('n'))`, "SAFE"],
  ["celery task arg->os.system", `from celery import Celery\nimport os\napp = Celery('x')\n@app.task\ndef run(cmd):\n    os.system(cmd)`, "VULN:command-injection"],
  ["celery task arg->ssrf", `from celery import shared_task\nimport requests\n@shared_task\ndef fetch(url):\n    return requests.get(url).text`, "VULN:ssrf"],
  // --- more
  ["flask path param->open", `from flask import Flask
app = Flask(__name__)
@app.route('/f/<name>')
def a(name):
    return open('/data/' + name).read()`, "VULN:path-traversal"],
  ["flask path param->sql", `from flask import Flask
app = Flask(__name__)
@app.route('/u/<name>')
def a(name):
    cursor.execute("SELECT * FROM t WHERE n = '" + name + "'")`, "VULN:sql-injection"],
  ["aiohttp session assigned->ssrf", `import aiohttp
async def a(request):
    session = aiohttp.ClientSession()
    return await session.get(request.query['u'])`, "VULN:ssrf"],
  ["requests.Session->ssrf", `import requests
from flask import request
def a():
    s = requests.Session()
    return s.get(request.args.get('u')).text`, "VULN:ssrf"],
  ["httpx client->ssrf", `import httpx
from flask import request
def a():
    with httpx.Client() as c:
        return c.get(request.args.get('u')).text`, "VULN:ssrf"],
  ["redis client.get (not http, safe)", `import redis, requests
from flask import request
r = redis.Redis()
def a():
    return r.get(request.args.get('k'))`, "SAFE"],
  ["tornado write without html concat (safe)", `import tornado.web
class H(tornado.web.RequestHandler):
    def get(self):
        self.write({'ok': True})`, "SAFE"],
  ["celery task fixed arg (safe)", `from celery import shared_task
import requests
@shared_task
def fetch():
    return requests.get('https://api.example.com/x').text`, "SAFE"],
  // --- safe controls
  ["requests fixed url (safe)", `import requests\ndef a():\n    return requests.get('https://api.example.com/x').text`, "SAFE"],
  ["open fixed path (safe)", `def a():\n    return open('/etc/app/config.json').read()`, "SAFE"],
];

const found = (idx: number, code: string) =>
  [...new Set(runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: `app/t${idx}.py`, content: code }] })
    .files[0].indicators.filter(i => i.line != null && /critical|high|medium/.test(i.severity)).map(i => i.id))];

describe("vulnerable code is found", () => {
  it.each(CASES.map((c, i) => [c[0], i, c[1], c[2]] as const).filter(c => c[3].startsWith("VULN:")))("%s", (_n, idx, code, expectation) => {
    expect(found(idx, code)).toContain(expectation.slice(5));
  });
});

describe("safe code stays quiet", () => {
  it.each(CASES.map((c, i) => [c[0], i, c[1], c[2]] as const).filter(c => c[3] === "SAFE"))("%s", (_n, idx, code) => {
    expect(found(idx, code).filter(i => /injection|ssrf|path-traversal|redirect|xss|ssti|eval/.test(i))).toEqual([]);
  });
});
