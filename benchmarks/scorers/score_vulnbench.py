"""VulnBench 2.0 scorer: TrustLedger findings against the reference set, using the benchmark's published matching rule
(https://vulnbench.com/releases/2.0 and docs/benchmark.md in https://github.com/snyk-labs/snyk-vulnbench).

  headline : type match + endpoint-localised match (+-2 lines): one reference location needs one reported location; two need
             both, or one at a labelled endpoint; more than two need a distinct reported location at a labelled source AND at
             a labelled sink. One finding and one reference vulnerability are consumed per match.
  lenient  : type match + ANY reference location within +-2 lines (a sensitivity check, never the headline).

This is an independent implementation of the published rule, not Snyk's harness, so a score here is not a leaderboard entry.

Usage: python score_vulnbench.py FIXTURES_DIR PROBE_OUT_DIR RESULT_JSON
  FIXTURES_DIR   the cloned snyk-vulnbench `fixtures` directory
  PROBE_OUT_DIR  per-fixture findings written by benchmarks/harness/vulnbench.test.ts.txt
"""
import json, glob, os, re, sys, collections
FIX, OUT, RESULT = sys.argv[1], sys.argv[2], sys.argv[3]
TOL = 2
RULE_TYPE = {'sql-injection': 'sql-injection', 'xss': 'xss', 'path-traversal': 'path-traversal', 'command-injection': 'command-injection',
             'eval-exec': 'code-injection', 'insecure-deserialization': 'insecure-deserialization', 'bola-missing-ownership-check': 'idor', 'idor': 'idor',
             'ssrf': 'ssrf', 'open-redirect': 'open-redirect', 'ssti': 'template-injection', 'mass-assignment': 'mass-assignment',
             'prototype-pollution': 'prototype-pollution', 'redos': 'redos', 'type-confusion': 'improper-type-validation'}
def norm(p): return p.replace(chr(92), '/').lstrip('./').lower()
def pmatch(a, b):
    a, b = norm(a), norm(b)
    return a == b or a.endswith('/' + b) or b.endswith('/' + a) or os.path.basename(a) == os.path.basename(b)
def lmatch(f, line, gf, gl): return pmatch(f, gf) and abs(line - gl) <= TOL

gts = []
for p in sorted(glob.glob(f'{FIX}/app-project-*/findings-attacker-reachable.json')):
    fx = os.path.basename(os.path.dirname(p))
    d = json.loads(re.sub(r'^\s*//.*$', '', open(p, encoding='utf-8').read(), flags=re.M))
    for v in d['vulnerabilities']: gts.append((fx, v))
findings = {}
for fx in set(f for f, _ in gts):
    q = f'{OUT}/{fx}.json'
    rs = json.load(open(q, encoding='utf-8'))['results'] if os.path.exists(q) else []
    fl = []
    for r in rs:
        t = RULE_TYPE.get(r['rule'])
        if not t: continue
        locs = [('sink', r['file'], r['line'])]
        if r.get('sink') and (r['sink']['file'], r['sink']['line']) != (r['file'], r['line']): locs.append(('sink', r['sink']['file'], r['sink']['line']))
        if r.get('source'): locs.append(('source', r['source']['file'], r['source']['line']))
        fl.append(dict(rule=r['rule'], type=t, file=r['file'], line=r['line'], locs=locs, detail=r['detail'], used=False, severity=r['severity'], category=r['category']))
    findings[fx] = fl

def official(gt, f):
    """returns an overlap score (>0) when finding f satisfies the endpoint rule for gt, else 0"""
    locs = gt['filesRelated']; n = len(locs)
    if f['type'] != gt['type']: return 0
    hit = lambda gl: [i for i, (role, file, line) in enumerate(f['locs']) if lmatch(file, line, gl['file'], gl['line'])]
    matched = [(gl, hit(gl)) for gl in locs]
    if n == 1: return 1 if matched[0][1] else 0
    srcs = [m for m in matched if m[0].get('type') == 'source']; snks = [m for m in matched if m[0].get('type') == 'sink']
    nm = sum(1 for m in matched if m[1])
    if n == 2:
        if all(m[1] for m in matched): return 2 + nm
        labeled = [m for m in matched if m[0].get('type') in ('source', 'sink')]
        return 1 + nm if any(m[1] for m in (labeled or matched)) else 0
    gsrc = [m for m in matched if m[0].get('type') == 'source']; gsnk = [m for m in matched if m[0].get('type') == 'sink']
    sidx = {i for m in gsrc for i in m[1]}; kidx = {i for m in gsnk for i in m[1]}
    # distinct reported locations must satisfy a source anchor AND a sink anchor
    ok = any(a != b for a in sidx for b in kidx)
    return 2 + nm if ok else 0
def lenient(gt, f):
    if f['type'] != gt['type']: return 0
    return sum(1 for gl in gt['filesRelated'] if any(lmatch(file, line, gl['file'], gl['line']) for _, file, line in f['locs']))

def assign(fn):
    res = {}
    for fx in findings: pass
    for fx in sorted(findings):
        fl = findings[fx]; used = set()
        cands = []
        for gi, (g_fx, gt) in enumerate(gts):
            if g_fx != fx: continue
            for fi, f in enumerate(fl):
                s = fn(gt, f)
                if s: cands.append((s, gi, fi))
        for s, gi, fi in sorted(cands, key=lambda x: -x[0]):
            if gi in res or fi in used: continue
            res[gi] = fl[fi]; used.add(fi)
    return res
off, len_ = assign(official), assign(lenient)
rows = []; by = collections.defaultdict(lambda: [0, 0, 0])
for gi, (fx, gt) in enumerate(gts):
    o, l = off.get(gi), len_.get(gi)
    b = by[gt['type']]; b[0] += 1; b[1] += bool(o); b[2] += bool(l)
    rows.append(dict(fixture=fx, id=gt['id'], type=gt['type'], severity=gt.get('severity'), locations=gt['filesRelated'], description=gt['description'][:300],
                     official=bool(o), lenient=bool(l), matchedBy=(dict(rule=(o or l)['rule'], file=(o or l)['file'], line=(o or l)['line'], detail=(o or l)['detail']) if (o or l) else None)))
tot = len(gts); no = sum(r['official'] for r in rows); nl = sum(r['lenient'] for r in rows)
nfind = sum(len(v) for v in findings.values()); 
print(f'reference vulnerabilities: {tot}  official-rule matched: {no} ({no/tot:.1%})  lenient (any location +-2): {nl} ({nl/tot:.1%})  reported findings of scored types: {nfind}')
print(f'{"type":28} {"total":>5} {"official":>8} {"lenient":>8}')
for t, (n, o, l) in sorted(by.items(), key=lambda kv: -kv[1][0]): print(f'{t:28} {n:5} {o:8} {l:8}')
json.dump(dict(total=tot, official=no, lenient=nl, byType={t: dict(total=a, official=b, lenient=c) for t, (a, b, c) in by.items()}, rows=rows, reportedFindings=nfind), open(RESULT, 'w'), indent=1)
