/**
 * Reachability-based dependency analysis: is a vulnerable package's code actually used by this repo, and is
 * that use reachable?
 *
 * A CVE in a declared dependency is only as urgent as the path to it. For each vulnerable package this finds,
 * in the scanned source files:
 *   - where it is IMPORTED (file:line), mapping the distribution name to what code imports
 *     (PyYAML -> yaml, beautifulsoup4 -> bs4, a Go module path -> its packages, a Maven groupId -> its Java
 *     packages, ...);
 *   - whether an importing file is REACHABLE -- an entry point (route/controller/handler/main), or reached
 *     from one through relative imports (JS/TS and Python, the languages whose imports name files);
 *   - when the advisory names the vulnerable functions (OSV `ecosystem_specific.imports[].symbols` for Go,
 *     `affects.functions` for Rust, `affected_functions`), whether any of them is CALLED from production code.
 *
 * Tiers, most to least urgent: called > reachable > imported > not-called > test-only > not-imported, and
 * unknown when no import mapping exists (OS packages from a base image). The answer is about the scanned
 * files only; "not-imported" says so rather than claiming the package is unused.
 */

export type DepReachabilityTier = "called" | "reachable" | "imported" | "not-called" | "test-only" | "not-imported" | "unknown";

export interface DepReachabilityEvidence { file: string; line: number; text: string; kind: "import" | "call" | "entry" }

export interface DepReachability {
  tier: DepReachabilityTier;
  /** One sentence a reader can act on. */
  summary: string;
  /** Import sites, the vulnerable call when one was found, and the entry point that reaches it. */
  evidence: DepReachabilityEvidence[];
  /** The advisory's vulnerable functions, when it names them. */
  vulnerableSymbols?: string[];
  /** Set for a transitive package: reachability is judged through the package that pulls it in. */
  via?: string;
}

/** Lower is more urgent; used to rank findings and to pick the strongest of several verdicts. */
export const REACHABILITY_RANK: Record<DepReachabilityTier, number> = {
  called: 0, reachable: 1, imported: 2, unknown: 3, "not-called": 4, "test-only": 5, "not-imported": 6,
};

export const REACHABILITY_LABEL: Record<DepReachabilityTier, string> = {
  called: "Vulnerable code called",
  reachable: "Reachable",
  imported: "Imported",
  "not-called": "Vulnerable code not called",
  "test-only": "Tests only",
  "not-imported": "Not imported",
  unknown: "Reachability unknown",
};

export interface SourceFile { file_path: string; content?: string | null }

type Family = "js" | "python" | "go" | "java" | "csharp" | "php" | "rust" | "ruby";

const FAMILY_OF_ECO: Record<string, Family | undefined> = {
  javascript: "js", typescript: "js", python: "python", go: "go", java: "java", csharp: "csharp", php: "php", rust: "rust", ruby: "ruby",
};

const EXT_FAMILY: Array<[RegExp, Family]> = [
  [/\.(?:[cm]?[jt]sx?)$/i, "js"], [/\.py$/i, "python"], [/\.go$/i, "go"], [/\.(?:java|kt)$/i, "java"],
  [/\.cs$/i, "csharp"], [/\.php$/i, "php"], [/\.rs$/i, "rust"], [/\.rb$/i, "ruby"],
];

function familyOfPath(p: string): Family | undefined {
  for (const [re, fam] of EXT_FAMILY) if (re.test(p)) return fam;
  return undefined;
}

// PyPI distributions whose import name differs from the distribution name.
const PY_IMPORT_NAMES: Record<string, string[]> = {
  pyyaml: ["yaml"], "beautifulsoup4": ["bs4"], pillow: ["PIL"], "scikit-learn": ["sklearn"], "scikit-image": ["skimage"],
  "python-dateutil": ["dateutil"], "opencv-python": ["cv2"], "opencv-python-headless": ["cv2"], "opencv-contrib-python": ["cv2"],
  protobuf: ["google.protobuf"], pyjwt: ["jwt"], "psycopg2-binary": ["psycopg2"], "python-jose": ["jose"], attrs: ["attr", "attrs"],
  pycryptodome: ["Crypto"], pycryptodomex: ["Cryptodome"], pycrypto: ["Crypto"], "pyopenssl": ["OpenSSL"], "python-multipart": ["multipart"],
  "djangorestframework": ["rest_framework"], "django-cors-headers": ["corsheaders"], "python-magic": ["magic"], "pymongo": ["pymongo", "bson", "gridfs"],
  "python-ldap": ["ldap"], "mysqlclient": ["MySQLdb"], "mysql-connector-python": ["mysql.connector"], "pyserial": ["serial"],
  "google-cloud-storage": ["google.cloud.storage"], "msgpack-python": ["msgpack"], "python-docx": ["docx"], "pyzmq": ["zmq"],
  "setuptools": ["setuptools", "pkg_resources"], "ruamel.yaml": ["ruamel.yaml"], "lxml": ["lxml"], "jinja2": ["jinja2"],
};

/** The module/package names code uses to import a distribution, in the given ecosystem. */
export function importNamesFor(pkg: string, ecosystem: string): string[] {
  const fam = FAMILY_OF_ECO[ecosystem];
  if (!fam) return [];
  switch (fam) {
    case "python": {
      const key = pkg.toLowerCase().replace(/_/g, "-");
      return PY_IMPORT_NAMES[key] ?? [pkg.replace(/-/g, "_").toLowerCase(), pkg.replace(/-/g, "_")].filter((v, i, a) => a.indexOf(v) === i);
    }
    case "java": {
      // groupId:artifactId -> Java packages usually start with the groupId (org.apache.logging.log4j:log4j-core).
      const [group] = pkg.split(":");
      return group ? [group] : [];
    }
    case "rust": return [pkg.replace(/-/g, "_")];
    case "php": {
      // vendor/package -> a PSR-4 namespace usually starts with the vendor (guzzlehttp/guzzle -> GuzzleHttp\).
      const vendor = pkg.split("/")[0] ?? "";
      return vendor ? [vendor.replace(/[-_]/g, "")] : [];
    }
    default: return [pkg];
  }
}

interface ImportSite {
  file: string; line: number; text: string;
  /** Names bound to the whole module: `import * as ns`, `import yaml`, a Go package name, `const _ = require()`. */
  namespaces: string[];
  /** Names bound to one exported symbol: imported name -> local name. */
  named: Map<string, string>;
}

const lineAt = (content: string, index: number) => content.slice(0, index).split("\n").length;
const lineText = (content: string, line: number) => (content.split("\n")[line - 1] ?? "").trim().slice(0, 160);
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

function namedList(list: string, sep: RegExp): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of list.split(",")) {
    const m = part.trim().match(sep);
    if (m && m[1]) out.set(m[1], m[2] ?? m[1]);
  }
  return out;
}

/** Every place `file` imports one of `names` (see importNamesFor). */
function importSites(file: SourceFile, fam: Family, names: readonly string[]): ImportSite[] {
  const content = file.content ?? "";
  const out: ImportSite[] = [];
  const push = (index: number, namespaces: string[], named = new Map<string, string>()) => {
    const line = lineAt(content, index);
    out.push({ file: file.file_path, line, text: lineText(content, line), namespaces, named });
  };
  for (const name of names) {
    const n = escapeRe(name);
    let m: RegExpExecArray | null;
    if (fam === "js") {
      const spec = `["'](${n})(?:/[^"']*)?["']`;
      // The clause never contains a quote or `;`, so a match can't start at an earlier import statement.
      const esm = new RegExp(`import\\s+(?:type\\s+)?([^;"'\`]*?)\\s+from\\s+${spec}`, "g");
      while ((m = esm.exec(content))) {
        const clause = m[1];
        const namespaces: string[] = [];
        const ns = clause.match(/\*\s+as\s+(\w+)/); if (ns) namespaces.push(ns[1]);
        const def = clause.match(/^\s*(\w+)\s*(?:,|$)/); if (def) namespaces.push(def[1]);
        const braces = clause.match(/\{([\s\S]*)\}/);
        push(m.index, namespaces, braces ? namedList(braces[1], /^(?:type\s+)?(\w+)(?:\s+as\s+(\w+))?$/) : new Map());
      }
      const bare = new RegExp(`import\\s+${spec}|import\\(\\s*${spec}\\s*\\)`, "g");
      while ((m = bare.exec(content))) push(m.index, []);
      const req = new RegExp(`(?:(?:const|let|var)\\s+(\\w+|\\{[^}]*\\})\\s*=\\s*)?require\\(\\s*${spec}\\s*\\)`, "g");
      while ((m = req.exec(content))) {
        const lhs = m[1] ?? "";
        if (lhs.startsWith("{")) push(m.index, [], namedList(lhs.slice(1, -1), /^(\w+)(?:\s*:\s*(\w+))?$/));
        else push(m.index, lhs ? [lhs] : []);
      }
    } else if (fam === "python") {
      const imp = new RegExp(`^[ \\t]*import\\s+(${n}(?:\\.[\\w.]+)?)(?:\\s+as\\s+(\\w+))?`, "gm");
      while ((m = imp.exec(content))) push(m.index, [m[2] ?? m[1]]);
      const from = new RegExp(`^[ \\t]*from\\s+${n}(?:\\.[\\w.]+)?\\s+import\\s+\\(?([^)\\n]+)`, "gm");
      while ((m = from.exec(content))) push(m.index, [], namedList(m[1], /^(\w+)(?:\s+as\s+(\w+))?$/));
    } else if (fam === "go") {
      // Only inside import declarations: `import "p"`, `import x "p"`, and `import ( ... )` blocks.
      const regions: Array<[number, number]> = [];
      const decl = /\bimport\s*\(([\s\S]*?)\)|\bimport\s+(?:[\w.]+\s+)?"[^"]*"/g;
      let d: RegExpExecArray | null;
      while ((d = decl.exec(content))) regions.push([d.index, d.index + d[0].length]);
      const imp = new RegExp(`(?:^|[\\s(])(?:(\\w+|\\.|_)\\s+)?"(${n}(?:/[^"]*)?)"`, "gm");
      while ((m = imp.exec(content))) {
        const at = m.index;
        if (!regions.some(([s, e]) => at >= s && at < e)) continue;
        const segs = m[2].split("/");
        const last = /^v\d+$/.test(segs[segs.length - 1]) && segs.length > 1 ? segs[segs.length - 2] : segs[segs.length - 1];
        const alias = m[1] && m[1] !== "import" && m[1] !== "_" && m[1] !== "." ? m[1] : null;
        // gopkg.in/yaml.v3 -> package yaml
        push(m.index + m[0].indexOf('"'), [alias ?? last.replace(/\.v\d+$/, "").replace(/^go-/, "").replace(/[^\w]/g, "_")]);
      }
    } else if (fam === "java") {
      const imp = new RegExp(`^[ \\t]*import\\s+(?:static\\s+)?(${n}(?:\\.[\\w*]+)*)\\s*;`, "gm");
      while ((m = imp.exec(content))) {
        const last = m[1].split(".").pop()!;
        push(m.index, [], last === "*" ? new Map() : new Map([[last, last]]));
      }
    } else if (fam === "csharp") {
      const imp = new RegExp(`^[ \\t]*using\\s+(?:static\\s+)?(?:\\w+\\s*=\\s*)?(${n}(?:\\.[\\w]+)*)\\s*;`, "gim");
      while ((m = imp.exec(content))) push(m.index, []);
    } else if (fam === "php") {
      const imp = new RegExp(`^[ \\t]*use\\s+\\\\?(${n}\\\\[\\w\\\\]+)(?:\\s+as\\s+(\\w+))?\\s*;`, "gim");
      while ((m = imp.exec(content))) {
        const last = m[1].split("\\").pop()!;
        push(m.index, [], new Map([[last, m[2] ?? last]]));
      }
    } else if (fam === "rust") {
      const imp = new RegExp(`\\b(?:use\\s+|extern\\s+crate\\s+)?${n}::|extern\\s+crate\\s+${n}\\b`, "g");
      while ((m = imp.exec(content))) { push(m.index, [name]); break; }
    } else if (fam === "ruby") {
      const imp = new RegExp(`^[ \\t]*require\\s+['"]${n}(?:/[^'"]*)?['"]`, "gm");
      while ((m = imp.exec(content))) push(m.index, []);
    }
  }
  // One site per line (a line can match two forms).
  const seen = new Set<number>();
  return out.filter(s => !seen.has(s.line) && (seen.add(s.line), true)).sort((a, b) => a.line - b.line);
}

const TEST_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|specs|testing|fixtures?|examples?|samples?|docs?|benchmarks?|e2e|cypress|mocks?|__mocks__)(?:\/|$)|(?:^|\/)test_[^/]*\.py$|_test\.(?:py|go)$|\.(?:test|spec)\.[cm]?[jt]sx?$|(?:Tests?|Spec)\.(?:java|kt|cs)$|(?:^|\/)conftest\.py$|Test\.php$/i;

export function isTestPath(p: string): boolean {
  return TEST_PATH_RE.test(p);
}

const ENTRY_PATH_RE = /(?:^|\/)(?:routes?|controllers?|handlers?|views|api|pages|app\/api|cmd|endpoints?|resources)\/|(?:^|\/)(?:server|app|main|index|manage|wsgi|asgi|urls|views|routes|program|startup)\.[a-z]+$|Controller\.(?:java|kt|cs|php)$|Handler\.(?:java|cs|go)$|(?:^|\/)route\.[jt]sx?$|(?:^|\/)page\.[jt]sx?$/i;
const ENTRY_CONTENT_RE = /\bexpress\(\)|\bapp\.listen\(|\b(?:app|router)\.(?:get|post|put|patch|delete|use)\(|@(?:Rest)?Controller\b|@(?:Get|Post|Put|Delete|Request)Mapping\b|\[(?:ApiController|Http(?:Get|Post|Put|Delete))\b|\bfunc\s+main\s*\(|\bhttp\.HandleFunc\(|@(?:app|bp|blueprint|router|api)\.(?:route|get|post|put|delete)\b|\bFastAPI\(|\bFlask\(__name__\)|\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|handler)\b|\bRoute::(?:get|post|put|delete)\(|\$_(?:GET|POST|REQUEST)\b|\bif\s+__name__\s*==\s*["']__main__["']/;

function isEntryFile(f: SourceFile): boolean {
  return !isTestPath(f.file_path) && (ENTRY_PATH_RE.test(f.file_path) || ENTRY_CONTENT_RE.test(f.content ?? ""));
}

const JS_EXTS = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", "/index.ts", "/index.tsx", "/index.js"];

function joinPath(dir: string, rel: string): string {
  const parts = dir ? dir.split("/") : [];
  for (const seg of rel.split("/")) {
    if (seg === "..") parts.pop();
    else if (seg && seg !== ".") parts.push(seg);
  }
  return parts.join("/");
}

/** Relative-import edges between batch files (importer -> imported), JS/TS and Python. */
function importGraph(files: readonly SourceFile[]): Map<string, string[]> {
  const byPath = new Set(files.map(f => f.file_path));
  const pyModules = files.filter(f => f.file_path.endsWith(".py"));
  const edges = new Map<string, string[]>();
  for (const f of files) {
    const content = f.content ?? "";
    const dir = f.file_path.includes("/") ? f.file_path.slice(0, f.file_path.lastIndexOf("/")) : "";
    const out = new Set<string>();
    if (familyOfPath(f.file_path) === "js") {
      const re = /(?:from\s+|require\(\s*|import\(\s*|import\s+)["'](\.{1,2}\/[^"']*)["']/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(content))) {
        const base = joinPath(dir, m[1].replace(/\.[cm]?js$/, ""));
        const hit = JS_EXTS.map(e => base + e).find(p => byPath.has(p));
        if (hit) out.add(hit);
      }
    } else if (f.file_path.endsWith(".py")) {
      const re = /^[ \t]*from\s+(\.*)([\w.]*)\s+import\s+([\w, ()]+)|^[ \t]*import\s+([\w.]+)/gm;
      let m: RegExpExecArray | null;
      while ((m = re.exec(content))) {
        const dots = m[1] ?? "";
        const mod = (m[2] ?? m[4] ?? "").replace(/\./g, "/");
        const targets: string[] = [];
        if (dots) {
          let base = dir;
          for (let i = 1; i < dots.length; i++) base = base.includes("/") ? base.slice(0, base.lastIndexOf("/")) : "";
          const stem = mod ? joinPath(base, mod) : base;
          targets.push(`${stem}.py`, `${stem}/__init__.py`);
          if (!mod && m[3]) for (const name of m[3].replace(/[()]/g, "").split(",")) targets.push(joinPath(stem, `${name.trim().split(/\s+/)[0]}.py`));
        } else if (mod) {
          for (const p of pyModules) if (p.file_path === `${mod}.py` || p.file_path.endsWith(`/${mod}.py`) || p.file_path.endsWith(`/${mod}/__init__.py`)) targets.push(p.file_path);
        }
        for (const t of targets) if (byPath.has(t) && t !== f.file_path) out.add(t);
      }
    }
    if (out.size) edges.set(f.file_path, [...out]);
  }
  return edges;
}

const reachMemo = new WeakMap<readonly SourceFile[], Map<string, string>>();

/** Files reachable from an entry point through relative imports, and the entry each was reached from.
 * Memoised per files array: one scan's packages all share it. */
export function reachableFiles(files: readonly SourceFile[]): Map<string, string> {
  const memo = reachMemo.get(files);
  if (memo) return memo;
  const from = computeReachable(files);
  reachMemo.set(files, from);
  return from;
}

function computeReachable(files: readonly SourceFile[]): Map<string, string> {
  const edges = importGraph(files);
  const from = new Map<string, string>();
  const queue: string[] = [];
  for (const f of files) if (isEntryFile(f)) { from.set(f.file_path, f.file_path); queue.push(f.file_path); }
  while (queue.length) {
    const p = queue.shift()!;
    for (const q of edges.get(p) ?? []) {
      if (from.has(q) || isTestPath(q)) continue;
      from.set(q, from.get(p)!);
      queue.push(q);
    }
  }
  return from;
}

/** The last name of a symbol path: `github.com/x/y.Parse` -> Parse, `Decoder.Decode` -> Decode, `a::b::f` -> f. */
function symbolTail(sym: string): string {
  const s = sym.replace(/\(.*$/, "");
  return s.split(/::|[./#]/).filter(Boolean).pop() ?? s;
}

/** A call of one of `symbols` in `file` through what it imported at `sites`. */
function findVulnerableCall(file: SourceFile, sites: readonly ImportSite[], symbols: readonly string[]): { line: number; text: string; symbol: string } | null {
  const content = file.content ?? "";
  const namespaces = [...new Set(sites.flatMap(s => s.namespaces))];
  const named = new Map<string, string>();
  for (const s of sites) for (const [k, v] of s.named) named.set(k, v);
  for (const sym of symbols) {
    const tail = symbolTail(sym);
    if (!/^\w+$/.test(tail)) continue;
    const patterns: RegExp[] = [];
    for (const ns of namespaces) patterns.push(new RegExp(`\\b${escapeRe(ns)}(?:\\.\\w+)*\\.${tail}\\s*\\(`));
    const local = named.get(tail);
    if (local) patterns.push(new RegExp(`(?<![\\w.])${escapeRe(local)}\\s*\\(`));
    // A method of a type the file imports (`Decoder.Decode`, `Environment.from_string`): `.tail(` on anything,
    // only when the type part of the symbol is itself imported or namespaced here.
    const owner = sym.replace(/\(.*$/, "").split(/::|[./#]/).filter(Boolean).slice(-2, -1)[0];
    if (owner && owner !== tail && (named.has(owner) || /^[A-Z]/.test(owner))) patterns.push(new RegExp(`\\.${tail}\\s*\\(`));
    for (const re of patterns) {
      const m = re.exec(content);
      if (m) { const line = lineAt(content, m.index); return { line, text: lineText(content, line), symbol: sym }; }
    }
  }
  return null;
}

/**
 * Reachability of `pkg` (an `ecosystem` package, see dependencyScan.ts's LangEcosystem) in `files` -- one scan's
 * source files. `symbols`: the advisory's vulnerable functions, when known.
 */
export function analyzeDependencyReachability(
  pkg: string, ecosystem: string, files: readonly SourceFile[], symbols: readonly string[] = [],
): DepReachability {
  const fam = FAMILY_OF_ECO[ecosystem];
  const names = importNamesFor(pkg, ecosystem);
  const vulnerableSymbols = symbols.length ? [...new Set(symbols)] : undefined;
  if (!fam || names.length === 0) {
    return { tier: "unknown", summary: "No source import maps to this package, so its use can't be traced in code.", evidence: [], vulnerableSymbols };
  }
  const sources = files.filter(f => f.content && familyOfPath(f.file_path) === fam);
  const sitesByFile = new Map<string, ImportSite[]>();
  for (const f of sources) {
    const s = importSites(f, fam, names);
    if (s.length) sitesByFile.set(f.file_path, s);
  }
  const importEvidence = (paths: string[]): DepReachabilityEvidence[] =>
    paths.flatMap(p => sitesByFile.get(p)!.slice(0, 1)).slice(0, 5).map(s => ({ file: s.file, line: s.line, text: s.text, kind: "import" as const }));

  if (sitesByFile.size === 0) {
    return { tier: "not-imported", summary: `No scanned source file imports ${names[0]}; if the scanned files cover the code base, the vulnerable code is never loaded.`, evidence: [], vulnerableSymbols };
  }
  const prodFiles = [...sitesByFile.keys()].filter(p => !isTestPath(p));
  if (prodFiles.length === 0) {
    const all = [...sitesByFile.keys()];
    return { tier: "test-only", summary: `Imported only by tests, fixtures or examples (${all.length} file${all.length === 1 ? "" : "s"}), not by application code.`, evidence: importEvidence(all), vulnerableSymbols };
  }

  const reach = reachableFiles(files);
  const byPath = new Map(sources.map(f => [f.file_path, f]));
  const reachableProd = prodFiles.filter(p => reach.has(p));

  if (vulnerableSymbols) {
    const ordered = [...reachableProd, ...prodFiles.filter(p => !reach.has(p))];
    for (const p of ordered) {
      const call = findVulnerableCall(byPath.get(p)!, sitesByFile.get(p)!, vulnerableSymbols);
      if (!call) continue;
      const entry = reach.get(p);
      const evidence: DepReachabilityEvidence[] = [
        { file: p, line: call.line, text: call.text, kind: "call" },
        ...importEvidence([p]),
        ...(entry && entry !== p ? [{ file: entry, line: 1, text: "entry point", kind: "entry" as const }] : []),
      ];
      return {
        tier: "called",
        summary: `${call.symbol} -- a function the advisory names as vulnerable -- is called at ${p}:${call.line}${entry ? entry === p ? ", in an entry point" : `, reachable from ${entry}` : ""}.`,
        evidence, vulnerableSymbols,
      };
    }
    return {
      tier: "not-called",
      summary: `Imported by application code, but none of the vulnerable functions the advisory names (${vulnerableSymbols.slice(0, 4).map(symbolTail).join(", ")}${vulnerableSymbols.length > 4 ? ", ..." : ""}) is called in the scanned files.`,
      evidence: importEvidence(prodFiles), vulnerableSymbols,
    };
  }

  if (reachableProd.length) {
    const p = reachableProd[0];
    const entry = reach.get(p)!;
    return {
      tier: "reachable",
      summary: entry === p ? `Imported by an entry point (${p}).` : `Imported by ${p}, which ${entry} reaches through its imports.`,
      evidence: [...importEvidence(reachableProd), ...(entry !== p ? [{ file: entry, line: 1, text: "entry point", kind: "entry" as const }] : [])],
    };
  }
  return {
    tier: "imported",
    summary: `Imported by application code (${prodFiles.length} file${prodFiles.length === 1 ? "" : "s"}), but no scanned entry point was traced to it.`,
    evidence: importEvidence(prodFiles),
  };
}
