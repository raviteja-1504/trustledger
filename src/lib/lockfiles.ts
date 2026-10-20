/**
 * Lockfiles and the manifests depAnalysis.ts didn't cover -- what the dependency scanner reads to know the EXACT
 * version installed (a manifest's "^4.17.0" only says "4.17.0 or later"), and the packages that come in
 * transitively. Pure, dependency-free text parsing; anything unparseable yields [] rather than throwing.
 *
 * Lockfiles: package-lock.json (v1, v2, v3), yarn.lock (classic and Berry), pnpm-lock.yaml (v5-v9),
 * Pipfile.lock, poetry.lock, Cargo.lock, Gemfile.lock, composer.lock.
 * Manifests: Cargo.toml, Gemfile, pyproject.toml (PEP 621 and Poetry), Pipfile.
 */

export type LockEcosystem = "npm" | "python" | "rust" | "ruby" | "php";

export interface LockedPackage {
  name: string;
  version: string;
  /** Declared by the project itself (true), pulled in by another package (false), or unknown (undefined). */
  direct?: boolean;
  dev?: boolean;
  /** For a transitive package, the package that depends on it, when the lockfile says. */
  parent?: string;
}

export interface Lockfile { ecosystem: LockEcosystem; packages: LockedPackage[] }

export interface DeclaredRef { name: string; version: string; dev: boolean }

const base = (p: string) => p.split("/").pop()!.toLowerCase();

/** Which lockfile a path is, if any. */
export function lockfileKind(path: string): LockEcosystem | null {
  const b = base(path);
  if (b === "package-lock.json" || b === "npm-shrinkwrap.json" || b === "yarn.lock" || b === "pnpm-lock.yaml") return "npm";
  if (b === "pipfile.lock" || b === "poetry.lock") return "python";
  if (b === "cargo.lock") return "rust";
  if (b === "gemfile.lock") return "ruby";
  if (b === "composer.lock") return "php";
  return null;
}

export function parseLockfile(path: string, content: string): Lockfile | null {
  const b = base(path), eco = lockfileKind(path);
  if (!eco) return null;
  try {
    const packages =
      b === "package-lock.json" || b === "npm-shrinkwrap.json" ? parsePackageLock(content)
      : b === "yarn.lock" ? parseYarnLock(content)
      : b === "pnpm-lock.yaml" ? parsePnpmLock(content)
      : b === "pipfile.lock" ? parsePipfileLock(content)
      : b === "poetry.lock" ? parseTomlPackages(content, true)
      : b === "cargo.lock" ? parseTomlPackages(content, false)
      : b === "gemfile.lock" ? parseGemfileLock(content)
      : parseComposerLock(content);
    return { ecosystem: eco, packages: dedupe(packages) };
  } catch { return { ecosystem: eco, packages: [] }; }
}

/** One entry per name@version. Merged: direct if any copy is direct; dev only if every copy is dev. */
function dedupe(ps: LockedPackage[]): LockedPackage[] {
  const seen = new Map<string, LockedPackage>();
  for (const p of ps) {
    if (!p.name || !p.version) continue;
    const k = `${p.name}@${p.version}`;
    const cur = seen.get(k);
    if (!cur) { seen.set(k, { ...p }); continue; }
    cur.direct = cur.direct || p.direct;
    cur.dev = !!cur.dev && !!p.dev;
    cur.parent ??= p.parent;
  }
  return [...seen.values()];
}

// ── npm ───────────────────────────────────────────────────────────────────────

interface LockV2Entry { version?: string; dev?: boolean; devOptional?: boolean; link?: boolean; dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
interface LockV1Entry { version?: string; dev?: boolean; dependencies?: Record<string, LockV1Entry> }

export function parsePackageLock(content: string): LockedPackage[] {
  const j = JSON.parse(content) as { packages?: Record<string, LockV2Entry>; dependencies?: Record<string, LockV1Entry> };
  const out: LockedPackage[] = [];
  if (j.packages && Object.keys(j.packages).length > 0) {
    const root = j.packages[""] ?? {};
    const directs = new Set([...Object.keys(root.dependencies ?? {}), ...Object.keys(root.devDependencies ?? {})]);
    for (const [key, e] of Object.entries(j.packages)) {
      if (!key || e.link || !e.version) continue;
      const parts = key.split("node_modules/").filter(Boolean).map(s => s.replace(/\/$/, ""));
      const name = parts[parts.length - 1];
      const nested = parts.length > 1;
      out.push({ name, version: e.version, direct: !nested && directs.has(name), dev: !!(e.dev || e.devOptional), parent: nested ? parts[parts.length - 2] : undefined });
    }
    return out;
  }
  const walk = (deps: Record<string, LockV1Entry>, parent?: string) => {
    for (const [name, e] of Object.entries(deps)) {
      if (e.version && !e.version.startsWith("file:")) out.push({ name, version: e.version, direct: parent === undefined ? undefined : false, dev: !!e.dev, parent });
      if (e.dependencies) walk(e.dependencies, name);
    }
  };
  walk(j.dependencies ?? {});
  return out;
}

/** yarn.lock: classic (`"pkg@^1.0.0", pkg@~1.2:` + `  version "1.2.3"`) and Berry (`"pkg@npm:^1.0.0":` + `  version: 1.2.3`). */
export function parseYarnLock(content: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  const blocks = content.replace(/\r\n/g, "\n").split(/\n(?=[^\s#])/);
  for (const block of blocks) {
    const [head, ...rest] = block.split("\n");
    if (!head || head.startsWith("__metadata") || !head.trimEnd().endsWith(":")) continue;
    const firstSpec = head.replace(/:$/, "").split(",")[0].trim().replace(/^"|"$/g, "");
    const at = firstSpec.lastIndexOf("@");
    if (at <= 0) continue;
    const name = firstSpec.slice(0, at);
    const vLine = rest.find(l => /^\s+version:?\s/.test(l));
    const version = vLine?.replace(/^\s+version:?\s+/, "").trim().replace(/^"|"$/g, "");
    if (!version || /^0\.0\.0-use\.local$/.test(version)) continue;
    out.push({ name, version });
  }
  return out;
}

/** pnpm-lock.yaml `packages:` keys: v5 `/name/1.2.3`, v6 `/name@1.2.3`, v9 `name@1.2.3` (peer suffixes stripped). */
export function parsePnpmLock(content: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  let inPackages = false;
  for (const line of lines) {
    if (/^\S/.test(line)) { inPackages = /^(packages|snapshots):\s*$/.test(line); continue; }
    if (!inPackages) continue;
    const m = /^ {2}['"]?([^\s'"][^'"]*?)['"]?:\s*$/.exec(line);
    if (!m) continue;
    const key = m[1].replace(/^\//, "").replace(/\(.*$/, "").replace(/_.*$/, "");
    let name: string, version: string;
    const at = key.lastIndexOf("@");
    if (at > 0) { name = key.slice(0, at); version = key.slice(at + 1); }
    else { const i = key.lastIndexOf("/"); if (i <= 0) continue; name = key.slice(0, i); version = key.slice(i + 1); }
    if (/^\d/.test(version)) out.push({ name, version });
  }
  return out;
}

// ── Python ────────────────────────────────────────────────────────────────────

export function parsePipfileLock(content: string): LockedPackage[] {
  const j = JSON.parse(content) as { default?: Record<string, { version?: string }>; develop?: Record<string, { version?: string }> };
  const take = (o: Record<string, { version?: string }> | undefined, dev: boolean) =>
    Object.entries(o ?? {}).flatMap(([name, e]) => (e.version ? [{ name: name.toLowerCase(), version: e.version.replace(/^==/, ""), dev }] : []));
  return [...take(j.default, false), ...take(j.develop, true)];
}

/** `[[package]]` tables with name / version (poetry.lock, Cargo.lock); poetry's category/groups mark dev. */
export function parseTomlPackages(content: string, poetry: boolean): LockedPackage[] {
  const out: LockedPackage[] = [];
  for (const block of content.replace(/\r\n/g, "\n").split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const body = block.split(/^\[(?!\[package)/m)[0];
    const name = /^name\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    if (!name || !version) continue;
    const category = /^category\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    const groups = /^groups\s*=\s*\[([^\]]*)\]/m.exec(body)?.[1];
    const dev = poetry ? (category === "dev" || (!!groups && !/"main"/.test(groups))) : false;
    out.push({ name: poetry ? name.toLowerCase() : name, version, dev });
  }
  return out;
}

// ── Ruby / PHP ────────────────────────────────────────────────────────────────

/** Gemfile.lock: gems under `specs:` are `    name (1.2.3)` (direct deps are listed again under DEPENDENCIES). */
export function parseGemfileLock(content: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  const direct = new Set<string>();
  let section = "";
  for (const line of lines) {
    if (/^[A-Z]/.test(line)) { section = line.trim(); continue; }
    if (section === "DEPENDENCIES") { const m = /^ {2}([^\s!(]+)/.exec(line); if (m) direct.add(m[1]); continue; }
    const m = /^ {4}([^\s(]+) \(([^)]+)\)\s*$/.exec(line);
    if (m && (section === "GEM" || section === "GIT" || section === "PATH")) out.push({ name: m[1], version: m[2].split("-")[0] });
  }
  return out.map(p => ({ ...p, direct: direct.size ? direct.has(p.name) : undefined }));
}

export function parseComposerLock(content: string): LockedPackage[] {
  const j = JSON.parse(content) as { packages?: Array<{ name?: string; version?: string }>; "packages-dev"?: Array<{ name?: string; version?: string }> };
  const take = (a: Array<{ name?: string; version?: string }> | undefined, dev: boolean) =>
    (a ?? []).flatMap(p => (p.name && p.version ? [{ name: p.name, version: p.version.replace(/^v/, ""), dev }] : []));
  return [...take(j.packages, false), ...take(j["packages-dev"], true)];
}

// ── Manifests not covered by depAnalysis.ts ───────────────────────────────────

/** A TOML table's `key = "1.2"` / `key = { version = "1.2" }` lines. */
function tomlTable(content: string, header: RegExp): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  let inside = false;
  for (const raw of lines) {
    const line = raw.replace(/\s+#.*$/, "");
    if (/^\s*\[/.test(line)) { inside = header.test(line.trim()); continue; }
    if (!inside) continue;
    const m = /^\s*["']?([A-Za-z0-9_.\-]+)["']?\s*=\s*(.+)$/.exec(line);
    if (!m) continue;
    const v = m[2].trim();
    const ver = v.startsWith("{") ? /version\s*=\s*["']([^"']+)["']/.exec(v)?.[1] ?? "" : v.replace(/^["']|["']$/g, "");
    out.push([m[1], ver]);
  }
  return out;
}

export function parseCargoToml(content: string): DeclaredRef[] {
  return [
    ...tomlTable(content, /^\[(?:target\.[^\]]+\.)?dependencies\]$/).map(([name, version]) => ({ name, version, dev: false })),
    ...tomlTable(content, /^\[(?:target\.[^\]]+\.)?(?:dev|build)-dependencies\]$/).map(([name, version]) => ({ name, version, dev: true })),
  ];
}

export function parsePipfile(content: string): DeclaredRef[] {
  const fix = (v: string) => (v === "*" ? "" : v);
  return [
    ...tomlTable(content, /^\[packages\]$/).map(([name, version]) => ({ name: name.toLowerCase(), version: fix(version), dev: false })),
    ...tomlTable(content, /^\[dev-packages\]$/).map(([name, version]) => ({ name: name.toLowerCase(), version: fix(version), dev: true })),
  ];
}

/** pyproject.toml: PEP 621 `dependencies = [...]` / optional groups, and Poetry's dependency tables. */
export function parsePyproject(content: string): DeclaredRef[] {
  const out: DeclaredRef[] = [];
  const text = content.replace(/\r\n/g, "\n");
  const spec = (s: string, dev: boolean) => {
    const m = /^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(.*)$/.exec(s);
    if (m) out.push({ name: m[1].toLowerCase(), version: m[2].split(";")[0].trim(), dev });
  };
  // PEP 621: the quoted strings of `dependencies = [ ... ]` in [project]. Scanned, not regex-matched: a
  // requirement can itself contain "]" (pkg[extra]) or the other kind of quote (a marker's '3.8').
  const proj = /^\[project\]\s*$/m.exec(text);
  const dep = proj ? /^dependencies\s*=\s*\[/m.exec(text.slice(proj.index)) : null;
  if (proj && dep) {
    let i = proj.index + dep.index + dep[0].length;
    while (i < text.length && text[i] !== "]") {
      const q = text[i];
      if (q === '"' || q === "'") {
        const end = text.indexOf(q, i + 1);
        if (end < 0) break;
        spec(text.slice(i + 1, end), false);
        i = end + 1;
      } else if (q === "#") { const nl = text.indexOf("\n", i); i = nl < 0 ? text.length : nl; }
      else i++;
    }
  }
  for (const [name, version] of tomlTable(text, /^\[tool\.poetry\.dependencies\]$/)) if (name.toLowerCase() !== "python") out.push({ name: name.toLowerCase(), version: version === "*" ? "" : version, dev: false });
  for (const [name, version] of tomlTable(text, /^\[tool\.poetry\.(?:dev-dependencies|group\.[^\]]+\.dependencies)\]$/)) out.push({ name: name.toLowerCase(), version: version === "*" ? "" : version, dev: true });
  return out;
}

/** Gemfile: `gem "name", "~> 1.2"`; gems inside a :development / :test group are dev. */
export function parseGemfile(content: string): DeclaredRef[] {
  const out: DeclaredRef[] = [];
  let devDepth = 0, depth = 0;
  for (const raw of content.replace(/\r\n/g, "\n").split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (/^group\b.*\bdo\s*$/.test(line)) { depth++; if (/:development|:test/.test(line)) devDepth = depth; continue; }
    if (/^end\b/.test(line)) { if (devDepth === depth) devDepth = 0; depth = Math.max(0, depth - 1); continue; }
    const m = /^gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/.exec(line);
    if (m) out.push({ name: m[1], version: m[2] ?? "", dev: devDepth > 0 || /group:\s*\[?:?(?:development|test)/.test(line) });
  }
  return out;
}

// ── Versions ──────────────────────────────────────────────────────────────────

/** Compare dotted versions numerically (1.10 > 1.9); pre-release tails sort before the release. */
export function compareVersions(a: string, b: string): number {
  const norm = (v: string) => v.trim().replace(/^v/i, "").split(/[+]/)[0];
  const [ma, pa = ""] = norm(a).split("-", 2), [mb, pb = ""] = norm(b).split("-", 2);
  const xa = ma.split("."), xb = mb.split(".");
  for (let i = 0; i < Math.max(xa.length, xb.length); i++) {
    const na = parseInt(xa[i] ?? "0", 10), nb = parseInt(xb[i] ?? "0", 10);
    if (Number.isNaN(na) || Number.isNaN(nb)) { const c = (xa[i] ?? "").localeCompare(xb[i] ?? ""); if (c) return c; continue; }
    if (na !== nb) return na < nb ? -1 : 1;
  }
  if (pa && !pb) return -1;
  if (!pa && pb) return 1;
  return pa.localeCompare(pb);
}
