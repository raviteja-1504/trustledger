/**
 * Lockfile and manifest parsing (lib/lockfiles.ts): exact installed versions, direct vs transitive, dev.
 */
import {
  compareVersions, lockfileKind, parseCargoToml, parseGemfile, parseLockfile, parsePipfile, parsePyproject,
} from "@/lib/lockfiles";

const pkgs = (path: string, content: string) => parseLockfile(path, content)!.packages;

describe("npm lockfiles", () => {
  it("package-lock v2/v3: direct from the root, nested copies transitive with their parent, dev flagged", () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: {
      "": { dependencies: { lodash: "^4.17.0" }, devDependencies: { jest: "^29" } },
      "node_modules/lodash": { version: "4.17.21" },
      "node_modules/jest": { version: "29.7.0", dev: true },
      "node_modules/minimist": { version: "1.2.8", dev: true },
      "node_modules/old-lib/node_modules/lodash": { version: "4.17.15" },
      "node_modules/old-lib": { version: "1.0.0" },
      "node_modules/linked": { link: true, version: "0.0.1" },
    } });
    expect(pkgs("package-lock.json", lock)).toEqual(expect.arrayContaining([
      { name: "lodash", version: "4.17.21", direct: true, dev: false, parent: undefined },
      { name: "jest", version: "29.7.0", direct: true, dev: true, parent: undefined },
      { name: "minimist", version: "1.2.8", direct: false, dev: true, parent: undefined },
      { name: "lodash", version: "4.17.15", direct: false, dev: false, parent: "old-lib" },
    ]));
    expect(pkgs("package-lock.json", lock).some(p => p.name === "linked")).toBe(false);
  });

  it("package-lock v1: nested dependencies walk down with their parent", () => {
    const lock = JSON.stringify({ lockfileVersion: 1, dependencies: {
      express: { version: "4.17.1", dependencies: { qs: { version: "6.7.0" } } },
      mocha: { version: "10.0.0", dev: true },
    } });
    expect(pkgs("app/package-lock.json", lock)).toEqual([
      { name: "express", version: "4.17.1", direct: undefined, dev: false, parent: undefined },
      { name: "qs", version: "6.7.0", direct: false, dev: false, parent: "express" },
      { name: "mocha", version: "10.0.0", direct: undefined, dev: true, parent: undefined },
    ]);
  });

  it("yarn.lock, classic and Berry, scoped names included", () => {
    const classic = `# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.23.2"\n  resolved "x"\n\nlodash@^4.17.0:\n  version "4.17.21"\n`;
    expect(pkgs("yarn.lock", classic).map(p => `${p.name}@${p.version}`)).toEqual(["@babel/core@7.23.2", "lodash@4.17.21"]);
    const berry = `__metadata:\n  version: 6\n\n"lodash@npm:^4.17.0":\n  version: 4.17.20\n  resolution: "lodash@npm:4.17.20"\n\n"my-app@workspace:.":\n  version: 0.0.0-use.local\n`;
    expect(pkgs("yarn.lock", berry).map(p => `${p.name}@${p.version}`)).toEqual(["lodash@4.17.20"]);
  });

  it("pnpm-lock.yaml v5, v6 and v9 keys, peer suffixes stripped", () => {
    const lock = `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lodash:\n        version: 4.17.21\npackages:\n  lodash@4.17.21:\n    resolution: {integrity: x}\n  '@types/node@20.1.0':\n    resolution: {}\n  /express/4.18.2:\n    resolution: {}\n  /react-dom@18.2.0(react@18.2.0):\n    resolution: {}\nsnapshots:\n  lodash@4.17.21: {}\n`;
    expect(pkgs("pnpm-lock.yaml", lock).map(p => `${p.name}@${p.version}`).sort()).toEqual(["@types/node@20.1.0", "express@4.18.2", "lodash@4.17.21", "react-dom@18.2.0"]);
  });
});

describe("other ecosystems", () => {
  it("Pipfile.lock and poetry.lock (dev from develop / category / groups)", () => {
    expect(pkgs("Pipfile.lock", JSON.stringify({ default: { Requests: { version: "==2.31.0" } }, develop: { pytest: { version: "==8.0.0" } } })))
      .toEqual([{ name: "requests", version: "2.31.0", dev: false }, { name: "pytest", version: "8.0.0", dev: true }]);
    const poetry = `[[package]]\nname = "Django"\nversion = "4.2.1"\ncategory = "main"\n\n[[package]]\nname = "black"\nversion = "23.1.0"\ncategory = "dev"\n\n[[package]]\nname = "mypy"\nversion = "1.5.0"\ngroups = ["dev"]\n\n[metadata]\nlock-version = "2.0"\n`;
    expect(pkgs("poetry.lock", poetry)).toEqual([
      { name: "django", version: "4.2.1", dev: false }, { name: "black", version: "23.1.0", dev: true }, { name: "mypy", version: "1.5.0", dev: true },
    ]);
  });

  it("Cargo.lock, Gemfile.lock (direct from DEPENDENCIES), composer.lock", () => {
    expect(pkgs("Cargo.lock", `version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.190"\nsource = "x"\n\n[[package]]\nname = "my-app"\nversion = "0.1.0"\n`)
      .map(p => `${p.name}@${p.version}`)).toEqual(["serde@1.0.190", "my-app@0.1.0"]);
    const gem = `GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n    rails (7.1.0)\n      rack (>= 2.2.4)\n    nokogiri (1.15.4-x86_64-linux)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (~> 7.1)\n  nokogiri\n`;
    expect(pkgs("Gemfile.lock", gem)).toEqual([
      { name: "rack", version: "2.2.8", direct: false }, { name: "rails", version: "7.1.0", direct: true }, { name: "nokogiri", version: "1.15.4", direct: true },
    ]);
    expect(pkgs("composer.lock", JSON.stringify({ packages: [{ name: "guzzlehttp/guzzle", version: "v7.8.0" }], "packages-dev": [{ name: "phpunit/phpunit", version: "10.4.0" }] })))
      .toEqual([{ name: "guzzlehttp/guzzle", version: "7.8.0", dev: false }, { name: "phpunit/phpunit", version: "10.4.0", dev: true }]);
  });

  it("which files are lockfiles; garbage yields no packages, never a throw", () => {
    expect(lockfileKind("web/package-lock.json")).toBe("npm");
    expect(lockfileKind("Pipfile.lock")).toBe("python");
    expect(lockfileKind("package.json")).toBeNull();
    expect(pkgs("package-lock.json", "{not json")).toEqual([]);
    expect(parseLockfile("README.md", "x")).toBeNull();
  });

  it("duplicates merge: direct if any copy is, dev only if every copy is", () => {
    const lock = JSON.stringify({ packages: { "": { dependencies: { a: "1" } }, "node_modules/a": { version: "1.0.0", dev: true }, "node_modules/x/node_modules/a": { version: "1.0.0" } } });
    expect(pkgs("package-lock.json", lock).filter(p => p.name === "a")).toEqual([{ name: "a", version: "1.0.0", direct: true, dev: false, parent: "x" }]);
    // Same when the transitive copy comes first.
    const reversed = JSON.stringify({ packages: { "": { dependencies: { a: "1" } }, "node_modules/x/node_modules/a": { version: "1.0.0" }, "node_modules/a": { version: "1.0.0" } } });
    expect(pkgs("package-lock.json", reversed).find(p => p.name === "a")).toMatchObject({ direct: true, parent: "x" });
  });

  it("npm's devOptional counts as dev", () => {
    const lock = JSON.stringify({ packages: { "": {}, "node_modules/fsevents": { version: "2.3.3", devOptional: true } } });
    expect(pkgs("package-lock.json", lock)[0].dev).toBe(true);
  });
});

describe("manifests", () => {
  it("Cargo.toml: dependencies (plain, table and target-specific), dev and build deps as dev", () => {
    const toml = `[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies]\nserde = { version = "1.0", features = ["derive"] }\ntokio = "1.32" # runtime\n\n[dev-dependencies]\ncriterion = "0.5"\n\n[target.'cfg(unix)'.dependencies]\nlibc = "0.2"\n\n[build-dependencies]\ncc = "1.0"\n`;
    expect(parseCargoToml(toml)).toEqual([
      { name: "serde", version: "1.0", dev: false }, { name: "tokio", version: "1.32", dev: false }, { name: "libc", version: "0.2", dev: false },
      { name: "criterion", version: "0.5", dev: true }, { name: "cc", version: "1.0", dev: true },
    ]);
  });

  it("pyproject.toml: PEP 621 and Poetry (python itself skipped)", () => {
    const pep = `[project]\nname = "x"\ndependencies = [\n  "requests>=2.31",\n  "pydantic[email]==2.4.0 ; python_version > '3.8'",\n]\n`;
    expect(parsePyproject(pep)).toEqual([{ name: "requests", version: ">=2.31", dev: false }, { name: "pydantic", version: "==2.4.0", dev: false }]);
    const poetry = `[tool.poetry.dependencies]\npython = "^3.11"\nDjango = "^4.2"\n\n[tool.poetry.group.dev.dependencies]\npytest = "*"\n`;
    expect(parsePyproject(poetry)).toEqual([{ name: "django", version: "^4.2", dev: false }, { name: "pytest", version: "", dev: true }]);
  });

  it("Pipfile and Gemfile (groups mark dev)", () => {
    expect(parsePipfile(`[packages]\nflask = "==2.3.0"\nrequests = "*"\n\n[dev-packages]\nblack = "*"\n`)).toEqual([
      { name: "flask", version: "==2.3.0", dev: false }, { name: "requests", version: "", dev: false }, { name: "black", version: "", dev: true },
    ]);
    const gemfile = `source "https://rubygems.org"\ngem "rails", "~> 7.1"\ngem 'pg'\ngroup :development, :test do\n  gem "rspec-rails", "~> 6.0"\nend\ngem "puma", group: :development\n`;
    expect(parseGemfile(gemfile)).toEqual([
      { name: "rails", version: "~> 7.1", dev: false }, { name: "pg", version: "", dev: false },
      { name: "rspec-rails", version: "~> 6.0", dev: true }, { name: "puma", version: "", dev: true },
    ]);
  });
});

describe("compareVersions", () => {
  it("numeric parts, v prefixes, pre-releases before the release", () => {
    expect(compareVersions("1.10.0", "1.9.9")).toBe(1);
    expect(compareVersions("v2.0", "2.0.0")).toBe(0);
    expect(compareVersions("1.2.3-beta.1", "1.2.3")).toBe(-1);
    expect(compareVersions("1.2.3", "1.2.3-rc1")).toBe(1);
    expect(compareVersions("4.17.15", "4.17.21")).toBe(-1);
    expect(compareVersions("3.1.5-r0", "3.1.5-r1")).toBe(-1);
  });
});
