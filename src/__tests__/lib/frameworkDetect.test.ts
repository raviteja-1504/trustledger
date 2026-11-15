/**
 * Framework detection registry (taint/frameworks.ts): evidence from manifests, specific imports and convention files,
 * versions per manifest dialect, several frameworks in one repository, and the ambiguity rules (one weak signal never
 * counts; a similarly named package is not the framework; a commented-out import is not evidence).
 */
import { detectFrameworks, FRAMEWORKS, frameworkDef, type RepoFile } from "@/lib/taint/frameworks";

const f = (path: string, content: string): RepoFile => ({ path, content });
const ids = (files: RepoFile[]) => detectFrameworks(files).map(d => d.id);
const one = (files: RepoFile[], id: string) => detectFrameworks(files).find(d => d.id === id);

describe("registry shape", () => {
  it("has unique ids and every entry carries evidence it can actually match", () => {
    const seen = new Set<string>();
    for (const d of FRAMEWORKS) {
      expect(seen.has(d.id)).toBe(false);
      seen.add(d.id);
      expect((d.packages?.length ?? 0) + (d.imports?.length ?? 0) + (d.files?.length ?? 0) + (d.weak?.length ?? 0)).toBeGreaterThan(0);
      expect(d.langs.length).toBeGreaterThan(0);
    }
    expect(frameworkDef("spring-boot")?.langs).toEqual(["java", "kt"]);
  });
});

describe("versions by manifest dialect", () => {
  it.each<[string, string, RepoFile[], string, string, number]>([
    ["package.json", "express", [f("package.json", `{"dependencies":{"express":"^4.18.2","express-session":"^1.17.0"}}`)], "express", "4.18.2", 4],
    ["requirements.txt", "flask", [f("requirements.txt", `flask-cors==4.0.0\nFlask==2.3.2\n`)], "flask", "2.3.2", 2],
    ["pyproject", "django", [f("pyproject.toml", `[tool.poetry.dependencies]\ndjango = "^4.2.1"\n`)], "django", "4.2.1", 4],
    ["pom.xml", "spring boot", [f("pom.xml", `<parent><artifactId>spring-boot-starter-parent</artifactId><version>3.1.0</version></parent>`)], "spring-boot", "3.1.0", 3],
    ["gradle", "spring boot", [f("build.gradle", `implementation 'org.springframework.boot:spring-boot-starter-web:2.7.14'`)], "spring-boot", "2.7.14", 2],
    ["go.mod", "gin", [f("go.mod", `require github.com/gin-gonic/gin v1.9.1\n`)], "gin", "1.9.1", 1],
    ["Cargo.toml", "actix", [f("Cargo.toml", `[dependencies]\nactix-web = "4.3.1"\n`)], "actix-web", "4.3.1", 4],
    ["Cargo.toml table", "axum", [f("Cargo.toml", `axum = { version = "0.6.20", features = ["macros"] }\n`)], "axum", "0.6.20", 0],
    ["composer.json", "laravel", [f("composer.json", `{"require":{"laravel/framework":"^10.0"}}`)], "laravel", "10.0", 10],
    ["Gemfile", "rails", [f("Gemfile", `gem 'rails', '~> 7.0.4'\n`)], "rails", "7.0.4", 7],
    ["Gemfile.lock", "rails", [f("Gemfile.lock", `GEM\n  specs:\n    rails (6.1.7)\n`)], "rails", "6.1.7", 6],
    ["csproj", "entity framework", [f("App.csproj", `<PackageReference Include="Microsoft.EntityFrameworkCore" Version="7.0.5" />`)], "entity-framework", "7.0.5", 7],
  ])("%s: %s", (_d, _n, files, id, version, major) => {
    const d = one(files, id);
    expect(d?.version).toBe(version);
    expect(d?.major).toBe(major);
    expect(d?.confidence).toBe("medium");
    expect(d?.evidence[0]).toMatch(/^declared:/);
  });

  it("a declared package plus an import is high confidence", () => {
    const d = one([f("package.json", `{"dependencies":{"express":"4.17.1"}}`), f("src/app.js", `const express = require('express');\n`)], "express");
    expect(d?.confidence).toBe("high");
    expect(d?.evidence.map(e => e.split(":")[0]).sort()).toEqual(["declared", "import"]);
  });
});

describe("ambiguity", () => {
  it("a lone weak signal is not a framework", () => {
    expect(ids([f("main.go", `package main\nimport "net/http"\n`)])).not.toContain("net-http");
    expect(ids([f("a.js", `app.get('/x', (req, res) => res.send('ok'));\n`)])).not.toContain("express");
    expect(ids([f("A.java", `@Controller\nclass A {}\n`)])).not.toContain("spring-boot");
  });

  it("two different weak signals corroborate each other", () => {
    const d = one([f("main.go", `package main\nimport "net/http"\nfunc main() { http.ListenAndServe(":80", nil) }\n`)], "net-http");
    expect(d?.confidence).toBe("medium");
  });

  it("a package that merely contains the name is not the framework", () => {
    expect(ids([f("requirements.txt", `flask-cors==4.0.0\nflask_sqlalchemy_helpers==1\n`)])).not.toContain("flask");
    expect(ids([f("package.json", `{"dependencies":{"express-session":"1.0.0","next-auth":"4.0.0"}}`)])).not.toEqual(expect.arrayContaining(["express"]));
    expect(ids([f("package.json", `{"dependencies":{"express-session":"1.0.0","next-auth":"4.0.0"}}`)])).not.toContain("nextjs");
    expect(ids([f("app.py", `from flask_cors import CORS\n`)])).not.toContain("flask");
    expect(ids([f("app.py", `from app import views\nimport myflask\n`)])).not.toContain("flask");
  });

  it("an import inside a comment is not evidence", () => {
    expect(ids([f("a.js", `// const express = require('express');\n/* from 'koa' */\n`)])).toEqual([]);
    expect(ids([f("a.py", `# from flask import Flask\n`)])).toEqual([]);
  });

  it("a framework of another language is not claimed from the wrong files", () => {
    expect(ids([f("notes.txt", `from flask import Flask\nrequire('express')\n`)])).toEqual([]);
    expect(ids([f("a.py", `const express = require('express');\n`)])).not.toContain("express");
  });
});

describe("evidence kinds", () => {
  it("a specific import alone is enough (medium)", () => {
    const d = one([f("app.py", `from flask import Flask, request\n`)], "flask");
    expect(d?.confidence).toBe("medium");
    expect(d?.version).toBeNull();
  });

  it("a convention file counts", () => {
    expect(ids([f("artisan", `#!/usr/bin/env php\n`)])).toContain("laravel");
    expect(ids([f("config/routes.rb", `Rails.application.routes.draw do\nend\n`)])).toContain("rails");
    expect(ids([f("next.config.js", `module.exports = {}\n`)])).toContain("nextjs");
    expect(ids([f("manage.py", `os.environ.setdefault("DJANGO_SETTINGS_MODULE", "x")\n`)])).toContain("django");
    expect(ids([f("manage.py", `print("hi")\n`)])).not.toContain("django");
  });

  it("every language's imports are recognised", () => {
    const cases: Array<[string, RepoFile, string]> = [
      ["ktor", f("A.kt", `import io.ktor.server.application.*\n`), "ktor"],
      ["spring (kotlin)", f("A.kt", `import org.springframework.web.bind.annotation.*\n`), "spring-boot"],
      ["jax-rs", f("A.java", `import javax.ws.rs.GET;\n`), "jax-rs"],
      ["gin", f("a.go", `import "github.com/gin-gonic/gin"\n`), "gin"],
      ["asp.net", f("a.cs", `using Microsoft.AspNetCore.Mvc;\n`), "aspnetcore"],
      ["symfony", f("a.php", `<?php\nuse Symfony\\Component\\HttpFoundation\\Request;\n`), "symfony"],
      ["sinatra", f("a.rb", `require 'sinatra'\n`), "sinatra"],
      ["axum", f("a.rs", `use axum::{routing::get, Router};\n`), "axum"],
      ["drogon", f("a.cc", `#include <drogon/drogon.h>\n`), "drogon"],
      ["sqlite", f("a.c", `#include <sqlite3.h>\n`), "sqlite3"],
    ];
    for (const [, file, id] of cases) expect(ids([file])).toContain(id);
  });
});

describe("several frameworks in one repository", () => {
  it("reports each, with its own version, and keeps them apart", () => {
    const repo = [
      f("web/package.json", `{"dependencies":{"express":"^4.18.2","mongoose":"^7.0.0"}}`),
      f("web/src/server.js", `const express = require('express');\nconst mongoose = require('mongoose');\n`),
      f("api/requirements.txt", `Django==4.2.1\nrequests==2.31.0\n`),
      f("api/views.py", `from django.http import HttpResponse\nimport requests\n`),
      f("svc/go.mod", `require github.com/gin-gonic/gin v1.9.1\n`),
      f("svc/main.go", `import "github.com/gin-gonic/gin"\n`),
      f("jvm/pom.xml", `<artifactId>spring-boot-starter-parent</artifactId><version>3.1.0</version>`),
      f("jvm/src/A.java", `import org.springframework.web.bind.annotation.*;\n`),
    ];
    const got = new Map(detectFrameworks(repo).map(d => [d.id, d]));
    for (const id of ["express", "mongoose", "django", "requests", "gin", "spring-boot"]) expect(got.has(id)).toBe(true);
    expect(got.get("express")?.version).toBe("4.18.2");
    expect(got.get("django")?.version).toBe("4.2.1");
    expect(got.get("gin")?.version).toBe("1.9.1");
    expect(got.get("spring-boot")?.major).toBe(3);
    // none leaks into another ecosystem
    expect(got.has("flask")).toBe(false);
    expect(got.has("fastapi")).toBe(false);
    expect(got.has("koa")).toBe(false);
    // highest score first
    const scores = detectFrameworks(repo).map(d => d.score);
    expect([...scores].sort((a, b) => b - a)).toEqual(scores);
  });
});
