/**
 * Framework detection registry.
 *
 * Which frameworks / ORMs / HTTP clients / template engines a repository uses, found from FOUR independent kinds of
 * evidence, never from one ambiguous import:
 *   - declared    the package is listed in a manifest (package.json, requirements.txt, pom.xml, go.mod, Cargo.toml ...)
 *   - import      a package-specific import / `use` / `using` / `#include` in source (`from flask import`, not `from app import`)
 *   - file        a convention file the framework requires (`artisan`, `config/routes.rb`, `next.config.js`)
 *   - weak        a usage shape or a generic import that many libraries share (`net/http`, `@Controller(`, `app.get(`)
 *
 * A framework is reported when its evidence scores >= 2 (declared 3, import 2, file 2, each distinct weak signal 1,
 * at most 2 counted), so a lone weak signal never counts; confidence is "high" from 4. Several frameworks (and several
 * languages) can be reported for one repository, each with the version its manifest declares when there is one.
 *
 * This module only DETECTS. The sources, sinks, propagators and sanitizers that apply once a framework is known live in
 * taint/models/* and taint/sanitizers.ts, which the language engines already read; the coverage report
 * (frameworkCoverageReport.test.ts) says which detected frameworks have a passing vulnerable + safe test.
 * Client-safe: no imports.
 */

export type FwLang = "js" | "py" | "java" | "kt" | "go" | "cs" | "php" | "rb" | "rs" | "cpp";
export type FwKind = "web" | "orm" | "http-client" | "template" | "http-server" | "database" | "queue" | "other";

export interface FrameworkDef {
  id: string;
  name: string;
  /** The languages whose source files can use it (Spring Boot: java and kt). */
  langs: readonly FwLang[];
  kind: FwKind;
  /** Package names as the manifests spell them. Matched whole (`flask` never matches `flask-cors`). */
  packages?: readonly string[];
  /** Package-specific imports: one of these alone is reliable evidence. */
  imports?: readonly RegExp[];
  /** Shapes that several libraries share, or generic imports: only evidence in pairs. */
  weak?: readonly RegExp[];
  /** Convention files (path and, optionally, content). */
  files?: readonly { path: RegExp; content?: RegExp }[];
  /** Words the coverage report looks for in test-case names. */
  keywords?: readonly string[];
}

export interface DetectedFramework {
  id: string;
  name: string;
  langs: readonly FwLang[];
  kind: FwKind;
  /** The version the manifest declares (`^4.18.2` -> `4.18.2`), or null. */
  version: string | null;
  major: number | null;
  confidence: "high" | "medium";
  score: number;
  /** Where each signal was seen, e.g. `declared: package.json`, `import: src/app.js`. */
  evidence: string[];
}

export interface RepoFile { path: string; content: string }

const R = (s: string, f = "") => new RegExp(s, f);

export const FRAMEWORKS: readonly FrameworkDef[] = [
  // ── JavaScript / TypeScript ──
  { id: "express", name: "Express", langs: ["js"], kind: "web", packages: ["express"], imports: [R(String.raw`require\(\s*['"]express['"]\s*\)|from\s+['"]express['"]`)], weak: [R(String.raw`\bexpress\s*\(\s*\)`), R(String.raw`\b(?:app|router)\.(?:get|post|put|delete|use)\s*\(\s*['"]\/`)] },
  { id: "koa", name: "Koa", langs: ["js"], kind: "web", packages: ["koa", "koa-router", "@koa/router"], imports: [R(String.raw`require\(\s*['"]koa['"]\s*\)|from\s+['"]koa['"]`)], weak: [R(String.raw`\bctx\.(?:request|query|body)\b`)] },
  { id: "fastify", name: "Fastify", langs: ["js"], kind: "web", packages: ["fastify"], imports: [R(String.raw`require\(\s*['"]fastify['"]\s*\)|from\s+['"]fastify['"]`)] },
  { id: "nestjs", name: "NestJS", langs: ["js"], kind: "web", packages: ["@nestjs/core", "@nestjs/common"], imports: [R(String.raw`from\s+['"]@nestjs\/(?:common|core)['"]`)], weak: [R(String.raw`@(?:Controller|Injectable|Module)\s*\(`)], files: [{ path: /(?:^|\/)nest-cli\.json$/ }] },
  { id: "nextjs", name: "Next.js", langs: ["js"], kind: "web", packages: ["next"], imports: [R(String.raw`from\s+['"]next(?:\/[\w-]+)*['"]`)], files: [{ path: /(?:^|\/)next\.config\.(?:js|mjs|ts)$/ }] },
  { id: "hapi", name: "hapi", langs: ["js"], kind: "web", packages: ["@hapi/hapi", "hapi"], imports: [R(String.raw`require\(\s*['"](?:@hapi\/)?hapi['"]\s*\)|from\s+['"](?:@hapi\/)?hapi['"]`)] },
  { id: "sequelize", name: "Sequelize", langs: ["js"], kind: "orm", packages: ["sequelize"], imports: [R(String.raw`require\(\s*['"]sequelize['"]\s*\)|from\s+['"]sequelize['"]`)] },
  { id: "mongoose", name: "Mongoose", langs: ["js"], kind: "orm", packages: ["mongoose"], imports: [R(String.raw`require\(\s*['"]mongoose['"]\s*\)|from\s+['"]mongoose['"]`)] },
  { id: "prisma", name: "Prisma", langs: ["js"], kind: "orm", packages: ["@prisma/client", "prisma"], imports: [R(String.raw`from\s+['"]@prisma\/client['"]|require\(\s*['"]@prisma\/client['"]\s*\)`)], files: [{ path: /(?:^|\/)schema\.prisma$/ }] },
  { id: "typeorm", name: "TypeORM", langs: ["js"], kind: "orm", packages: ["typeorm"], imports: [R(String.raw`from\s+['"]typeorm['"]`)] },
  { id: "knex", name: "Knex", langs: ["js"], kind: "orm", packages: ["knex"], imports: [R(String.raw`require\(\s*['"]knex['"]\s*\)|from\s+['"]knex['"]`)] },
  { id: "ejs", name: "EJS", langs: ["js"], kind: "template", packages: ["ejs"], imports: [R(String.raw`require\(\s*['"]ejs['"]\s*\)|from\s+['"]ejs['"]`)], weak: [R(String.raw`set\(\s*['"]view engine['"]\s*,\s*['"]ejs['"]`)] },
  { id: "handlebars", name: "Handlebars", langs: ["js"], kind: "template", packages: ["handlebars", "express-handlebars"], imports: [R(String.raw`require\(\s*['"](?:express-)?handlebars['"]\s*\)|from\s+['"](?:express-)?handlebars['"]`)] },
  { id: "pug", name: "Pug", langs: ["js"], kind: "template", packages: ["pug"], imports: [R(String.raw`require\(\s*['"]pug['"]\s*\)|from\s+['"]pug['"]`)] },
  { id: "axios", name: "axios", langs: ["js"], kind: "http-client", packages: ["axios"], imports: [R(String.raw`require\(\s*['"]axios['"]\s*\)|from\s+['"]axios['"]`)] },

  // ── Python ──
  { id: "flask", name: "Flask", langs: ["py"], kind: "web", packages: ["flask", "Flask"], imports: [R(String.raw`^\s*(?:from\s+flask\s+import|import\s+flask\b)`, "m")], weak: [R(String.raw`@\w+\.route\s*\(`)] },
  { id: "django", name: "Django", langs: ["py"], kind: "web", packages: ["django", "Django"], imports: [R(String.raw`^\s*(?:from\s+django[\w.]*\s+import|import\s+django\b)`, "m")], files: [{ path: /(?:^|\/)manage\.py$/, content: /django/i }, { path: /(?:^|\/)settings\.py$/, content: /INSTALLED_APPS/ }] },
  { id: "fastapi", name: "FastAPI", langs: ["py"], kind: "web", packages: ["fastapi"], imports: [R(String.raw`^\s*(?:from\s+fastapi[\w.]*\s+import|import\s+fastapi\b)`, "m")] },
  { id: "aiohttp", name: "aiohttp", langs: ["py"], kind: "web", packages: ["aiohttp"], imports: [R(String.raw`^\s*(?:from\s+aiohttp[\w.]*\s+import|import\s+aiohttp\b)`, "m")] },
  { id: "tornado", name: "Tornado", langs: ["py"], kind: "web", packages: ["tornado"], imports: [R(String.raw`^\s*(?:from\s+tornado[\w.]*\s+import|import\s+tornado\b)`, "m")] },
  { id: "bottle", name: "Bottle", langs: ["py"], kind: "web", packages: ["bottle"], imports: [R(String.raw`^\s*(?:from\s+bottle\s+import|import\s+bottle\b)`, "m")] },
  { id: "sqlalchemy", name: "SQLAlchemy", langs: ["py"], kind: "orm", packages: ["sqlalchemy", "SQLAlchemy", "flask-sqlalchemy"], imports: [R(String.raw`^\s*(?:from\s+sqlalchemy[\w.]*\s+import|import\s+sqlalchemy\b|from\s+flask_sqlalchemy\s+import)`, "m")] },
  { id: "jinja2", name: "Jinja2", langs: ["py"], kind: "template", packages: ["jinja2", "Jinja2"], imports: [R(String.raw`^\s*(?:from\s+jinja2[\w.]*\s+import|import\s+jinja2\b)`, "m")] },
  { id: "requests", name: "requests", langs: ["py"], kind: "http-client", packages: ["requests"], imports: [R(String.raw`^\s*(?:import\s+requests\b|from\s+requests\s+import)`, "m")] },
  { id: "httpx", name: "httpx", langs: ["py"], kind: "http-client", packages: ["httpx"], imports: [R(String.raw`^\s*(?:import\s+httpx\b|from\s+httpx\s+import)`, "m")] },

  // ── Java / Kotlin ──
  { id: "spring-boot", name: "Spring Boot", langs: ["java", "kt"], kind: "web", packages: ["spring-boot-starter-parent", "spring-boot-starter-web", "spring-boot-starter-webflux", "spring-boot-starter", "org.springframework.boot", "spring-boot"], imports: [R(String.raw`^\s*import\s+org\.springframework\.(?:boot|web|http|jdbc|data)\b`, "m")], weak: [R(String.raw`@(?:RestController|RequestMapping|GetMapping|PostMapping|SpringBootApplication)\b`)], files: [{ path: /(?:^|\/)application(?:-\w+)?\.(?:properties|ya?ml)$/, content: /^\s*(?:spring\.|server\.port)/m }] },
  { id: "jax-rs", name: "JAX-RS", langs: ["java", "kt"], kind: "web", packages: ["jakarta.ws.rs-api", "javax.ws.rs-api", "resteasy", "jersey-server", "quarkus-resteasy"], imports: [R(String.raw`^\s*import\s+(?:javax|jakarta)\.ws\.rs\b`, "m")], weak: [R(String.raw`@Path\s*\(`)] },
  { id: "servlet", name: "Servlet API", langs: ["java", "kt"], kind: "http-server", packages: ["javax.servlet-api", "jakarta.servlet-api"], imports: [R(String.raw`^\s*import\s+(?:javax|jakarta)\.servlet\b`, "m")] },
  { id: "struts", name: "Apache Struts", langs: ["java"], kind: "web", packages: ["struts2-core", "struts-core"], imports: [R(String.raw`^\s*import\s+org\.apache\.struts2?\b`, "m")], files: [{ path: /(?:^|\/)struts\.xml$/ }] },
  { id: "micronaut", name: "Micronaut", langs: ["java", "kt"], kind: "web", packages: ["micronaut-http-server-netty", "micronaut-runtime", "io.micronaut"], imports: [R(String.raw`^\s*import\s+io\.micronaut\b`, "m")] },
  { id: "quarkus", name: "Quarkus", langs: ["java", "kt"], kind: "web", packages: ["quarkus-resteasy", "quarkus-rest", "quarkus-bom", "io.quarkus"], imports: [R(String.raw`^\s*import\s+io\.quarkus\b`, "m")] },
  { id: "vertx", name: "Vert.x", langs: ["java", "kt"], kind: "web", packages: ["vertx-core", "vertx-web", "io.vertx"], imports: [R(String.raw`^\s*import\s+io\.vertx\b`, "m")] },
  { id: "javalin", name: "Javalin", langs: ["java", "kt"], kind: "web", packages: ["javalin", "io.javalin"], imports: [R(String.raw`^\s*import\s+io\.javalin\b`, "m")] },
  { id: "hibernate", name: "Hibernate / JPA", langs: ["java", "kt"], kind: "orm", packages: ["hibernate-core", "hibernate-entitymanager", "spring-boot-starter-data-jpa", "jakarta.persistence-api"], imports: [R(String.raw`^\s*import\s+(?:org\.hibernate|javax\.persistence|jakarta\.persistence)\b`, "m")] },
  { id: "mybatis", name: "MyBatis", langs: ["java", "kt"], kind: "orm", packages: ["mybatis", "mybatis-spring"], imports: [R(String.raw`^\s*import\s+org\.(?:apache\.ibatis|mybatis)\b`, "m")] },
  { id: "ktor", name: "Ktor", langs: ["kt"], kind: "web", packages: ["ktor-server-core", "ktor-server-netty", "ktor-client-core", "io.ktor"], imports: [R(String.raw`^\s*import\s+io\.ktor\b`, "m")] },
  { id: "http4k", name: "http4k", langs: ["kt"], kind: "web", packages: ["http4k-core", "org.http4k"], imports: [R(String.raw`^\s*import\s+org\.http4k\b`, "m")] },
  { id: "exposed", name: "Exposed", langs: ["kt"], kind: "orm", packages: ["exposed-core", "exposed-jdbc", "org.jetbrains.exposed"], imports: [R(String.raw`^\s*import\s+org\.jetbrains\.exposed\b`, "m")] },

  // ── Go ──
  { id: "gin", name: "Gin", langs: ["go"], kind: "web", packages: ["github.com/gin-gonic/gin"], imports: [R(String.raw`"github\.com\/gin-gonic\/gin"`)] },
  { id: "echo", name: "Echo", langs: ["go"], kind: "web", packages: ["github.com/labstack/echo"], imports: [R(String.raw`"github\.com\/labstack\/echo(?:\/v\d+)?"`)] },
  { id: "fiber", name: "Fiber", langs: ["go"], kind: "web", packages: ["github.com/gofiber/fiber"], imports: [R(String.raw`"github\.com\/gofiber\/fiber(?:\/v\d+)?"`)] },
  { id: "chi", name: "chi", langs: ["go"], kind: "web", packages: ["github.com/go-chi/chi"], imports: [R(String.raw`"github\.com\/go-chi\/chi(?:\/v\d+)?"`)] },
  { id: "gorilla-mux", name: "gorilla/mux", langs: ["go"], kind: "web", packages: ["github.com/gorilla/mux"], imports: [R(String.raw`"github\.com\/gorilla\/mux"`)] },
  { id: "beego", name: "Beego", langs: ["go"], kind: "web", packages: ["github.com/beego/beego", "github.com/astaxie/beego"], imports: [R(String.raw`"github\.com\/(?:beego|astaxie)\/beego(?:\/v\d+)?(?:\/[\w\/]*)?"`)] },
  { id: "gorm", name: "GORM", langs: ["go"], kind: "orm", packages: ["gorm.io/gorm", "github.com/jinzhu/gorm"], imports: [R(String.raw`"(?:gorm\.io\/gorm|github\.com\/jinzhu\/gorm)"`)] },
  { id: "net-http", name: "net/http", langs: ["go"], kind: "http-server", weak: [R(String.raw`^\s*(?:import\s+)?"net\/http"`, "m"), R(String.raw`\bhttp\.(?:HandleFunc|ListenAndServe|NewServeMux)\s*\(`), R(String.raw`\bfunc\s+\w+\s*\(\s*\w+\s+http\.ResponseWriter\s*,\s*\w+\s+\*http\.Request\s*\)`)] },

  // ── C# ──
  { id: "aspnetcore", name: "ASP.NET Core", langs: ["cs"], kind: "web", packages: ["Microsoft.NET.Sdk.Web", "Microsoft.AspNetCore.App", "Microsoft.AspNetCore.Mvc"], imports: [R(String.raw`^\s*using\s+Microsoft\.AspNetCore\b`, "m")], weak: [R(String.raw`\[(?:HttpGet|HttpPost|ApiController)\b`)] },
  { id: "entity-framework", name: "Entity Framework", langs: ["cs"], kind: "orm", packages: ["Microsoft.EntityFrameworkCore", "EntityFramework"], imports: [R(String.raw`^\s*using\s+(?:Microsoft\.EntityFrameworkCore|System\.Data\.Entity)\b`, "m")] },
  { id: "dapper", name: "Dapper", langs: ["cs"], kind: "orm", packages: ["Dapper"], imports: [R(String.raw`^\s*using\s+Dapper\s*;`, "m")] },
  { id: "nancy", name: "Nancy", langs: ["cs"], kind: "web", packages: ["Nancy"], imports: [R(String.raw`^\s*using\s+Nancy\b`, "m")] },

  // ── PHP ──
  { id: "laravel", name: "Laravel", langs: ["php"], kind: "web", packages: ["laravel/framework"], imports: [R(String.raw`\buse\s+Illuminate\\`)], files: [{ path: /(?:^|\/)artisan$/ }] },
  { id: "symfony", name: "Symfony", langs: ["php"], kind: "web", packages: ["symfony/framework-bundle", "symfony/symfony"], imports: [R(String.raw`\buse\s+Symfony\\(?:Component\\HttpFoundation|Bundle|Component\\Routing)`)], files: [{ path: /(?:^|\/)symfony\.lock$/ }, { path: /(?:^|\/)config\/bundles\.php$/ }] },
  { id: "codeigniter", name: "CodeIgniter", langs: ["php"], kind: "web", packages: ["codeigniter4/framework", "codeigniter/framework"], imports: [R(String.raw`\buse\s+CodeIgniter\\`), R(String.raw`extends\s+CI_Controller\b`)] },
  { id: "yii", name: "Yii", langs: ["php"], kind: "web", packages: ["yiisoft/yii2", "yiisoft/yii2-app-basic"], imports: [R(String.raw`\buse\s+yii\\`)] },
  { id: "cakephp", name: "CakePHP", langs: ["php"], kind: "web", packages: ["cakephp/cakephp"], imports: [R(String.raw`\buse\s+Cake\\`)] },
  { id: "slim", name: "Slim", langs: ["php"], kind: "web", packages: ["slim/slim"], imports: [R(String.raw`\buse\s+Slim\\`)] },
  { id: "laminas", name: "Laminas", langs: ["php"], kind: "web", packages: ["laminas/laminas-mvc", "laminas/laminas-mvc-skeleton"], imports: [R(String.raw`\buse\s+Laminas\\`)] },
  { id: "wordpress", name: "WordPress", langs: ["php"], kind: "web", files: [{ path: /(?:^|\/)wp-config(?:-sample)?\.php$/ }, { path: /(?:^|\/)wp-content\/(?:plugins|themes)\/.+\.php$/ }], weak: [R(String.raw`\badd_(?:action|filter)\s*\(`), R(String.raw`\$wpdb->`), R(String.raw`\bABSPATH\b`)] },
  { id: "doctrine", name: "Doctrine", langs: ["php"], kind: "orm", packages: ["doctrine/orm", "doctrine/dbal"], imports: [R(String.raw`\buse\s+Doctrine\\(?:ORM|DBAL)`)] },

  // ── Ruby ──
  { id: "rails", name: "Rails", langs: ["rb"], kind: "web", packages: ["rails"], files: [{ path: /(?:^|\/)config\/routes\.rb$/ }, { path: /(?:^|\/)config\/application\.rb$/, content: /Rails::Application/ }], weak: [R(String.raw`<\s*ApplicationController\b`), R(String.raw`<\s*(?:ActiveRecord::Base|ApplicationRecord)\b`)] },
  { id: "sinatra", name: "Sinatra", langs: ["rb"], kind: "web", packages: ["sinatra"], imports: [R(String.raw`^\s*require\s+['"]sinatra(?:\/base)?['"]`, "m")] },
  { id: "hanami", name: "Hanami", langs: ["rb"], kind: "web", packages: ["hanami"], imports: [R(String.raw`^\s*require\s+['"]hanami['"]|\bmodule\s+Hanami\b`, "m")] },
  { id: "grape", name: "Grape", langs: ["rb"], kind: "web", packages: ["grape"], imports: [R(String.raw`<\s*Grape::API\b`)] },
  { id: "sequel", name: "Sequel", langs: ["rb"], kind: "orm", packages: ["sequel"], imports: [R(String.raw`^\s*require\s+['"]sequel['"]`, "m")] },

  // ── Rust ──
  { id: "actix-web", name: "Actix Web", langs: ["rs"], kind: "web", packages: ["actix-web"], imports: [R(String.raw`\buse\s+actix_web\b`)] },
  { id: "axum", name: "Axum", langs: ["rs"], kind: "web", packages: ["axum"], imports: [R(String.raw`\buse\s+axum\b`)] },
  { id: "rocket", name: "Rocket", langs: ["rs"], kind: "web", packages: ["rocket"], imports: [R(String.raw`\buse\s+rocket\b|#\[macro_use\]\s*extern\s+crate\s+rocket`)] },
  { id: "warp", name: "warp", langs: ["rs"], kind: "web", packages: ["warp"], imports: [R(String.raw`\buse\s+warp\b`)] },
  { id: "poem", name: "Poem", langs: ["rs"], kind: "web", packages: ["poem"], imports: [R(String.raw`\buse\s+poem\b`)] },
  { id: "hyper", name: "Hyper", langs: ["rs"], kind: "http-server", packages: ["hyper"], imports: [R(String.raw`\buse\s+hyper\b`)] },
  { id: "diesel", name: "Diesel", langs: ["rs"], kind: "orm", packages: ["diesel"], imports: [R(String.raw`\buse\s+diesel\b`)] },
  { id: "sqlx", name: "SQLx", langs: ["rs"], kind: "orm", packages: ["sqlx"], imports: [R(String.raw`\buse\s+sqlx\b`)] },
  { id: "sea-orm", name: "SeaORM", langs: ["rs"], kind: "orm", packages: ["sea-orm"], imports: [R(String.raw`\buse\s+sea_orm\b`)] },
  { id: "reqwest", name: "reqwest", langs: ["rs"], kind: "http-client", packages: ["reqwest"], imports: [R(String.raw`\buse\s+reqwest\b|\breqwest::`)] },

  // ── C / C++ ──
  { id: "boost-asio-beast", name: "Boost.Asio / Beast", langs: ["cpp"], kind: "http-server", packages: ["Boost", "boost"], imports: [R(String.raw`#\s*include\s*<boost\/(?:asio|beast)\b`)] },
  { id: "qt", name: "Qt", langs: ["cpp"], kind: "other", packages: ["Qt5", "Qt6", "Qt"], imports: [R(String.raw`#\s*include\s*<Q(?:Network|Sql|File|Process|Core)\w*>|#\s*include\s*<Qt\w+\/`)] },
  { id: "poco", name: "POCO", langs: ["cpp"], kind: "http-server", packages: ["Poco", "poco"], imports: [R(String.raw`#\s*include\s*["<]Poco\/`)] },
  { id: "crow", name: "Crow", langs: ["cpp"], kind: "web", packages: ["Crow", "crow"], imports: [R(String.raw`#\s*include\s*["<]crow(?:_all)?\.h`)] },
  { id: "drogon", name: "Drogon", langs: ["cpp"], kind: "web", packages: ["Drogon", "drogon"], imports: [R(String.raw`#\s*include\s*["<]drogon\/`)] },
  { id: "pistache", name: "Pistache", langs: ["cpp"], kind: "web", packages: ["Pistache", "pistache"], imports: [R(String.raw`#\s*include\s*["<]pistache\/`)] },
  { id: "libcurl", name: "libcurl", langs: ["cpp"], kind: "http-client", packages: ["CURL", "curl", "libcurl"], imports: [R(String.raw`#\s*include\s*<curl\/curl\.h>`)] },
  { id: "sqlite3", name: "SQLite", langs: ["cpp"], kind: "database", packages: ["SQLite3", "sqlite3"], imports: [R(String.raw`#\s*include\s*["<]sqlite3\.h[">]`)] },
  { id: "openssl", name: "OpenSSL", langs: ["cpp"], kind: "other", packages: ["OpenSSL", "openssl"], imports: [R(String.raw`#\s*include\s*<openssl\/`)] },
  { id: "apache-httpd", name: "Apache HTTP Server", langs: ["cpp"], kind: "http-server", imports: [R(String.raw`#\s*include\s*["<](?:httpd|http_core|http_protocol|apr_\w+)\.h[">]`)] },
];

const SOURCE_EXT: Record<FwLang, RegExp> = {
  js: /\.(?:[cm]?js|jsx|tsx?|vue)$/i, py: /\.py$/i, java: /\.java$/i, kt: /\.kts?$/i, go: /\.go$/i, cs: /\.cs$/i,
  php: /\.php$/i, rb: /\.rb$/i, rs: /\.rs$/i, cpp: /\.(?:c|cc|cpp|cxx|h|hh|hpp)$/i,
};

const MANIFEST: Array<{ langs: readonly FwLang[]; test: RegExp; kind: ManifestKind }> = [
  { langs: ["js"], test: /(?:^|\/)package\.json$/, kind: "package.json" },
  { langs: ["py"], test: /(?:^|\/)(?:requirements[\w.-]*\.txt|Pipfile|pyproject\.toml|setup\.py|setup\.cfg)$/, kind: "python" },
  { langs: ["java", "kt"], test: /(?:^|\/)pom\.xml$/, kind: "pom" },
  { langs: ["java", "kt"], test: /(?:^|\/)(?:build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?|libs\.versions\.toml)$/, kind: "gradle" },
  { langs: ["go"], test: /(?:^|\/)go\.mod$/, kind: "go.mod" },
  { langs: ["cs"], test: /(?:\.csproj|packages\.config|Directory\.Packages\.props)$/, kind: "csproj" },
  { langs: ["php"], test: /(?:^|\/)composer\.(?:json|lock)$/, kind: "composer" },
  { langs: ["rb"], test: /(?:^|\/)(?:Gemfile|Gemfile\.lock|[\w-]+\.gemspec)$/, kind: "gemfile" },
  { langs: ["rs"], test: /(?:^|\/)Cargo\.toml$/, kind: "cargo" },
  { langs: ["cpp"], test: /(?:^|\/)(?:CMakeLists\.txt|vcpkg\.json|conanfile\.(?:txt|py)|meson\.build)$/, kind: "native" },
];
type ManifestKind = "package.json" | "python" | "pom" | "gradle" | "go.mod" | "csproj" | "composer" | "gemfile" | "cargo" | "native";

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");

/** The version written right after a package's name in a manifest, by manifest dialect; null when none is stated. */
const VERSION_AFTER: Record<ManifestKind, RegExp> = {
  "package.json": /^"\s*:\s*"[\^~>=<\s]*(\d[\w.*+-]*)/,
  python: /^(?:\[[^\]]*\])?\s*(?:==|>=|<=|~=|!=|>|<|=)?\s*["']?[\^~>=<\s]*(\d[\w.*+-]*)/,
  pom: /^<\/artifactId>\s*<version>\s*(\d[\w.-]*)/,
  gradle: /^["']?\s*(?::|,\s*version\s*[:=]?\s*["']?|\s+version\s+["'])(\d[\w.-]*)/,
  "go.mod": /^(?:\/v\d+)?\s+v?(\d[\w.+-]*)/,
  csproj: /^"[^>]*?\bVersion="(\d[\w.*-]*)"/,
  composer: /^"\s*:\s*"[\^~>=<\s]*(\d[\w.*-]*)/,
  gemfile: /^(?:['"])?\s*(?:,\s*['"][~>=<\s]*(\d[\w.]*)['"]|\s+\((\d[\w.]*)\))/,
  cargo: /^\s*=\s*(?:\{[^}]*?version\s*=\s*)?"[\^~=]?(\d[\w.+-]*)"/,
  native: /^\s*(?:VERSION\s+|[=\s:"]+)(\d[\w.]*)/,
};

function declared(def: FrameworkDef, files: readonly RepoFile[]): { where: string; version: string | null } | null {
  if (!def.packages?.length) return null;
  let best: { where: string; version: string | null } | null = null;
  for (const f of files) {
    for (const m of MANIFEST) {
      if (!m.test.test(f.path) || !m.langs.some(l => def.langs.includes(l))) continue;
      for (const pkg of def.packages) {
        // whole-name match: `flask` is not `flask-cors`, `express` is not `express-session`
        const re = new RegExp(`(?<![\\w./@-])${esc(pkg)}(?![\\w-])`, "g");
        let hit: RegExpExecArray | null;
        while ((hit = re.exec(f.content))) {
          const after = f.content.slice(hit.index + hit[0].length, hit.index + hit[0].length + 160);
          const v = VERSION_AFTER[m.kind].exec(after);
          const version = v ? (v[1] ?? v[2] ?? null) : null;
          if (!best || (!best.version && version)) best = { where: f.path, version };
          if (version) return best;
        }
      }
    }
  }
  return best;
}

const sourceFilesOf = (def: FrameworkDef, files: readonly RepoFile[]) => files.filter(f => def.langs.some(l => SOURCE_EXT[l].test(f.path)));

/** The code with `//`, `#` and `/* *\/` comments blanked out, so an import in a comment is not evidence. */
function stripComments(code: string): string {
  return code.replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, " ")).replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1").replace(/^\s*#(?!\s*include|\[)[^\n]*/gm, "");
}

export function detectFrameworks(files: readonly RepoFile[]): DetectedFramework[] {
  const out: DetectedFramework[] = [];
  const cleaned = new Map<string, string>();
  const text = (f: RepoFile) => { let c = cleaned.get(f.path); if (c === undefined) { c = stripComments(f.content); cleaned.set(f.path, c); } return c; };

  for (const def of FRAMEWORKS) {
    const evidence: string[] = [];
    let score = 0;
    const decl = declared(def, files);
    if (decl) { score += 3; evidence.push(`declared: ${decl.where}${decl.version ? ` (${decl.version})` : ""}`); }

    const sources = sourceFilesOf(def, files);
    const importHit = def.imports?.length ? sources.find(f => def.imports!.some(re => re.test(text(f)))) : undefined;
    if (importHit) { score += 2; evidence.push(`import: ${importHit.path}`); }

    const fileHit = def.files?.find(sig => files.some(f => sig.path.test(f.path) && (!sig.content || sig.content.test(f.content))));
    if (fileHit) { score += 2; evidence.push(`file: ${files.find(f => fileHit.path.test(f.path))!.path}`); }

    // weak signals count once each, at most two: two different generic shapes are corroboration, one is not
    let weak = 0;
    for (const re of def.weak ?? []) {
      if (weak >= 2) break;
      const f = sources.find(s => re.test(text(s)));
      if (f) { weak++; evidence.push(`weak: ${f.path}`); }
    }
    score += weak;

    if (score < 2) continue;
    const version = decl?.version ?? null;
    const major = version ? Number.parseInt(version, 10) : NaN;
    out.push({
      id: def.id, name: def.name, langs: def.langs, kind: def.kind, version, major: Number.isFinite(major) ? major : null,
      confidence: score >= 4 ? "high" : "medium", score, evidence,
    });
  }
  return out.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
}

/** The registry entry for an id (the coverage report iterates this). */
export function frameworkDef(id: string): FrameworkDef | undefined { return FRAMEWORKS.find(f => f.id === id); }
