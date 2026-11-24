/**
 * @jest-environment node
 *
 * Request sources and sinks of the Rust stack: Actix Web, Axum, Rocket, Warp, Poem, Tide, Salvo, Hyper, Tokio (sockets, stdin, env), and
 * Diesel / SQLx / SeaORM / rusqlite / tokio-postgres, plus unsafe Rust and FFI (raw pointers, libc, extern "C", libloading). Each vulnerable
 * case ("rule") must be reported; each "!rule" case is the safe counterpart (bound parameter, checked conversion, guard, constant) that must stay quiet.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";
jest.setTimeout(300_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);
const ids = (name: string, content: string) =>
  runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: `t/${name}`, content }] })
    .files[0].indicators.filter(i => i.line != null && i.id !== "ai-model-attribution").map(i => i.id);
const ACT = (sig: string, body: string) => `use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};\nuse std::process::Command;\nuse std::fs;\n\n#[get("/a")]\nasync fn h(${sig}) -> HttpResponse {\n${body}\n    HttpResponse::Ok().finish()\n}\n`;
const AXUM = (sig: string, body: string) => `use axum::{extract::{Query, Path, Json, Form, State}, http::HeaderMap, response::IntoResponse};\nuse std::process::Command;\nuse std::fs;\n\nasync fn h(${sig}) -> impl IntoResponse {\n${body}\n    "ok"\n}\n`;
const ROCKET = (attr: string, sig: string, body: string) => `use rocket::{get, post, serde::json::Json, form::Form};\nuse std::process::Command;\nuse std::fs;\n\n#[${attr}]\nfn h(${sig}) -> String {\n${body}\n    String::new()\n}\n`;
const cases: Array<[string, string, string]> = [
 // ---- Actix Web
 ["actix Query command", "command-injection", ACT("q: web::Query<Q>", `    Command::new(&q.cmd).output().unwrap();`)],
 ["actix Path command", "command-injection", ACT("path: web::Path<String>", `    Command::new(path.into_inner()).output().unwrap();`)],
 ["actix Json sh -c", "command-injection", ACT("b: web::Json<B>", `    Command::new("sh").arg("-c").arg(&b.cmd).output().unwrap();`)],
 ["actix Form arg injection", "argument-injection", ACT("f: web::Form<F>", `    Command::new("ls").arg(&f.dir).output().unwrap();`)],
 ["actix arg after -- safe", "!argument-injection", ACT("f: web::Form<F>", `    Command::new("ls").arg("--").arg(&f.dir).output().unwrap();`)],
 ["actix header", "path-traversal", ACT("req: HttpRequest", `    let p = req.headers().get("X-F").unwrap().to_str().unwrap();\n    fs::read_to_string(p).unwrap();`)],
 ["actix match_info", "path-traversal", ACT("req: HttpRequest", `    let p = req.match_info().get("f").unwrap();\n    fs::read(p).unwrap();`)],
 ["actix query_string", "ssrf", ACT("req: HttpRequest", `    reqwest::get(req.query_string()).await.unwrap();`)],
 ["actix Bytes body", "command-injection", ACT("body: web::Bytes", `    Command::new(String::from_utf8_lossy(&body).to_string()).output().unwrap();`)],
 ["actix String body", "command-injection", ACT("body: String", `    Command::new(body).output().unwrap();`)],
 ["actix cookie", "path-traversal", ACT("req: HttpRequest", `    let c = req.cookie("f").unwrap();\n    fs::read(c.value()).unwrap();`)],
 ["actix sqlx format", "sql-injection", ACT("q: web::Query<Q>, pool: web::Data<PgPool>", `    sqlx::query(&format!("SELECT * FROM t WHERE n = '{}'", q.n)).fetch_all(pool.get_ref()).await.unwrap();`)],
 ["actix HttpRequest redirect", "open-redirect", `use actix_web::{web, HttpResponse};\nasync fn h(q: web::Query<Q>) -> HttpResponse {\n    HttpResponse::Found().append_header(("Location", q.next.clone())).finish()\n}\n`],
 ["actix NamedFile", "path-traversal", `use actix_files::NamedFile;\nuse actix_web::{web, Result};\nasync fn h(path: web::Path<String>) -> Result<NamedFile> {\n    Ok(NamedFile::open(path.into_inner())?)\n}\n`],
 ["actix NamedFile join", "path-traversal", `use actix_files::NamedFile;\nuse actix_web::{web, Result};\nuse std::path::PathBuf;\nasync fn h(path: web::Path<String>) -> Result<NamedFile> {\n    let p = PathBuf::from("./static").join(path.into_inner());\n    Ok(NamedFile::open(p)?)\n}\n`],
 ["actix NamedFile file_name safe", "!path-traversal", `use actix_files::NamedFile;\nuse actix_web::{web, Result};\nuse std::path::{Path, PathBuf};\nasync fn h(path: web::Path<String>) -> Result<NamedFile> {\n    let n = Path::new(&path.into_inner()).file_name().unwrap().to_owned();\n    Ok(NamedFile::open(PathBuf::from("./static").join(n))?)\n}\n`],
 ["actix html format xss", "xss", `use actix_web::{web, HttpResponse};\nasync fn h(q: web::Query<Q>) -> HttpResponse {\n    HttpResponse::Ok().content_type("text/html").body(format!("<h1>{}</h1>", q.n))\n}\n`],
 ["actix html escape safe", "!xss", `use actix_web::{web, HttpResponse};\nasync fn h(q: web::Query<Q>) -> HttpResponse {\n    HttpResponse::Ok().content_type("text/html").body(format!("<h1>{}</h1>", html_escape::encode_text(&q.n)))\n}\n`],
 // ---- Axum
 ["axum Query command", "command-injection", AXUM("Query(q): Query<Q>", `    Command::new(q.cmd).output().unwrap();`)],
 ["axum Path", "path-traversal", AXUM("Path(name): Path<String>", `    fs::read_to_string(name).unwrap();`)],
 ["axum Json", "ssrf", AXUM("Json(b): Json<B>", `    reqwest::get(&b.url).await.unwrap();`)],
 ["axum Form", "sql-injection", AXUM("State(pool): State<PgPool>, Form(f): Form<F>", `    sqlx::query(&format!("SELECT * FROM t WHERE n = '{}'", f.n)).fetch_all(&pool).await.unwrap();`)],
 ["axum HeaderMap", "ssrf", AXUM("headers: HeaderMap", `    let u = headers.get("x-u").unwrap().to_str().unwrap();\n    reqwest::get(u).await.unwrap();`)],
 ["axum RawQuery", "command-injection", `use axum::extract::RawQuery;\nuse std::process::Command;\nasync fn h(RawQuery(q): RawQuery) -> &'static str {\n    Command::new(q.unwrap()).output().unwrap();\n    "ok"\n}\n`],
 ["axum String body", "command-injection", AXUM("body: String", `    Command::new("sh").arg("-c").arg(body).output().unwrap();`)],
 ["axum Bytes body", "path-traversal", `use axum::body::Bytes;\nuse std::fs;\nasync fn h(body: Bytes) -> &'static str {\n    fs::read(String::from_utf8(body.to_vec()).unwrap()).unwrap();\n    "ok"\n}\n`],
 ["axum Request uri", "path-traversal", `use axum::{extract::Request, response::IntoResponse};\nuse std::fs;\nasync fn h(req: Request) -> impl IntoResponse {\n    fs::read(req.uri().path()).unwrap();\n    "ok"\n}\n`],
 ["axum TypedHeader host", "ssrf", `use axum_extra::{headers::Host, TypedHeader};\nasync fn h(TypedHeader(host): TypedHeader<Host>) -> &'static str {\n    reqwest::get(format!("http://{}/", host)).await.unwrap();\n    "ok"\n}\n`],
 ["axum Path i64 safe", "!sql-injection", AXUM("Path(id): Path<i64>, State(pool): State<PgPool>", `    sqlx::query(&format!("SELECT * FROM t WHERE id = {}", id)).fetch_all(&pool).await.unwrap();`)],
 ["axum bind safe", "!sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    sqlx::query("SELECT * FROM t WHERE n = $1").bind(q.n).fetch_all(&pool).await.unwrap();`)],
 ["axum query! macro safe", "!sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    sqlx::query!("SELECT * FROM t WHERE n = $1", q.n).fetch_all(&pool).await.unwrap();`)],
 ["axum Redirect", "open-redirect", `use axum::{extract::Query, response::Redirect};\nasync fn h(Query(q): Query<Q>) -> Redirect {\n    Redirect::to(&q.next)\n}\n`],
 ["axum Html xss", "xss", `use axum::{extract::Query, response::Html};\nasync fn h(Query(q): Query<Q>) -> Html<String> {\n    Html(format!("<h1>{}</h1>", q.n))\n}\n`],
 ["axum Client get", "ssrf", AXUM("Query(q): Query<Q>", `    let c = reqwest::Client::new();\n    c.get(&q.u).send().await.unwrap();`)],
 ["axum Client post", "ssrf", AXUM("Query(q): Query<Q>", `    let c = reqwest::Client::new();\n    c.post(q.u).send().await.unwrap();`)],
 ["axum constant url safe", "!ssrf", AXUM("Query(q): Query<Q>", `    reqwest::get("https://api.example.com/x").await.unwrap();`)],
 ["axum tokio fs", "path-traversal", AXUM("Path(p): Path<String>", `    tokio::fs::read(p).await.unwrap();`)],
 ["axum tokio Command", "command-injection", `use axum::extract::Query;\nuse tokio::process::Command;\nasync fn h(Query(q): Query<Q>) -> &'static str {\n    Command::new(q.cmd).output().await.unwrap();\n    "ok"\n}\n`],
 ["axum File::open", "path-traversal", `use axum::extract::Path;\nuse std::fs::File;\nasync fn h(Path(p): Path<String>) -> &'static str {\n    let f = File::open(p).unwrap();\n    "ok"\n}\n`],
 ["axum tokio File::open", "path-traversal", `use axum::extract::Path;\nuse tokio::fs::File;\nasync fn h(Path(p): Path<String>) -> &'static str {\n    let f = File::open(p).await.unwrap();\n    "ok"\n}\n`],
 ["axum OpenOptions", "path-traversal", `use axum::extract::Path;\nuse std::fs::OpenOptions;\nasync fn h(Path(p): Path<String>) -> &'static str {\n    OpenOptions::new().write(true).create(true).open(p).unwrap();\n    "ok"\n}\n`],
 ["axum fs::write", "path-traversal", AXUM("Path(p): Path<String>, body: String", `    fs::write(p, body).unwrap();`)],
 ["axum remove_file", "path-traversal", AXUM("Path(p): Path<String>", `    fs::remove_file(p).unwrap();`)],
 ["axum canonicalize guard safe", "!path-traversal", AXUM("Path(p): Path<String>", `    let base = std::path::Path::new("/srv/files").canonicalize().unwrap();\n    let full = base.join(&p).canonicalize().unwrap();\n    if !full.starts_with(&base) { return "no"; }\n    fs::read(full).unwrap();`)],
 // ---- Rocket
 ["rocket route param", "command-injection", ROCKET(`get("/<name>")`, "name: &str", `    Command::new(name).output().unwrap();`)],
 ["rocket query param", "path-traversal", ROCKET(`get("/?<f>")`, "f: String", `    fs::read(f).unwrap();`)],
 ["rocket Form", "sql-injection", `use rocket::{post, form::Form};\nuse sqlx::PgPool;\n#[post("/a", data = "<f>")]\nasync fn h(f: Form<F>, pool: &rocket::State<PgPool>) -> String {\n    sqlx::query(&format!("SELECT * FROM t WHERE n = '{}'", f.n)).fetch_all(pool.inner()).await.unwrap();\n    String::new()\n}\n`],
 ["rocket Json", "ssrf", `use rocket::{post, serde::json::Json};\n#[post("/a", data = "<b>")]\nasync fn h(b: Json<B>) -> String {\n    reqwest::get(&b.url).await.unwrap();\n    String::new()\n}\n`],
 ["rocket CookieJar", "path-traversal", `use rocket::{get, http::CookieJar};\nuse std::fs;\n#[get("/a")]\nfn h(jar: &CookieJar<'_>) -> String {\n    let f = jar.get("f").unwrap().value().to_string();\n    fs::read(f).unwrap();\n    String::new()\n}\n`],
 ["rocket data Data", "command-injection", `use rocket::{post, Data};\nuse std::process::Command;\n#[post("/a", data = "<d>")]\nasync fn h(d: Data<'_>) -> String {\n    let s = d.open(1.mebibytes()).into_string().await.unwrap();\n    Command::new(s.into_inner()).output().unwrap();\n    String::new()\n}\n`],
 ["rocket segments", "path-traversal", `use rocket::get;\nuse std::path::PathBuf;\nuse std::fs;\n#[get("/<path..>")]\nfn h(path: PathBuf) -> String {\n    fs::read(PathBuf::from("/srv").join(path)).unwrap();\n    String::new()\n}\n`],
 ["rocket redirect", "open-redirect", `use rocket::{get, response::Redirect};\n#[get("/go?<next>")]\nfn h(next: String) -> Redirect {\n    Redirect::to(next)\n}\n`],
 ["rocket i32 param safe", "!sql-injection", `use rocket::get;\n#[get("/<id>")]\nasync fn h(id: i32, pool: &rocket::State<PgPool>) -> String {\n    sqlx::query(&format!("SELECT * FROM t WHERE id = {}", id)).fetch_all(pool.inner()).await.unwrap();\n    String::new()\n}\n`],
 // ---- Warp
 ["warp query", "command-injection", `use warp::Filter;\nuse std::collections::HashMap;\nuse std::process::Command;\nfn routes() {\n    let r = warp::path("a").and(warp::query::<HashMap<String, String>>()).map(|q: HashMap<String, String>| {\n        Command::new(q.get("c").unwrap()).output().unwrap();\n        "ok"\n    });\n}\n`],
 ["warp path param", "path-traversal", `use warp::Filter;\nuse std::fs;\nfn routes() {\n    let r = warp::path("f").and(warp::path::param::<String>()).map(|name: String| {\n        fs::read(name).unwrap();\n        "ok"\n    });\n}\n`],
 ["warp json body", "ssrf", `use warp::Filter;\nfn routes() {\n    let r = warp::post().and(warp::body::json()).and_then(|b: B| async move {\n        reqwest::get(&b.url).await.unwrap();\n        Ok::<_, warp::Rejection>("ok")\n    });\n}\n`],
 ["warp header", "path-traversal", `use warp::Filter;\nuse std::fs;\nfn routes() {\n    let r = warp::header::<String>("x-f").map(|f: String| {\n        fs::read(f).unwrap();\n        "ok"\n    });\n}\n`],
 ["warp form", "sql-injection", `use warp::Filter;\nfn routes(pool: PgPool) {\n    let r = warp::post().and(warp::body::form()).and_then(move |f: HashMap<String, String>| { let pool = pool.clone(); async move {\n        sqlx::query(&format!("SELECT * FROM t WHERE n = '{}'", f["n"])).fetch_all(&pool).await.unwrap();\n        Ok::<_, warp::Rejection>("ok")\n    } });\n}\n`],
 ["warp handler fn", "command-injection", `use warp::Filter;\nuse std::process::Command;\nasync fn run(cmd: String) -> Result<impl warp::Reply, warp::Rejection> {\n    Command::new(cmd).output().unwrap();\n    Ok("ok")\n}\nfn routes() {\n    let r = warp::path!("run" / String).and_then(run);\n}\n`],
 ["warp redirect", "open-redirect", `use warp::Filter;\nfn routes() {\n    let r = warp::query::<HashMap<String, String>>().map(|q: HashMap<String, String>| {\n        warp::redirect::found(q["next"].parse::<warp::http::Uri>().unwrap())\n    });\n}\n`],
 // ---- Poem
 ["poem Query", "command-injection", `use poem::{handler, web::Query};\nuse std::process::Command;\n#[handler]\nfn h(Query(q): Query<Q>) -> String {\n    Command::new(q.cmd).output().unwrap();\n    String::new()\n}\n`],
 ["poem Path", "path-traversal", `use poem::{handler, web::Path};\nuse std::fs;\n#[handler]\nfn h(Path(name): Path<String>) -> String {\n    fs::read_to_string(name).unwrap()\n}\n`],
 ["poem Json", "ssrf", `use poem::{handler, web::Json};\n#[handler]\nasync fn h(Json(b): Json<B>) -> String {\n    reqwest::get(b.url).await.unwrap();\n    String::new()\n}\n`],
 ["poem Form", "sql-injection", `use poem::{handler, web::Form};\n#[handler]\nasync fn h(Form(f): Form<F>, pool: poem::web::Data<&PgPool>) -> String {\n    sqlx::query(&format!("SELECT * FROM t WHERE n = '{}'", f.n)).fetch_all(pool.0).await.unwrap();\n    String::new()\n}\n`],
 ["poem Request header", "ssrf", `use poem::{handler, Request};\n#[handler]\nasync fn h(req: &Request) -> String {\n    let u = req.header("x-u").unwrap();\n    reqwest::get(u).await.unwrap();\n    String::new()\n}\n`],
 ["poem Request uri query", "command-injection", `use poem::{handler, Request};\nuse std::process::Command;\n#[handler]\nfn h(req: &Request) -> String {\n    Command::new(req.uri().query().unwrap()).output().unwrap();\n    String::new()\n}\n`],
 ["poem openapi", "path-traversal", `use poem_openapi::{param::Query, OpenApi};\nstruct Api;\n#[OpenApi]\nimpl Api {\n    #[oai(path = "/a", method = "get")]\n    async fn a(&self, f: Query<String>) -> String {\n        std::fs::read_to_string(f.0).unwrap()\n    }\n}\n`],
 // ---- Tide
 ["tide query", "command-injection", `use std::process::Command;\nasync fn h(req: tide::Request<()>) -> tide::Result {\n    let q: Q = req.query()?;\n    Command::new(q.cmd).output().unwrap();\n    Ok("ok".into())\n}\n`],
 ["tide param", "path-traversal", `async fn h(req: tide::Request<()>) -> tide::Result {\n    let f = req.param("f")?;\n    std::fs::read(f).unwrap();\n    Ok("ok".into())\n}\n`],
 ["tide body_json", "ssrf", `async fn h(mut req: tide::Request<()>) -> tide::Result {\n    let b: B = req.body_json().await?;\n    reqwest::get(&b.url).await.unwrap();\n    Ok("ok".into())\n}\n`],
 ["tide body_string", "command-injection", `use std::process::Command;\nasync fn h(mut req: tide::Request<()>) -> tide::Result {\n    let b = req.body_string().await?;\n    Command::new(b).output().unwrap();\n    Ok("ok".into())\n}\n`],
 ["tide header", "ssrf", `async fn h(req: tide::Request<()>) -> tide::Result {\n    let u = req.header("x-u").unwrap().as_str();\n    reqwest::get(u).await.unwrap();\n    Ok("ok".into())\n}\n`],
 ["tide url query", "path-traversal", `async fn h(req: tide::Request<()>) -> tide::Result {\n    let p = req.url().path().to_string();\n    std::fs::read(p).unwrap();\n    Ok("ok".into())\n}\n`],
 ["tide sql", "sql-injection", `async fn h(req: tide::Request<PgPool>) -> tide::Result {\n    let q: Q = req.query()?;\n    sqlx::query(&format!("SELECT * FROM t WHERE n = '{}'", q.n)).fetch_all(req.state()).await?;\n    Ok("ok".into())\n}\n`],
 ["tide redirect", "open-redirect", `async fn h(req: tide::Request<()>) -> tide::Result {\n    let q: Q = req.query()?;\n    Ok(tide::Redirect::new(q.next).into())\n}\n`],
 // ---- Salvo
 ["salvo query", "command-injection", `use salvo::prelude::*;\nuse std::process::Command;\n#[handler]\nasync fn h(req: &mut Request, res: &mut Response) {\n    let c = req.query::<String>("c").unwrap();\n    Command::new(c).output().unwrap();\n}\n`],
 ["salvo param", "path-traversal", `use salvo::prelude::*;\n#[handler]\nasync fn h(req: &mut Request, res: &mut Response) {\n    let f = req.param::<String>("f").unwrap();\n    std::fs::read(f).unwrap();\n}\n`],
 ["salvo parse_json", "ssrf", `use salvo::prelude::*;\n#[handler]\nasync fn h(req: &mut Request, res: &mut Response) {\n    let b = req.parse_json::<B>().await.unwrap();\n    reqwest::get(&b.url).await.unwrap();\n}\n`],
 ["salvo form", "sql-injection", `use salvo::prelude::*;\n#[handler]\nasync fn h(req: &mut Request, depot: &mut Depot) {\n    let n = req.form::<String>("n").await.unwrap();\n    sqlx::query(&format!("SELECT * FROM t WHERE n = '{}'", n)).fetch_all(pool()).await.unwrap();\n}\n`],
 ["salvo header", "ssrf", `use salvo::prelude::*;\n#[handler]\nasync fn h(req: &mut Request, res: &mut Response) {\n    let u = req.header::<String>("x-u").unwrap();\n    reqwest::get(u).await.unwrap();\n}\n`],
 ["salvo extract", "command-injection", `use salvo::prelude::*;\nuse std::process::Command;\n#[handler]\nasync fn h(req: &mut Request) {\n    let q = req.extract::<Q>().await.unwrap();\n    Command::new(q.cmd).output().unwrap();\n}\n`],
 ["salvo handler arg", "command-injection", `use salvo::prelude::*;\nuse std::process::Command;\n#[handler]\nasync fn h(q: QueryParam<String, true>) {\n    Command::new(q.into_inner()).output().unwrap();\n}\n`],
 ["salvo redirect", "open-redirect", `use salvo::prelude::*;\n#[handler]\nasync fn h(req: &mut Request, res: &mut Response) {\n    let n = req.query::<String>("next").unwrap();\n    res.render(Redirect::found(n));\n}\n`],
 // ---- Hyper
 ["hyper uri query", "command-injection", `use hyper::{Body, Request, Response};\nuse std::process::Command;\nasync fn h(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {\n    Command::new(req.uri().query().unwrap()).output().unwrap();\n    Ok(Response::new(Body::empty()))\n}\n`],
 ["hyper uri path", "path-traversal", `use hyper::{Body, Request, Response};\nasync fn h(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {\n    std::fs::read(req.uri().path()).unwrap();\n    Ok(Response::new(Body::empty()))\n}\n`],
 ["hyper header", "ssrf", `use hyper::{Body, Request, Response};\nasync fn h(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {\n    let u = req.headers().get("x-u").unwrap().to_str().unwrap();\n    reqwest::get(u).await.unwrap();\n    Ok(Response::new(Body::empty()))\n}\n`],
 ["hyper body to_bytes", "command-injection", `use hyper::{Body, Request, Response};\nuse std::process::Command;\nasync fn h(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {\n    let b = hyper::body::to_bytes(req.into_body()).await?;\n    Command::new(String::from_utf8(b.to_vec()).unwrap()).output().unwrap();\n    Ok(Response::new(Body::empty()))\n}\n`],
 ["hyper body aggregate", "path-traversal", `use hyper::{Body, Request, Response};\nuse hyper::body::Buf;\nasync fn h(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {\n    let b = hyper::body::aggregate(req).await?;\n    let s = String::from_utf8(b.chunk().to_vec()).unwrap();\n    std::fs::read(s).unwrap();\n    Ok(Response::new(Body::empty()))\n}\n`],
 ["hyper service_fn", "command-injection", `use hyper::{service::service_fn, Body, Request, Response};\nuse std::process::Command;\nfn main() {\n    let svc = service_fn(|req: Request<Body>| async move {\n        Command::new(req.uri().path()).output().unwrap();\n        Ok::<_, hyper::Error>(Response::new(Body::empty()))\n    });\n}\n`],
 ["hyper uri builder ssrf", "ssrf", `use hyper::{Body, Client, Request};\nasync fn h(req: Request<Body>) {\n    let u = req.uri().query().unwrap();\n    let r = Request::builder().uri(u).body(Body::empty()).unwrap();\n    Client::new().request(r).await.unwrap();\n}\n`],
 ["hyper client get", "ssrf", `use hyper::{Body, Client, Request};\nasync fn h(req: Request<Body>) {\n    let u: hyper::Uri = req.uri().query().unwrap().parse().unwrap();\n    Client::new().get(u).await.unwrap();\n}\n`],
 // ---- Tokio: sockets, stdin, env
 ["tokio TcpStream read", "command-injection", `use tokio::{io::AsyncReadExt, net::TcpStream};\nuse std::process::Command;\nasync fn h(mut s: TcpStream) {\n    let mut buf = vec![0u8; 1024];\n    let n = s.read(&mut buf).await.unwrap();\n    Command::new(String::from_utf8_lossy(&buf[..n]).to_string()).output().unwrap();\n}\n`],
 ["tokio read_to_string", "path-traversal", `use tokio::{io::AsyncReadExt, net::TcpStream};\nasync fn h(mut s: TcpStream) {\n    let mut p = String::new();\n    s.read_to_string(&mut p).await.unwrap();\n    std::fs::read(p).unwrap();\n}\n`],
 ["tokio BufReader lines", "command-injection", `use tokio::{io::{AsyncBufReadExt, BufReader}, net::TcpStream};\nuse std::process::Command;\nasync fn h(s: TcpStream) {\n    let mut lines = BufReader::new(s).lines();\n    while let Some(l) = lines.next_line().await.unwrap() {\n        Command::new(l).output().unwrap();\n    }\n}\n`],
 ["std stdin read_line", "command-injection", `use std::process::Command;\nfn main() {\n    let mut s = String::new();\n    std::io::stdin().read_line(&mut s).unwrap();\n    Command::new(s.trim()).output().unwrap();\n}\n`],
 ["env args", "command-injection", `use std::process::Command;\nfn main() {\n    let a: Vec<String> = std::env::args().collect();\n    Command::new(&a[1]).output().unwrap();\n}\n`],
 // CLI tools intentionally accept user-provided paths as args -- path-traversal from env::args is a false positive;
 // env::var (injected via environment) is a real source for path traversal.
 ["env args path not flagged", "!path-traversal", `fn main() {\n    let a: Vec<String> = std::env::args().collect();\n    std::fs::read(&a[1]).unwrap();\n}\n`],
 ["env var", "path-traversal", `fn main() {\n    let p = std::env::var("CFG").unwrap();\n    std::fs::read(p).unwrap();\n}\n`],
 ["tokio UdpSocket recv_from", "path-traversal", `use tokio::net::UdpSocket;\nasync fn h(s: UdpSocket) {\n    let mut buf = [0u8; 512];\n    let (n, _) = s.recv_from(&mut buf).await.unwrap();\n    std::fs::read(String::from_utf8_lossy(&buf[..n]).to_string()).unwrap();\n}\n`],
 ["tokio spawn_blocking cmd", "command-injection", `use axum::extract::Query;\nuse std::process::Command;\nasync fn h(Query(q): Query<Q>) {\n    tokio::task::spawn_blocking(move || { Command::new(q.cmd).output().unwrap(); }).await.unwrap();\n}\n`],
 ["tokio spawn cmd", "command-injection", `use axum::extract::Query;\nuse tokio::process::Command;\nasync fn h(Query(q): Query<Q>) {\n    tokio::spawn(async move { Command::new(q.cmd).spawn().unwrap(); });\n}\n`],
 // ---- Diesel
 ["diesel sql_query format", "sql-injection", `use axum::extract::Query;\nuse diesel::prelude::*;\nasync fn h(Query(q): Query<Q>, mut conn: PgConnection) {\n    diesel::sql_query(format!("SELECT * FROM t WHERE n = '{}'", q.n)).load::<T>(&mut conn).unwrap();\n}\n`],
 ["diesel sql_query concat", "sql-injection", `use axum::extract::Query;\nuse diesel::prelude::*;\nasync fn h(Query(q): Query<Q>, mut conn: PgConnection) {\n    let sql = "DELETE FROM t WHERE n = '".to_string() + &q.n + "'";\n    diesel::sql_query(sql).execute(&mut conn).unwrap();\n}\n`],
 ["diesel sql_query bind safe", "!sql-injection", `use axum::extract::Query;\nuse diesel::prelude::*;\nuse diesel::sql_types::Text;\nasync fn h(Query(q): Query<Q>, mut conn: PgConnection) {\n    diesel::sql_query("SELECT * FROM t WHERE n = $1").bind::<Text, _>(q.n).load::<T>(&mut conn).unwrap();\n}\n`],
 ["diesel filter safe", "!sql-injection", `use axum::extract::Query;\nuse diesel::prelude::*;\nasync fn h(Query(q): Query<Q>, mut conn: PgConnection) {\n    t::table.filter(t::n.eq(q.n)).load::<T>(&mut conn).unwrap();\n}\n`],
 ["diesel sql() literal", "sql-injection", `use axum::extract::Query;\nuse diesel::prelude::*;\nasync fn h(Query(q): Query<Q>, mut conn: PgConnection) {\n    t::table.filter(diesel::dsl::sql::<diesel::sql_types::Bool>(&format!("n = '{}'", q.n))).load::<T>(&mut conn).unwrap();\n}\n`],
 ["diesel order sql", "sql-injection", `use axum::extract::Query;\nuse diesel::prelude::*;\nasync fn h(Query(q): Query<Q>, mut conn: PgConnection) {\n    t::table.order(diesel::dsl::sql::<diesel::sql_types::Bool>(&q.o)).load::<T>(&mut conn).unwrap();\n}\n`],
 ["diesel batch_execute", "sql-injection", `use axum::extract::Query;\nuse diesel::prelude::*;\nasync fn h(Query(q): Query<Q>, mut conn: PgConnection) {\n    conn.batch_execute(&format!("DELETE FROM t WHERE n = '{}'", q.n)).unwrap();\n}\n`],
 ["diesel actix Path", "sql-injection", `use actix_web::web;\nuse diesel::prelude::*;\nasync fn h(path: web::Path<String>, mut conn: PgConnection) {\n    diesel::sql_query(format!("SELECT * FROM t WHERE n = '{}'", path.into_inner())).load::<T>(&mut conn).unwrap();\n}\n`],
 // ---- SQLx
 ["sqlx query_as", "sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    sqlx::query_as::<_, T>(&format!("SELECT * FROM t WHERE n = '{}'", q.n)).fetch_all(&pool).await.unwrap();`)],
 ["sqlx query_scalar", "sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    sqlx::query_scalar::<_, i64>(&format!("SELECT count(*) FROM t WHERE n = '{}'", q.n)).fetch_one(&pool).await.unwrap();`)],
 ["sqlx execute", "sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    sqlx::query(&format!("DELETE FROM t WHERE n = '{}'", q.n)).execute(&pool).await.unwrap();`)],
 ["sqlx raw_sql", "sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    sqlx::raw_sql(&format!("DELETE FROM t WHERE n = '{}'", q.n)).execute(&pool).await.unwrap();`)],
 ["sqlx pool.execute", "sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    pool.execute(format!("DELETE FROM t WHERE n = '{}'", q.n).as_str()).await.unwrap();`)],
 ["sqlx String sql var", "sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    let sql = format!("SELECT * FROM t WHERE n = '{}'", q.n);\n    sqlx::query(&sql).fetch_all(&pool).await.unwrap();`)],
 ["sqlx inline capture", "sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    let n = q.n;\n    sqlx::query(&format!("SELECT * FROM t WHERE n = '{n}'")).fetch_all(&pool).await.unwrap();`)],
 ["sqlx push_str builder", "sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    let mut sql = String::from("SELECT * FROM t WHERE n = '");\n    sql.push_str(&q.n);\n    sql.push('\\'');\n    sqlx::query(&sql).fetch_all(&pool).await.unwrap();`)],
 ["sqlx QueryBuilder push safe", "!sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    let mut qb = sqlx::QueryBuilder::new("SELECT * FROM t WHERE n = ");\n    qb.push_bind(q.n);\n    qb.build().fetch_all(&pool).await.unwrap();`)],
 ["sqlx QueryBuilder push raw", "sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    let mut qb = sqlx::QueryBuilder::new("SELECT * FROM t WHERE ");\n    qb.push(q.cond);\n    qb.build().fetch_all(&pool).await.unwrap();`)],
 ["sqlx order by interp", "sql-injection", AXUM("State(pool): State<PgPool>, Query(q): Query<Q>", `    sqlx::query(&format!("SELECT * FROM t ORDER BY {}", q.o)).fetch_all(&pool).await.unwrap();`)],
 ["sqlx tokio_postgres", "sql-injection", AXUM("State(client): State<std::sync::Arc<tokio_postgres::Client>>, Query(q): Query<Q>", `    client.query(&format!("SELECT * FROM t WHERE n = '{}'", q.n), &[]).await.unwrap();`)],
 ["tokio_postgres simple_query", "sql-injection", AXUM("State(client): State<std::sync::Arc<tokio_postgres::Client>>, Query(q): Query<Q>", `    client.simple_query(&format!("DELETE FROM t WHERE n = '{}'", q.n)).await.unwrap();`)],
 ["rusqlite execute", "sql-injection", AXUM("State(conn): State<std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>>, Query(q): Query<Q>", `    conn.lock().unwrap().execute(&format!("DELETE FROM t WHERE n = '{}'", q.n), []).unwrap();`)],
 ["rusqlite params safe", "!sql-injection", AXUM("State(conn): State<std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>>, Query(q): Query<Q>", `    conn.lock().unwrap().execute("DELETE FROM t WHERE n = ?1", [q.n]).unwrap();`)],
 ["mysql_async query", "sql-injection", AXUM("State(pool): State<mysql_async::Pool>, Query(q): Query<Q>", `    let mut conn = pool.get_conn().await.unwrap();\n    conn.query_drop(format!("DELETE FROM t WHERE n = '{}'", q.n)).await.unwrap();`)],
 // ---- SeaORM
 ["sea Statement::from_string", "sql-injection", AXUM("State(db): State<DatabaseConnection>, Query(q): Query<Q>", `    db.execute(Statement::from_string(DbBackend::Postgres, format!("DELETE FROM t WHERE n = '{}'", q.n))).await.unwrap();`)],
 ["sea query_all from_string", "sql-injection", AXUM("State(db): State<DatabaseConnection>, Query(q): Query<Q>", `    db.query_all(Statement::from_string(DbBackend::Postgres, format!("SELECT * FROM t WHERE n = '{}'", q.n))).await.unwrap();`)],
 ["sea execute_unprepared", "sql-injection", AXUM("State(db): State<DatabaseConnection>, Query(q): Query<Q>", `    db.execute_unprepared(&format!("DELETE FROM t WHERE n = '{}'", q.n)).await.unwrap();`)],
 ["sea from_raw_sql", "sql-injection", AXUM("State(db): State<DatabaseConnection>, Query(q): Query<Q>", `    Entity::find().from_raw_sql(Statement::from_string(DbBackend::Postgres, format!("SELECT * FROM t WHERE n = '{}'", q.n))).all(&db).await.unwrap();`)],
 ["sea Expr::cust", "sql-injection", AXUM("State(db): State<DatabaseConnection>, Query(q): Query<Q>", `    Entity::find().filter(Expr::cust(format!("n = '{}'", q.n))).all(&db).await.unwrap();`)],
 ["sea Expr::cust_with_values safe", "!sql-injection", AXUM("State(db): State<DatabaseConnection>, Query(q): Query<Q>", `    Entity::find().filter(Expr::cust_with_values("n = $1", [q.n])).all(&db).await.unwrap();`)],
 ["sea from_sql_and_values safe", "!sql-injection", AXUM("State(db): State<DatabaseConnection>, Query(q): Query<Q>", `    db.execute(Statement::from_sql_and_values(DbBackend::Postgres, "DELETE FROM t WHERE n = $1", [q.n.into()])).await.unwrap();`)],
 ["sea filter eq safe", "!sql-injection", AXUM("State(db): State<DatabaseConnection>, Query(q): Query<Q>", `    Entity::find().filter(Column::Name.eq(q.n)).all(&db).await.unwrap();`)],
 ["sea order_by_asc column", "sql-injection", AXUM("State(db): State<DatabaseConnection>, Query(q): Query<Q>", `    Entity::find().order_by_asc(Expr::cust(q.o)).all(&db).await.unwrap();`)],
 ["sea actix", "sql-injection", `use actix_web::web;\nasync fn h(db: web::Data<DatabaseConnection>, q: web::Query<Q>) {\n    db.execute_unprepared(&format!("DELETE FROM t WHERE n = '{}'", q.n)).await.unwrap();\n}\n`],
 // ---- command & SSRF details
 ["Command::new const arg tainted", "argument-injection", AXUM("Query(q): Query<Q>", `    Command::new("git").arg("clone").arg(q.repo).output().unwrap();`)],
 ["Command args vec", "argument-injection", AXUM("Query(q): Query<Q>", `    Command::new("ls").args(&["-l", &q.dir]).output().unwrap();`)],
 ["Command bash -c format", "command-injection", AXUM("Query(q): Query<Q>", `    Command::new("bash").args(["-c", &format!("echo {}", q.m)]).output().unwrap();`)],
 ["Command constant safe", "!command-injection", AXUM("Query(q): Query<Q>", `    Command::new("ls").arg("-l").output().unwrap();`)],
 ["Command int parse safe", "!argument-injection", AXUM("Query(q): Query<Q>", `    let n: u32 = q.n.parse().unwrap();\n    Command::new("head").arg("-n").arg(n.to_string()).output().unwrap();`)],
 ["Command allowlist safe", "!command-injection", AXUM("Query(q): Query<Q>", `    let cmd = q.cmd;\n    let allowed = ["ls", "pwd"];\n    if !allowed.contains(&cmd.as_str()) { return "no"; }\n    Command::new(cmd).output().unwrap();`)],
 ["reqwest blocking get", "ssrf", AXUM("Query(q): Query<Q>", `    reqwest::blocking::get(&q.u).unwrap();`)],
 ["reqwest Client builder", "ssrf", AXUM("Query(q): Query<Q>", `    let c = reqwest::Client::builder().build().unwrap();\n    c.get(&q.u).send().await.unwrap();`)],
 ["reqwest client put", "ssrf", AXUM("Query(q): Query<Q>", `    let c = reqwest::Client::new();\n    c.put(&q.u).body("x").send().await.unwrap();`)],
 ["reqwest request()", "ssrf", AXUM("Query(q): Query<Q>", `    let c = reqwest::Client::new();\n    c.request(reqwest::Method::GET, &q.u).send().await.unwrap();`)],
 ["reqwest format host", "ssrf", AXUM("Query(q): Query<Q>", `    reqwest::get(format!("http://{}/admin", q.host)).await.unwrap();`)],
 ["reqwest format path safe", "!ssrf", AXUM("Query(q): Query<Q>", `    reqwest::get(format!("https://api.example.com/users/{}", q.id)).await.unwrap();`)],
 ["ureq get", "ssrf", AXUM("Query(q): Query<Q>", `    ureq::get(&q.u).call().unwrap();`)],
 ["surf get", "ssrf", AXUM("Query(q): Query<Q>", `    surf::get(&q.u).await.unwrap();`)],
 ["isahc get", "ssrf", AXUM("Query(q): Query<Q>", `    isahc::get(&q.u).unwrap();`)],
 ["TcpStream::connect", "ssrf", AXUM("Query(q): Query<Q>", `    tokio::net::TcpStream::connect(&q.addr).await.unwrap();`)],
 ["std TcpStream::connect", "ssrf", AXUM("Query(q): Query<Q>", `    std::net::TcpStream::connect(&q.addr).unwrap();`)],
 // ---- unsafe Rust
 ["unsafe get_unchecked tainted idx", "buffer-overflow", AXUM("Query(q): Query<Q>", `    let v = vec![1u8, 2, 3];\n    let i: usize = q.i.parse().unwrap();\n    let x = unsafe { *v.get_unchecked(i) };`)],
 ["unsafe ptr add tainted", "buffer-overflow", AXUM("Query(q): Query<Q>", `    let v = [1u8, 2, 3];\n    let n: usize = q.n.parse().unwrap();\n    let x = unsafe { *v.as_ptr().add(n) };`)],
 ["unsafe from_raw_parts len", "buffer-overflow", AXUM("Query(q): Query<Q>", `    let v = [1u8, 2, 3];\n    let n: usize = q.n.parse().unwrap();\n    let s = unsafe { std::slice::from_raw_parts(v.as_ptr(), n) };`)],
 ["unsafe set_len", "buffer-overflow", AXUM("Query(q): Query<Q>", `    let mut v: Vec<u8> = Vec::with_capacity(8);\n    let n: usize = q.n.parse().unwrap();\n    unsafe { v.set_len(n); }`)],
 ["unsafe copy_nonoverlapping len", "buffer-overflow", AXUM("Query(q): Query<Q>", `    let src = [0u8; 8];\n    let mut dst = [0u8; 8];\n    let n: usize = q.n.parse().unwrap();\n    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), n); }`)],
 ["unsafe ptr write offset", "buffer-overflow", AXUM("Query(q): Query<Q>", `    let mut buf = [0u8; 8];\n    let o: isize = q.o.parse().unwrap();\n    unsafe { *buf.as_mut_ptr().offset(o) = 1; }`)],
 ["unsafe bounded safe", "!buffer-overflow", AXUM("Query(q): Query<Q>", `    let v = vec![1u8, 2, 3];\n    let i: usize = q.i.parse().unwrap();\n    if i >= v.len() { return "no"; }\n    let x = unsafe { *v.get_unchecked(i) };`)],
 ["unsafe from_utf8_unchecked", "buffer-overflow", AXUM("body: axum::body::Bytes", `    let s = unsafe { String::from_utf8_unchecked(body.to_vec()) };`)],
 ["unsafe transmute from request", "buffer-overflow", AXUM("body: axum::body::Bytes", `    let v: u64 = unsafe { std::mem::transmute::<[u8; 8], u64>(body[..8].try_into().unwrap()) };`)],
 ["ffi system via libc", "command-injection", `use axum::extract::Query;\nuse std::ffi::CString;\nasync fn h(Query(q): Query<Q>) -> &'static str {\n    let c = CString::new(q.cmd).unwrap();\n    unsafe { libc::system(c.as_ptr()); }\n    "ok"\n}\n`],
 ["ffi extern C system", "command-injection", `use axum::extract::Query;\nuse std::ffi::CString;\nextern "C" { fn system(cmd: *const std::os::raw::c_char) -> i32; }\nasync fn h(Query(q): Query<Q>) -> &'static str {\n    let c = CString::new(q.cmd).unwrap();\n    unsafe { system(c.as_ptr()); }\n    "ok"\n}\n`],
 ["ffi strcpy", "buffer-overflow", `use axum::extract::Query;\nuse std::ffi::CString;\nasync fn h(Query(q): Query<Q>) -> &'static str {\n    let c = CString::new(q.name).unwrap();\n    let mut d = [0i8; 16];\n    unsafe { libc::strcpy(d.as_mut_ptr(), c.as_ptr()); }\n    "ok"\n}\n`],
 ["ffi memcpy len", "buffer-overflow", `use axum::extract::Query;\nasync fn h(Query(q): Query<Q>) -> &'static str {\n    let src = [0u8; 8];\n    let mut dst = [0u8; 8];\n    let n: usize = q.n.parse().unwrap();\n    unsafe { libc::memcpy(dst.as_mut_ptr() as *mut _, src.as_ptr() as *const _, n); }\n    "ok"\n}\n`],
 ["ffi sqlite3_exec", "sql-injection", `use axum::extract::Query;\nuse std::ffi::CString;\nasync fn h(Query(q): Query<Q>, db: *mut sqlite3) -> &'static str {\n    let sql = CString::new(format!("DELETE FROM t WHERE n = '{}'", q.n)).unwrap();\n    unsafe { sqlite3_exec(db, sql.as_ptr(), None, std::ptr::null_mut(), std::ptr::null_mut()); }\n    "ok"\n}\n`],
 ["ffi dlopen", "eval-exec", `use axum::extract::Query;\nuse std::ffi::CString;\nasync fn h(Query(q): Query<Q>) -> &'static str {\n    let c = CString::new(q.lib).unwrap();\n    unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW); }\n    "ok"\n}\n`],
 ["libloading Library::new", "eval-exec", `use axum::extract::Query;\nasync fn h(Query(q): Query<Q>) -> &'static str {\n    let l = unsafe { libloading::Library::new(q.lib).unwrap() };\n    "ok"\n}\n`],
 ["ffi printf format", "format-string", `use axum::extract::Query;\nuse std::ffi::CString;\nasync fn h(Query(q): Query<Q>) -> &'static str {\n    let c = CString::new(q.msg).unwrap();\n    unsafe { libc::printf(c.as_ptr()); }\n    "ok"\n}\n`],
 ["ffi constant safe", "!command-injection", `use std::ffi::CString;\nasync fn h() -> &'static str {\n    let c = CString::new("ls").unwrap();\n    unsafe { libc::system(c.as_ptr()); }\n    "ok"\n}\n`],
 ["ffi printf %s safe", "!format-string", `use axum::extract::Query;\nuse std::ffi::CString;\nasync fn h(Query(q): Query<Q>) -> &'static str {\n    let c = CString::new(q.msg).unwrap();\n    unsafe { libc::printf(b"%s\\0".as_ptr() as *const _, c.as_ptr()); }\n    "ok"\n}\n`],
 ["integer overflow arithmetic", "arithmetic-overflow", AXUM("Query(q): Query<Q>", `    let a: u32 = q.a.parse().unwrap();\n    let n = a * 4096;\n    let v = vec![0u8; n as usize];`)],
 ["checked_mul safe", "!arithmetic-overflow", AXUM("Query(q): Query<Q>", `    let a: u32 = q.a.parse().unwrap();\n    let n = a.checked_mul(4096).unwrap_or(0);`)],
 ["neg warp state closure", "!command-injection", `use warp::Filter;\nuse std::process::Command;\nfn routes(bin: String) {\n    let r = warp::any().map(move || { Command::new(bin.clone()).output().unwrap(); "ok" });\n}\n`],
 ["neg file read not a source", "!command-injection", `use std::io::Read;\nuse std::process::Command;\nfn main() {\n    let mut f = std::fs::File::open("cfg").unwrap();\n    let mut s = String::new();\n    f.read_to_string(&mut s).unwrap();\n    Command::new(s).output().unwrap();\n}\n`],
 ["neg actix Data app state", "!command-injection", `use actix_web::web;\nuse std::process::Command;\nasync fn h(cfg: web::Data<Config>) -> &'static str {\n    Command::new(&cfg.bin).output().unwrap();\n    "ok"\n}\n`],
 ["neg user fn named system", "!command-injection", `use axum::extract::Query;\nfn system(c: &str) -> usize { c.len() }\nasync fn h(Query(q): Query<Q>) -> &'static str {\n    system(&q.cmd);\n    "ok"\n}\n`],
 ["neg transmute constant", "!buffer-overflow", `fn main() {\n    let v: u32 = unsafe { std::mem::transmute::<[u8; 4], u32>([1, 2, 3, 4]) };\n}\n`],
 ["neg hyper constant body", "!command-injection", `use hyper::{Body, Request, Response};\nuse std::process::Command;\nasync fn h(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {\n    Command::new("ls").output().unwrap();\n    Ok(Response::new(Body::empty()))\n}\n`],
 ["neg tokio constant after read", "!command-injection", `use tokio::{io::AsyncReadExt, net::TcpStream};\nuse std::process::Command;\nasync fn h(mut s: TcpStream) {\n    let mut buf = vec![0u8; 16];\n    let _ = s.read(&mut buf).await.unwrap();\n    Command::new("ls").output().unwrap();\n}\n`],
 ["neg salvo constant", "!command-injection", `use salvo::prelude::*;\nuse std::process::Command;\n#[handler]\nasync fn h(req: &mut Request, res: &mut Response) {\n    let _ = req.query::<String>("c");\n    Command::new("ls").output().unwrap();\n}\n`],
 ["neg redirect constant", "!open-redirect", `use axum::response::Redirect;\nasync fn h() -> Redirect {\n    Redirect::to("/home")\n}\n`],
 ["typed closure request param", "command-injection", `use hyper::{Body, Request};
use std::process::Command;
fn main() {
    register(|req: Request<Body>| {
        Command::new(req.uri().path()).output().unwrap();
    });
}
`],
 ["typed closure extractor param", "path-traversal", `use axum::extract::Query;
fn main() {
    register(|Query(q): Query<Q>| {
        std::fs::read(q.f).unwrap();
    });
}
`],
];
describe("Rust framework request sources and sinks", () => {
  it.each(cases)("%s -> %s", (_label, want, code) => {
    const got = ids("p.rs", code);
    if (want.startsWith("!")) expect(got).not.toContain(want.slice(1));
    else expect(got).toContain(want);
  });
});
