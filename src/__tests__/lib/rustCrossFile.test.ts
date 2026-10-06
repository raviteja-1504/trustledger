/**
 * @jest-environment node
 *
 * Rust cross-file evidence through runScan: a handler passing request input to a service method, a trait object,
 * an associated function or a free function in another module is reported at the call -- and stays quiet when
 * the callee binds the value or the module isn't in the batch.
 */
import { runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { warmRustTaintEngine } from "@/lib/astTaintRust";

beforeAll(async () => { await warmRustTaintEngine(); }, 120000);

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const ast = (r: ReturnType<typeof scan>, path: string, id: string): ScanIndicator[] =>
  r.files.find(f => f.file_path === path)!.indicators.filter(i => i.confidence === 95 && i.id === id);

const HANDLER = "src/handlers.rs";
const handler = (call: string, extra = "") => `use std::sync::Arc;
${extra}
pub async fn search(Query(p): Query<Search>, State(svc): State<Arc<UserService>>) -> impl IntoResponse {
    ${call};
    "ok"
}
`;
const SERVICE: F = { path: "src/services/user.rs", content: `pub struct UserService { conn: Connection }
impl UserService {
    pub fn find(&self, name: &str) {
        self.conn.execute(&format!("SELECT * FROM users WHERE name = '{}'", name), []).unwrap();
    }
    pub fn find_safe(&self, name: &str) {
        self.conn.execute("SELECT * FROM users WHERE name = ?1", [name]).unwrap();
    }
    pub fn export(path: &str) -> String {
        std::fs::read_to_string(path).unwrap()
    }
}
pub fn run(cmd: &str) {
    std::process::Command::new(cmd).spawn().unwrap();
}
` };

describe("Rust cross-file sink facts", () => {
  it("a service method through State<Arc<T>> is reported at the handler call", () => {
    const f = ast(scan([SERVICE, { path: HANDLER, content: handler("svc.find(&p.name)") }]), HANDLER, "sql-injection");
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(4);
    expect(f[0].sinkExpr).toContain("UserService.find");
  });

  it("an associated function and a free function imported with use", () => {
    expect(ast(scan([SERVICE, { path: HANDLER, content: handler("UserService::export(&p.file)") }]), HANDLER, "path-traversal")).toHaveLength(1);
    expect(ast(scan([SERVICE, { path: HANDLER, content: handler("run(&p.cmd)", "use crate::services::user::run;") }]), HANDLER, "command-injection")).toHaveLength(1);
    expect(ast(scan([SERVICE, { path: HANDLER, content: handler("user::run(&p.cmd)", "use crate::services::user;") }]), HANDLER, "command-injection")).toHaveLength(1);
  });

  it("a service held in an app-state struct (state.users.find)", () => {
    const h: F = { path: HANDLER, content: `pub struct AppState { users: UserService }\npub async fn h(Query(p): Query<Search>, State(state): State<Arc<AppState>>) {\n    state.users.find(&p.name);\n}\n` };
    expect(ast(scan([SERVICE, h]), HANDLER, "sql-injection")).toHaveLength(1);
  });

  it("through a trait object", () => {
    const repo: F = { path: "src/repo.rs", content: `pub trait Repo { fn raw(&self, q: &str); }\npub struct PgRepo { client: Client }\nimpl Repo for PgRepo {\n    fn raw(&self, q: &str) {\n        self.client.query(&format!("SELECT * FROM t WHERE a = '{q}'"), &[]);\n    }\n}\n` };
    const h: F = { path: HANDLER, content: `pub async fn h(Query(p): Query<P>, State(repo): State<Arc<dyn Repo>>) {\n    repo.raw(&p.q);\n}\n` };
    expect(ast(scan([repo, h]), HANDLER, "sql-injection")).toHaveLength(1);
  });

  it("quiet for the bound-parameter method, a literal, or without the service file", () => {
    expect(ast(scan([SERVICE, { path: HANDLER, content: handler("svc.find_safe(&p.name)") }]), HANDLER, "sql-injection")).toHaveLength(0);
    expect(ast(scan([SERVICE, { path: HANDLER, content: handler(`svc.find("bob")`) }]), HANDLER, "sql-injection")).toHaveLength(0);
    expect(ast(scan([{ path: HANDLER, content: handler("svc.find(&p.name)") }]), HANDLER, "sql-injection")).toHaveLength(0);
  });
});
