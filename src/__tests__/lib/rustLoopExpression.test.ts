/**
 * @jest-environment node
 *
 * A Rust `loop { ... }` used as an expression sent the taint engine into infinite recursion (mask -> valueMask -> mask on the
 * same node): "Maximum call stack size exceeded", and every other function in that file went unanalysed. Found scanning the
 * Angular repository (packages/compiler-cli/preprocessor/ng-analyze).
 */
import { analyzeFile } from "@/lib/scanner";
import { warmRustTaintEngine } from "@/lib/astTaintRust";

beforeAll(async () => { await warmRustTaintEngine(); }, 120000);

const withLoop = `
use std::process::Command;

fn next_token(input: &str) -> usize {
    let mut i = 0;
    let end = loop {
        if i >= input.len() { break i; }
        i += 1;
    };
    end
}

fn run(req: &actix_web::HttpRequest) -> std::io::Result<()> {
    let host = req.match_info().get("host").unwrap_or("");
    Command::new("sh").arg("-c").arg(format!("ping {}", host)).status()?;
    Ok(())
}
`;

describe("Rust loop expressions", () => {
  it("analysing a file with `let x = loop { ... }` does not overflow the stack, and the rest of the file is still analysed", () => {
    const errors = jest.spyOn(console, "error").mockImplementation(() => {});
    try {
      const ids = analyzeFile("src/handlers.rs", withLoop).indicators.map(i => i.id);
      // the command injection in the NEXT function is found: the engine did not give up on the file
      expect(ids).toContain("command-injection");
      const crashes = errors.mock.calls.filter(c => /Maximum call stack|threw/.test(String(c[0]) + String(c[1])));
      expect(crashes).toEqual([]);
    } finally {
      errors.mockRestore();
    }
  });

  it("a loop in statement position and a `while` are fine too", () => {
    const errors = jest.spyOn(console, "error").mockImplementation(() => {});
    try {
      const code = `fn f(n: u32) -> u32 {\n    let mut x = 0;\n    loop { x += 1; if x > n { break; } }\n    while x > 0 { x -= 1; }\n    x\n}\n`;
      analyzeFile("src/a.rs", code);
      expect(errors.mock.calls.filter(c => /Maximum call stack|threw/.test(String(c[0]) + String(c[1])))).toEqual([]);
    } finally {
      errors.mockRestore();
    }
  });
});
