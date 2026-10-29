/**
 * @jest-environment node
 *
 * Constant folding ported from the Java engine (OWASP BenchmarkJava) to C#, PHP, Ruby and Kotlin: an if / ternary /
 * switch on a compile-time constant of its function runs one arm, and the arm that can't run is recorded as cleared
 * so the regex layer's line match is vetoed too. A reassigned "constant" is not one.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";
import { warmKotlinTaintEngine } from "@/lib/astTaintKotlin";

beforeAll(async () => {
  await warmCSharpTaintEngine(); await warmPhpTaintEngine(); await warmRubyTaintEngine(); await warmKotlinTaintEngine();
}, 120000);

const cmd = (path: string, code: string) => analyzeFile(path, code).indicators.some(i => i.id === "command-injection");

describe("C#", () => {
  const cs = (pick: string) => `using System.Diagnostics;\nnamespace A {\n  public class HomeController : Controller {\n    public IActionResult Run(string p) {\n      string bar;\n${pick}\n      Process.Start("/bin/sh", "-c ls " + bar);\n      return Content("x");\n    }\n  }\n}\n`;
  it("if / ?: / switch on a constant", () => {
    expect(cmd("Controllers/HomeController.cs", cs(`      int num = 86;\n      if ((7 * 42) - num > 200) bar = "safe"; else bar = p;`))).toBe(false);
    expect(cmd("Controllers/HomeController.cs", cs(`      int num = 86;\n      if ((7 * 42) - num > 200) bar = p; else bar = "safe";`))).toBe(true);
    expect(cmd("Controllers/HomeController.cs", cs(`      int num = 106;\n      bar = (7 * 18) + num > 200 ? "safe" : p;`))).toBe(false);
    expect(cmd("Controllers/HomeController.cs", cs(`      string guess = "ABC";\n      switch (guess[1]) {\n        case 'A': bar = p; break;\n        default: bar = "bob"; break;\n      }`.replace("guess[1]", "guess.charAt(1)")))).toBe(false);
    expect(cmd("Controllers/HomeController.cs", cs(`      int num = 86;\n      num = int.Parse(p);\n      if ((7 * 42) - num > 200) bar = "safe"; else bar = p;`))).toBe(true);
  });
});

describe("PHP", () => {
  const php = (pick: string) => `<?php\nfunction run() {\n    $p = $_GET['p'];\n${pick}\n    system("ls " . $bar);\n}\n`;
  it("if / ?: / switch on a constant", () => {
    expect(cmd("run.php", php(`    $num = 86;\n    if ((7 * 42) - $num > 200) { $bar = 'safe'; } else { $bar = $p; }`))).toBe(false);
    expect(cmd("run.php", php(`    $num = 86;\n    if ((7 * 42) - $num > 200) { $bar = $p; } else { $bar = 'safe'; }`))).toBe(true);
    expect(cmd("run.php", php(`    $num = 106;\n    $bar = (7 * 18) + $num > 200 ? 'safe' : $p;`))).toBe(false);
    expect(cmd("run.php", php(`    $guess = 'ABC';\n    switch ($guess) {\n        case 'XYZ': $bar = $p; break;\n        default: $bar = 'bob'; break;\n    }`))).toBe(false);
    expect(cmd("run.php", php(`    $num = 86;\n    $num = intval($p);\n    if ((7 * 42) - $num > 200) { $bar = 'safe'; } else { $bar = $p; }`))).toBe(true);
  });
});

describe("Ruby", () => {
  const rb = (pick: string) => `class RunController < ApplicationController\n  def run\n    p = params[:p]\n${pick}\n    system("ls #{bar}")\n  end\nend\n`;
  it("if / unless / ?: / case on a constant", () => {
    expect(cmd("app/controllers/run_controller.rb", rb(`    num = 86\n    if (7 * 42) - num > 200\n      bar = "safe"\n    else\n      bar = p\n    end`))).toBe(false);
    expect(cmd("app/controllers/run_controller.rb", rb(`    num = 86\n    if (7 * 42) - num > 200\n      bar = p\n    else\n      bar = "safe"\n    end`))).toBe(true);
    expect(cmd("app/controllers/run_controller.rb", rb(`    num = 86\n    unless (7 * 42) - num > 200\n      bar = "safe"\n    else\n      bar = p\n    end`))).toBe(true);
    expect(cmd("app/controllers/run_controller.rb", rb(`    num = 106\n    bar = (7 * 18) + num > 200 ? "safe" : p`))).toBe(false);
    expect(cmd("app/controllers/run_controller.rb", rb(`    guess = 'B'\n    case guess\n    when 'A'\n      bar = p\n    else\n      bar = "bob"\n    end`))).toBe(false);
  });
});

describe("Kotlin", () => {
  const kt = (pick: string) => `@RestController\nclass RunController {\n    @GetMapping("/run")\n    fun run(@RequestParam p: String): String {\n${pick}\n        Runtime.getRuntime().exec("ls " + bar)\n        return "ok"\n    }\n}\n`;
  it("if / when on a constant", () => {
    expect(cmd("RunController.kt", kt(`        val num = 86\n        val bar = if ((7 * 42) - num > 200) "safe" else p`))).toBe(false);
    expect(cmd("RunController.kt", kt(`        val num = 86\n        val bar = if ((7 * 42) - num > 200) p else "safe"`))).toBe(true);
    expect(cmd("RunController.kt", kt(`        val guess = "ABC"\n        val bar = when (guess[1]) {\n            'A' -> p\n            else -> "bob"\n        }`))).toBe(false);
    expect(cmd("RunController.kt", kt(`        var num = 86\n        num = p.length\n        val bar = if ((7 * 42) - num > 200) "safe" else p`))).toBe(true);
  });
});
