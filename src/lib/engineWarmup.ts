/**
 * Wait for the tree-sitter data-flow engines (Python, Go, C#, PHP, Ruby, Kotlin, Rust, C/C++) before scanning.
 *
 * Nothing loads them at server start (that slowed every route's cold start, see instrumentation.ts), so a scan
 * that didn't wait would give those files pattern checks only. Every scan entry point awaits this first. Bounded: if an engine can't load within `timeoutMs`, the scan
 * goes ahead and its health report (scanHealth.ts) says which files lost data-flow analysis.
 * Server-only.
 */
import { warmPythonTaintEngine } from "./astTaintPython";
import { warmGoTaintEngine } from "./astTaintGo";
import { warmCSharpTaintEngine } from "./astTaintCSharp";
import { warmPhpTaintEngine } from "./astTaintPHP";
import { warmRubyTaintEngine } from "./astTaintRuby";
import { warmKotlinTaintEngine } from "./astTaintKotlin";
import { warmRustTaintEngine } from "./astTaintRust";
import { warmCppTaintEngine } from "./astTaintCpp";

export const ENGINE_WARMUP_TIMEOUT_MS = 20000;

export async function ensureTaintEngines(timeoutMs = ENGINE_WARMUP_TIMEOUT_MS): Promise<{ ready: boolean; ms: number }> {
  const t0 = Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const all = Promise.allSettled([warmPythonTaintEngine(), warmGoTaintEngine(), warmCSharpTaintEngine(), warmPhpTaintEngine(), warmRubyTaintEngine(), warmKotlinTaintEngine(), warmRustTaintEngine(), warmCppTaintEngine()])
    .then(results => results.every(r => r.status === "fulfilled"));
  const timeout = new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), timeoutMs); });
  try {
    const ready = await Promise.race([all, timeout]);
    return { ready, ms: Date.now() - t0 };
  } finally {
    if (timer) clearTimeout(timer);
  }
}
