/**
 * Wait for the tree-sitter data-flow engines (Python, Go, C#, PHP) before scanning.
 *
 * instrumentation.ts starts loading them when the server boots but does not wait, so on a cold serverless
 * start a scan could run before a parser is ready and those files would silently get pattern checks only.
 * Every scan entry point awaits this first. Bounded: if an engine can't load within `timeoutMs`, the scan
 * goes ahead and its health report (scanHealth.ts) says which files lost data-flow analysis.
 * Server-only.
 */
import { warmPythonTaintEngine } from "./astTaintPython";
import { warmGoTaintEngine } from "./astTaintGo";
import { warmCSharpTaintEngine } from "./astTaintCSharp";
import { warmPhpTaintEngine } from "./astTaintPHP";
import { warmRubyTaintEngine } from "./astTaintRuby";
import { warmKotlinTaintEngine } from "./astTaintKotlin";

export const ENGINE_WARMUP_TIMEOUT_MS = 20000;

export async function ensureTaintEngines(timeoutMs = ENGINE_WARMUP_TIMEOUT_MS): Promise<{ ready: boolean; ms: number }> {
  const t0 = Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const all = Promise.allSettled([warmPythonTaintEngine(), warmGoTaintEngine(), warmCSharpTaintEngine(), warmPhpTaintEngine(), warmRubyTaintEngine(), warmKotlinTaintEngine()])
    .then(results => results.every(r => r.status === "fulfilled"));
  const timeout = new Promise<boolean>(resolve => { timer = setTimeout(() => resolve(false), timeoutMs); });
  try {
    const ready = await Promise.race([all, timeout]);
    return { ready, ms: Date.now() - t0 };
  } finally {
    if (timer) clearTimeout(timer);
  }
}
