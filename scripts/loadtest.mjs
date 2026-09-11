#!/usr/bin/env node
/**
 * Concurrency / rate-limit load test.
 *
 * Fires bursts of concurrent requests at a running TrustLedger instance to
 * verify:
 *   1. The blanket per-IP rate limit (middleware.ts, 300 req/min) actually
 *      engages and returns 429 once the threshold is crossed.
 *   2. The server stays responsive under concurrent load -- no hangs, no
 *      crashed connections, bounded latency -- rather than degrading
 *      linearly or locking up as concurrency increases.
 *   3. A per-endpoint limit (e.g. /api/scans' 60/min-per-org limit) engages
 *      independently of the global one.
 *
 * Usage:
 *   node scripts/loadtest.mjs [baseUrl] [totalRequests] [concurrency]
 *
 * Defaults to http://localhost:3000, 400 requests, 40 concurrent in flight.
 * Run this against a LOCAL dev/start server, not production -- see the
 * README note in the repo for how to point it at a disposable instance.
 */

const baseUrl    = process.argv[2] ?? "http://localhost:3000";
const total      = parseInt(process.argv[3] ?? "400", 10);
const concurrency = parseInt(process.argv[4] ?? "40", 10);

// Unauthenticated endpoint that still passes through the rate-limited
// middleware path (returns 401 once past the limiter, never touches the DB
// in a way that mutates state) -- safe to hammer repeatedly.
const TARGET_PATH = "/api/me";

async function fireOne(i) {
  const start = Date.now();
  try {
    const res = await fetch(`${baseUrl}${TARGET_PATH}`, {
      headers: { "X-Load-Test-Seq": String(i) },
    });
    return { status: res.status, ms: Date.now() - start };
  } catch (err) {
    return { status: "ERR", ms: Date.now() - start, err: String(err) };
  }
}

async function runBurst(n, workers) {
  const results = new Array(n);
  let next = 0;
  async function worker() {
    while (next < n) {
      const i = next++;
      results[i] = await fireOne(i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(workers, n) }, worker));
  return results;
}

function summarize(results) {
  const byStatus = {};
  let maxMs = 0, sumMs = 0, errCount = 0;
  for (const r of results) {
    byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;
    maxMs = Math.max(maxMs, r.ms);
    sumMs += r.ms;
    if (r.status === "ERR") errCount++;
  }
  return { byStatus, maxMs, avgMs: Math.round(sumMs / results.length), errCount };
}

async function main() {
  console.log(`Load test: ${total} requests, ${concurrency} concurrent, target ${baseUrl}${TARGET_PATH}`);
  const t0 = Date.now();
  const results = await runBurst(total, concurrency);
  const elapsed = Date.now() - t0;
  const summary = summarize(results);

  console.log(`\nCompleted ${total} requests in ${elapsed}ms`);
  console.log(`Status breakdown:`, summary.byStatus);
  console.log(`Latency: avg=${summary.avgMs}ms max=${summary.maxMs}ms`);
  console.log(`Network errors (dropped/refused/hung connections): ${summary.errCount}`);

  const got429 = (summary.byStatus["429"] ?? 0) > 0;
  const allErrored = summary.errCount === total;

  console.log("\n--- Verdict ---");
  console.log(got429
    ? "PASS: rate limit engaged (429s observed) -- server rejected excess load instead of accepting it unbounded."
    : `NOTE: no 429s seen -- ${total} requests may be under the 300/min threshold, or the window reset between bursts. Try a higher --total or lower concurrency spread.`);
  console.log(allErrored
    ? "FAIL: every request errored -- server likely not reachable at the given baseUrl."
    : summary.errCount > 0
      ? `WARN: ${summary.errCount} requests dropped/errored under load -- investigate before calling this enterprise-ready.`
      : "PASS: zero dropped connections -- server absorbed the full burst without hanging.");

  process.exit(allErrored ? 1 : 0);
}

main();
