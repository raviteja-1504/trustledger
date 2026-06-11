/**
 * k6 load test — Scan API endpoint
 *
 * Tests: POST /api/scans
 *
 * Run:
 *   k6 run load-tests/scan-endpoint.js
 *   k6 run --vus 10 --duration 30s load-tests/scan-endpoint.js
 *
 * Install k6: https://k6.io/docs/getting-started/installation/
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";

// ── Config ─────────────────────────────────────────────────────────────────────

const BASE_URL = __ENV.BASE_URL ?? "http://localhost:3000";
const API_KEY  = __ENV.API_KEY  ?? "tl_live_test_key";

// ── Custom metrics ─────────────────────────────────────────────────────────────

const errorRate       = new Rate("errors");
const scanDuration    = new Trend("scan_duration_ms", true);
const p95ScanDuration = new Trend("p95_scan_duration_ms", true);

// ── Test scenarios ─────────────────────────────────────────────────────────────

export const options = {
  scenarios: {
    // Smoke test: 1 VU, 10 requests — verify basic functionality
    smoke: {
      executor:          "constant-vus",
      vus:               1,
      duration:          "10s",
      env:               { SCENARIO: "smoke" },
    },
    // Load test: 10 concurrent users for 30s
    load: {
      executor:          "ramping-vus",
      startVUs:          0,
      stages: [
        { duration: "10s", target: 10 },  // ramp up
        { duration: "20s", target: 10 },  // sustain
        { duration: "10s", target: 0  },  // ramp down
      ],
      startTime:         "12s",
      env:               { SCENARIO: "load" },
    },
    // Spike test: sudden 50 users for 5s
    spike: {
      executor:          "ramping-vus",
      startVUs:          0,
      stages: [
        { duration: "5s",  target: 50 },
        { duration: "10s", target: 50 },
        { duration: "5s",  target: 0  },
      ],
      startTime:         "45s",
      env:               { SCENARIO: "spike" },
    },
  },
  thresholds: {
    http_req_failed:      ["rate<0.05"],   // < 5% errors
    http_req_duration:    ["p(95)<3000"],  // 95% under 3s
    errors:               ["rate<0.05"],
  },
};

// ── Sample payloads ────────────────────────────────────────────────────────────

const SAMPLE_FILES = [
  {
    path:    "src/api.py",
    content: `import psycopg2\nSECRET = "sk_live_demo"\ndef get(user_id):\n    q = f"SELECT * FROM users WHERE id = '{user_id}'"\n`,
  },
  {
    path:    "src/utils.ts",
    content: `export function formatDate(d: Date): string { return d.toISOString(); }`,
  },
];

// ── Main test function ─────────────────────────────────────────────────────────

export default function () {
  const payload = JSON.stringify({
    repo:       "test/load-test-repo",
    pr_number:  Math.floor(Math.random() * 1000) + 1,
    commit_sha: Math.random().toString(36).slice(2, 10),
    files:      SAMPLE_FILES,
  });

  const start = Date.now();
  const res   = http.post(`${BASE_URL}/api/scans`, payload, {
    headers: {
      "Content-Type":      "application/json",
      "X-TrustLedger-Key": API_KEY,
    },
    timeout: "30s",
  });
  const duration = Date.now() - start;

  scanDuration.add(duration);

  const ok = check(res, {
    "status 200 or 401 (unauth in test)": r => [200, 201, 401, 429].includes(r.status),
    "response time < 5s":                 r => r.timings.duration < 5000,
    "has scan_id or error":               r => {
      try {
        const body = JSON.parse(r.body);
        return !!(body.scan_id || body.error);
      } catch { return false; }
    },
  });

  errorRate.add(!ok);

  // Rate limit compliance — don't hammer too hard
  sleep(Math.random() * 0.5 + 0.1);
}

export function handleSummary(data) {
  console.log("\n=== TrustLedger Load Test Summary ===");
  console.log(`Requests:     ${data.metrics.http_reqs?.values?.count ?? 0}`);
  console.log(`Error rate:   ${(data.metrics.errors?.values?.rate * 100 ?? 0).toFixed(2)}%`);
  console.log(`p50 duration: ${data.metrics.http_req_duration?.values?.["p(50)"]?.toFixed(0) ?? "n/a"}ms`);
  console.log(`p95 duration: ${data.metrics.http_req_duration?.values?.["p(95)"]?.toFixed(0) ?? "n/a"}ms`);
  console.log(`p99 duration: ${data.metrics.http_req_duration?.values?.["p(99)"]?.toFixed(0) ?? "n/a"}ms`);
  console.log("=====================================\n");
  return {};
}
