/**
 * k6 load test — Dashboard + read API endpoints
 *
 * Tests: GET /api/dashboard, GET /api/violations, GET /healthz
 *
 * Run:
 *   k6 run load-tests/dashboard-api.js
 *   k6 run --vus 20 --duration 60s load-tests/dashboard-api.js
 */

import http from "k6/http";
import { check, group, sleep } from "k6";

const BASE_URL = __ENV.BASE_URL ?? "http://localhost:3000";
const API_KEY  = __ENV.API_KEY  ?? "tl_live_test_key";

const HEADERS = {
  "X-TrustLedger-Key": API_KEY,
  "Accept":            "application/json",
};

export const options = {
  vus:        20,
  duration:   "60s",
  thresholds: {
    "http_req_duration{endpoint:healthz}":    ["p(95)<200"],   // health check must be fast
    "http_req_duration{endpoint:dashboard}":  ["p(95)<2000"],  // dashboard < 2s
    "http_req_duration{endpoint:violations}": ["p(95)<1000"],  // violations < 1s
    http_req_failed:                          ["rate<0.01"],   // < 1% errors
  },
};

export default function () {
  group("Health check", () => {
    const r = http.get(`${BASE_URL}/healthz`, { tags: { endpoint: "healthz" } });
    check(r, { "healthz 200": res => res.status === 200 });
  });

  sleep(0.1);

  group("Dashboard API", () => {
    const r = http.get(`${BASE_URL}/api/dashboard?days=30`, {
      headers: HEADERS,
      tags:    { endpoint: "dashboard" },
    });
    check(r, {
      "dashboard 200 or 401": res => [200, 401].includes(res.status),
      "dashboard < 2s":       res => res.timings.duration < 2000,
    });
  });

  sleep(0.1);

  group("Violations API", () => {
    const r = http.get(`${BASE_URL}/api/violations?status=open&limit=50`, {
      headers: HEADERS,
      tags:    { endpoint: "violations" },
    });
    check(r, {
      "violations 200 or 401": res => [200, 401].includes(res.status),
    });
  });

  sleep(Math.random() * 1 + 0.2);
}
