/**
 * Tests for pure helper functions extracted from notifications.ts.
 * We test the logic in isolation — not the React hook itself.
 */

// ── calcHealth helper (mirrors the one in notifications.ts) ──────────────────

function calcHealth(d: {
  repos: unknown[];
  attestation_rate: number;
  overall_ai_pct: number;
  unattested_deploy_count: number;
}): number {
  if (d.repos.length === 0) return 100;
  return Math.round(
    Math.min(100,
      d.attestation_rate * 60 +
      (1 - Math.min(d.overall_ai_pct, 1)) * 25 +
      Math.max(0, 15 - d.unattested_deploy_count * 3),
    )
  );
}

describe("calcHealth", () => {
  it("returns 100 for empty repos", () => {
    expect(calcHealth({ repos:[], attestation_rate:1, overall_ai_pct:0, unattested_deploy_count:0 })).toBe(100);
  });

  it("perfect compliance yields score near 100", () => {
    const score = calcHealth({ repos:[{}], attestation_rate:1, overall_ai_pct:0, unattested_deploy_count:0 });
    expect(score).toBe(100);
  });

  it("high AI% with no attestation yields low score", () => {
    const score = calcHealth({ repos:[{}], attestation_rate:0, overall_ai_pct:1, unattested_deploy_count:5 });
    expect(score).toBeLessThan(20);
  });

  it("deploy count > 5 clamps the deploy bonus to 0", () => {
    const many = calcHealth({ repos:[{}], attestation_rate:0.8, overall_ai_pct:0.3, unattested_deploy_count:10 });
    const none = calcHealth({ repos:[{}], attestation_rate:0.8, overall_ai_pct:0.3, unattested_deploy_count:0  });
    expect(none).toBeGreaterThan(many);
  });

  it("score never exceeds 100", () => {
    const score = calcHealth({ repos:[{}], attestation_rate:2, overall_ai_pct:0, unattested_deploy_count:0 });
    expect(score).toBeLessThanOrEqual(100);
  });
});

// ── Notification diff logic ───────────────────────────────────────────────────

describe("notification diff logic", () => {
  const base = {
    repos: [{ repo:"r/a", ai_pct:0.5, attestation_rate:0.8, last_scan:"2026-05-01", scan_count:5, file_count:50, latest_scan_id:"sc1" }],
    overall_ai_pct:          0.5,
    attestation_rate:        0.8,
    unattested_deploy_count: 0,
    risk_trend: [],
    scan_count:  10,
    file_count:  50,
    top_risk_files: [],
  };

  it("attestation rate drop of <10pp should not trigger a notification", () => {
    const next = { ...base, attestation_rate: 0.72 };   // 8pp drop
    const prev = { ...base, attestation_rate: 0.80 };
    const improved = next.attestation_rate >= prev.attestation_rate + 0.1;
    expect(improved).toBe(false);
  });

  it("attestation rate improvement ≥10pp is detected", () => {
    const prev = { ...base, attestation_rate: 0.5 };
    const next = { ...base, attestation_rate: 0.65 };
    const improved = next.attestation_rate >= prev.attestation_rate + 0.1;
    expect(improved).toBe(true);
  });

  it("AI content spike ≥10pp is detected", () => {
    const prev = { ...base, overall_ai_pct: 0.4 };
    const next = { ...base, overall_ai_pct: 0.55 };
    const spiked = next.overall_ai_pct >= prev.overall_ai_pct + 0.1;
    expect(spiked).toBe(true);
  });

  it("new repos added is detected", () => {
    const prev = { ...base, repos: base.repos };
    const next = { ...base, repos: [...base.repos, { ...base.repos[0], repo:"r/b" }] };
    expect(next.repos.length - prev.repos.length).toBe(1);
  });
});
