/**
 * TrustLedger API client
 * Calls our own Next.js API routes (which connect to Supabase).
 * Falls back to seed/offline data when NEXT_PUBLIC_SKIP_AUTH=true.
 */

import type {
  DashboardData, StatusResponse, ScanResult,
  ScanRequest, AttestRequest, AttestResponse, ActivityResponse,
} from "@/types";
import { supabase } from "./supabase";

// ── Auth token helper ──────────────────────────────────────────────────────────

async function getToken(): Promise<string | null> {
  if (typeof window === "undefined") return null;
  if (process.env.NEXT_PUBLIC_SKIP_AUTH === "true") return null;
  const { data: { session } } = await supabase.auth.getSession();
  return session?.access_token ?? null;
}

// ── Internal fetch wrapper ─────────────────────────────────────────────────────

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const token = await getToken();
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as { error?: string };
    throw new Error(body.error ?? `${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

// ── API surface ────────────────────────────────────────────────────────────────

export const api = {
  dashboard: (org: string, days = 90, startDate?: string, endDate?: string): Promise<DashboardData> => {
    const p = new URLSearchParams({ org });
    if (startDate && endDate) { p.set("start_date", startDate); p.set("end_date", endDate); }
    else p.set("days", String(days));
    return apiFetch<DashboardData>(`/api/dashboard?${p.toString()}`);
  },

  getScan: (scanId: string): Promise<ScanResult> =>
    apiFetch<ScanResult>(`/api/scans/${encodeURIComponent(scanId)}`),

  settings: () =>
    apiFetch<{ members: Array<{ email: string; name?: string; role: string }> }>("/api/settings"),

  scan: (body: ScanRequest): Promise<ScanResult> =>
    apiFetch<ScanResult>("/api/scans", { method: "POST", body: JSON.stringify(body) }),

  attest: (body: AttestRequest): Promise<AttestResponse> =>
    apiFetch<AttestResponse>("/api/attest", { method: "POST", body: JSON.stringify(body) }),

  status: (repo: string, commitSha: string): Promise<StatusResponse> =>
    apiFetch<StatusResponse>(`/api/status?repo=${encodeURIComponent(repo)}&commit_sha=${encodeURIComponent(commitSha)}`),

  violations: (params?: { status?: string; repo?: string; limit?: number }) => {
    const p = new URLSearchParams();
    if (params?.status) p.set("status", params.status);
    if (params?.repo)   p.set("repo", params.repo);
    if (params?.limit)  p.set("limit", String(params.limit));
    return apiFetch<{ violations: unknown[] }>(`/api/violations?${p.toString()}`);
  },

  resolveViolation: (id: string, status: string, note?: string) =>
    apiFetch("/api/violations", {
      method: "PATCH",
      body: JSON.stringify({ id, status, note }),
    }),

  auditLog: (page = 0, limit = 100) =>
    apiFetch<{ events: unknown[]; total: number }>(`/api/audit?page=${page}&limit=${limit}`),

  verifyAuditChain: () =>
    apiFetch<{ valid: boolean; broken_at?: number; total: number }>("/api/audit", { method: "POST" }),

  apiKeys: {
    list: ()                           => apiFetch<{ keys: unknown[] }>("/api/keys"),
    create: (name: string, expireDays?: number) =>
      apiFetch<{ id: string; raw_key: string; key_prefix: string }>("/api/keys", {
        method: "POST", body: JSON.stringify({ name, expires_days: expireDays }),
      }),
    revoke: (id: string) =>
      apiFetch("/api/keys", { method: "DELETE", body: JSON.stringify({ id }) }),
  },

  // Legacy — kept for backward compat during migration
  repoScans: async (repo: string): Promise<ScanResult[]> => {
    const json = await apiFetch<{ scans: Array<{
      scan_id: string; repo: string; pr_number: number; commit_sha: string;
      branch?: string; overall_risk: ScanResult["overall_risk"]; total_ai_percentage: number;
      file_count?: number; attested_count?: number; triggered_by?: string; created_at: string;
    }> }>(`/api/scans?repo=${encodeURIComponent(repo)}`);
    return (json.scans ?? []).map(s => ({
      scan_id:             s.scan_id,
      repo:                s.repo,
      pr_number:           s.pr_number,
      commit_sha:          s.commit_sha,
      branch:              s.branch,
      files:               [],
      overall_risk:        s.overall_risk,
      total_ai_percentage: s.total_ai_percentage,
      file_count:          s.file_count,
      attested_count:      s.attested_count,
      triggered_by:        s.triggered_by,
      timestamp:           s.created_at,
    }));
  },

  activity: (_org: string, _limit = 20): Promise<ActivityResponse> =>
    apiFetch<ActivityResponse>("/api/activity"),

  vulnCatalog: () =>
    apiFetch<{ catalog: Record<string, unknown> }>("/api/vuln-catalog"),

  threatCatalog: () =>
    apiFetch<{ threats: unknown[] }>("/api/threat-catalog"),

  complianceConfig: (org: string) =>
    apiFetch<{ frameworks: unknown[]; crossFrameworkThemes: unknown[] }>(
      `/api/compliance-config?org=${encodeURIComponent(org)}`,
    ),

  auditConfig: (org: string) =>
    apiFetch<{ eventConfig: unknown; eventSoc2: unknown }>(
      `/api/audit-config?org=${encodeURIComponent(org)}`,
    ),

  generateReport: (body: { org: string; period_start: string; period_end: string; framework: string }): Promise<Response> =>
    getToken().then(token =>
      fetch("/api/report", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
      }).then(res => {
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
        return res;
      })
    ),
};
