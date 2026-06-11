// Auto-generated Supabase type stubs — replace with `supabase gen types typescript`
// after connecting your project.
export type Json = string | number | boolean | null | { [key: string]: Json } | Json[];

export interface Database {
  public: {
    Tables: {
      organizations: {
        Row: {
          id: string; slug: string; name: string; github_org: string | null;
          plan: string; ai_threshold: number; attest_sla_hours: number;
          block_on_critical: boolean; block_on_high: boolean;
          require_two_reviewers: boolean; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["organizations"]["Row"], "id"|"created_at"> & { id?: string };
        Update: Partial<Database["public"]["Tables"]["organizations"]["Insert"]>;
      };
      org_members: {
        Row: {
          id: string; org_id: string; user_id: string; email: string; name: string | null;
          role: string; github_login: string | null; avatar_url: string | null; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["org_members"]["Row"], "id"|"created_at"> & { id?: string };
        Update: Partial<Database["public"]["Tables"]["org_members"]["Insert"]>;
      };
      repositories: {
        Row: {
          id: string; org_id: string; repo_full_name: string; default_branch: string;
          github_repo_id: number | null; is_active: boolean; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["repositories"]["Row"], "id"|"created_at"> & { id?: string };
        Update: Partial<Database["public"]["Tables"]["repositories"]["Insert"]>;
      };
      scans: {
        Row: {
          id: string; org_id: string; repo_id: string | null; repo_full_name: string;
          pr_number: number | null; commit_sha: string; branch: string | null;
          overall_risk: string; total_ai_percentage: number; file_count: number;
          triggered_by: string; duration_ms: number | null; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["scans"]["Row"], "id"|"created_at"> & { id?: string };
        Update: Partial<Database["public"]["Tables"]["scans"]["Insert"]>;
      };
      scan_files: {
        Row: {
          id: string; scan_id: string; org_id: string; file_path: string;
          language: string | null; ai_percentage: number; risk_score: string;
          risk_indicators: string[]; content_hash: string | null; line_count: number | null;
          created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["scan_files"]["Row"], "id"|"created_at"> & { id?: string };
        Update: Partial<Database["public"]["Tables"]["scan_files"]["Insert"]>;
      };
      attestations: {
        Row: {
          id: string; org_id: string; scan_id: string; file_path: string;
          risk_score: string; reviewer_id: string | null; reviewer_email: string;
          reviewer_github: string | null; payload_hash: string; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["attestations"]["Row"], "id"|"created_at"> & { id?: string };
        Update: never; // immutable
      };
      violations: {
        Row: {
          id: string; org_id: string; scan_id: string; file_path: string;
          risk_score: string; status: string; assigned_to: string | null;
          assigned_email: string | null; notes: Json; escalated: boolean;
          sla_deadline: string | null; resolved_at: string | null;
          resolved_by: string | null; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["violations"]["Row"], "id"|"created_at"> & { id?: string };
        Update: Partial<Database["public"]["Tables"]["violations"]["Insert"]>;
      };
      secret_findings: {
        Row: {
          id: string; org_id: string; scan_id: string; file_path: string;
          secret_type: string; severity: string; label: string; masked_value: string;
          line_number: number | null; status: string; resolved_by: string | null;
          resolved_email: string | null; resolved_at: string | null; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["secret_findings"]["Row"], "id"|"created_at"> & { id?: string };
        Update: Partial<Database["public"]["Tables"]["secret_findings"]["Insert"]>;
      };
      incidents: {
        Row: {
          id: string; org_id: string; title: string; description: string | null;
          severity: string; status: string; incident_type: string;
          affected_repo: string | null; affected_file: string | null;
          impact: string | null; root_cause: string | null; lesson_learned: string | null;
          timeline: Json; stakeholders: Json; playbook: Json; related_cve: string | null;
          detected_at: string; contained_at: string | null; resolved_at: string | null;
          created_by: string | null; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["incidents"]["Row"], "id"|"created_at"> & { id?: string };
        Update: Partial<Database["public"]["Tables"]["incidents"]["Insert"]>;
      };
      alerts: {
        Row: {
          id: string; org_id: string; alert_type: string; severity: string;
          status: string; title: string; body: string | null; repo: string | null;
          scan_id: string | null; runbook_url: string | null; escalation_emails: string[] | null;
          acknowledged_by: string | null; acknowledged_at: string | null;
          snooze_until: string | null; resolved_at: string | null; notes: Json;
          fired_at: string; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["alerts"]["Row"], "id"|"created_at"> & { id?: string };
        Update: Partial<Database["public"]["Tables"]["alerts"]["Insert"]>;
      };
      audit_log: {
        Row: {
          id: number; org_id: string; event_type: string; actor_id: string | null;
          actor_email: string | null; resource_type: string | null; resource_id: string | null;
          payload: Json; prev_hash: string | null; entry_hash: string; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["audit_log"]["Row"], "id"|"created_at"> & { id?: number };
        Update: never; // immutable
      };
      api_keys: {
        Row: {
          id: string; org_id: string; name: string; key_hash: string; key_prefix: string;
          created_by: string | null; last_used: string | null; expires_at: string | null;
          revoked: boolean; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["api_keys"]["Row"], "id"|"created_at"> & { id?: string };
        Update: Partial<Database["public"]["Tables"]["api_keys"]["Insert"]>;
      };
      webhook_deliveries: {
        Row: {
          id: string; org_id: string | null; source: string; event_type: string;
          payload: Json; signature_ok: boolean; processed: boolean;
          scan_id: string | null; error: string | null; created_at: string;
        };
        Insert: Omit<Database["public"]["Tables"]["webhook_deliveries"]["Row"], "id"|"created_at"> & { id?: string };
        Update: Partial<Database["public"]["Tables"]["webhook_deliveries"]["Insert"]>;
      };
    };
    Views: Record<string, never>;
    Functions: Record<string, never>;
    Enums: Record<string, never>;
  };
}
