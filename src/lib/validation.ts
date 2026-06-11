/**
 * Input validation schemas using Zod.
 * Used in all API routes to validate request bodies before processing.
 * Returns typed, parsed data — never trust raw request body.
 */

import { z } from "zod";
import { NextRequest, NextResponse } from "next/server";

// ── Reusable field schemas ────────────────────────────────────────────────────

export const uuidSchema   = z.string().uuid("Must be a valid UUID");
export const emailSchema  = z.string().email("Must be a valid email").max(255);
export const urlSchema    = z.string().url("Must be a valid URL").max(2048);
export const semverSchema = z.string().regex(/^\d+\.\d+\.\d+$/, "Must be semver (e.g. 1.2.3)");

const RISK_LEVELS    = ["LOW","MEDIUM","HIGH","CRITICAL","UNKNOWN"] as const;
const SEVERITIES_P   = ["P1","P2","P3","P4"] as const;
const PLAN_NAMES     = ["trial","starter","growth","enterprise"] as const;

// ── API request schemas ───────────────────────────────────────────────────────

export const ScanFileSchema = z.object({
  path:         z.string().min(1).max(500),
  content:      z.string().max(500_000), // 500KB max per file
  _local_result:z.object({
    ai_percentage:   z.number().min(0).max(1),
    risk_score:      z.enum(RISK_LEVELS),
    risk_indicators: z.array(z.string()),
    content_hash:    z.string(),
    line_count:      z.number().int().nonnegative(),
    language:        z.string(),
  }).optional(),
});

export const CreateScanSchema = z.object({
  repo:       z.string().min(1).max(200).regex(/^[\w.-]+\/[\w.-]+$/, "Must be owner/repo format"),
  pr_number:  z.number().int().nonnegative().max(999999),
  commit_sha: z.string().min(6).max(64).regex(/^[a-f0-9]+$/i, "Must be a hex commit SHA"),
  branch:     z.string().max(200).optional(),
  local_scan: z.boolean().optional(),
  files:      z.array(ScanFileSchema).min(1).max(50),
});

export const AttestSchema = z.object({
  scan_id:         uuidSchema,
  file_path:       z.string().min(1).max(500),
  reviewer_email:  emailSchema,
  reviewer_github: z.string().max(100).optional(),
});

export const ViolationUpdateSchema = z.object({
  id:             uuidSchema,
  status:         z.enum(["open","in_review","resolved","accepted"]),
  assigned_email: emailSchema.optional(),
  note:           z.string().max(2000).optional(),
});

export const AlertUpdateSchema = z.object({
  id:            uuidSchema,
  status:        z.enum(["firing","acknowledged","snoozed","resolved"]),
  snooze_hours:  z.number().int().min(1).max(168).optional(),
  note:          z.string().max(1000).optional(),
});

export const CreateAlertSchema = z.object({
  alert_type:        z.string().max(100),
  severity:          z.enum(SEVERITIES_P),
  title:             z.string().min(1).max(500),
  body_text:         z.string().max(5000).optional(),
  repo:              z.string().max(200).optional(),
  scan_id:           uuidSchema.optional(),
  runbook_url:       urlSchema.optional(),
  escalation_emails: z.array(emailSchema).max(10).optional(),
  deliver:           z.boolean().default(false),
});

export const OrgSettingsSchema = z.object({
  name:                  z.string().min(1).max(100).optional(),
  github_org:            z.string().max(100).optional(),
  ai_threshold:          z.number().min(0).max(1).optional(),
  attest_sla_hours:      z.number().int().min(1).max(8760).optional(),
  block_on_critical:     z.boolean().optional(),
  block_on_high:         z.boolean().optional(),
  require_two_reviewers: z.boolean().optional(),
});

export const CreateIncidentSchema = z.object({
  title:          z.string().min(1).max(500),
  description:    z.string().max(10000).optional(),
  severity:       z.enum(SEVERITIES_P),
  incident_type:  z.string().max(100),
  affected_repo:  z.string().max(200).optional(),
  affected_file:  z.string().max(500).optional(),
  stakeholders:   z.array(emailSchema).max(20).optional(),
});

export const CreateApiKeySchema = z.object({
  name:         z.string().min(1).max(100),
  expires_days: z.number().int().min(1).max(3650).optional(),
});

export const WebhookConfigSchema = z.object({
  url:     urlSchema,
  secret:  z.string().max(200).optional(),
  events:  z.array(z.string()).max(20).optional(),
  id:      uuidSchema.optional(),
  enabled: z.boolean().optional(),
});

// ── Validation helper ─────────────────────────────────────────────────────────

type ValidationResult<T> =
  | { ok: true;  data: T }
  | { ok: false; response: NextResponse };

export async function validateBody<T>(
  req: NextRequest,
  schema: z.ZodSchema<T>,
): Promise<ValidationResult<T>> {
  let raw: unknown;
  try {
    raw = await req.json();
  } catch {
    return {
      ok:       false,
      response: NextResponse.json({ error:"invalid_json", detail:"Request body must be valid JSON" }, { status:400 }),
    };
  }

  const result = schema.safeParse(raw);
  if (!result.success) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const issues = (result.error as any).issues ?? (result.error as any).errors ?? [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const errors = issues.map((e: any) => ({
      field:   (e.path ?? []).join("."),
      message: e.message ?? "Invalid value",
    }));
    return {
      ok:       false,
      response: NextResponse.json({ error:"validation_error", details: errors }, { status:400 }),
    };
  }

  return { ok: true, data: result.data };
}

/** Validate query parameters from a URL. */
export function validateQuery<T>(
  url: URL,
  schema: z.ZodSchema<T>,
): ValidationResult<T> {
  const params = Object.fromEntries(url.searchParams.entries());
  const result = schema.safeParse(params);
  if (!result.success) {
    return {
      ok:       false,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      response: NextResponse.json({ error:"invalid_query_params", details: (result.error as any).issues ?? [] }, { status:400 }),
    };
  }
  return { ok: true, data: result.data };
}
