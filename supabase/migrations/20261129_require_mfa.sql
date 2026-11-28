-- Organisation-wide two-factor requirement — 2026-11-29
--
-- When on, every member must have two-factor authentication enabled to use the API: a member without it is refused with
-- "mfa_enrollment_required" (except on the pages and calls needed to switch it on) until they enrol. An admin can only turn
-- it on once they have two-factor on themselves, so the setting cannot lock its own author out. platform_admin is exempt
-- (break-glass).
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS require_mfa boolean NOT NULL DEFAULT false;
