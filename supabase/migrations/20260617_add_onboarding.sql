-- Phase 3: onboarding wizard
-- Track whether an org has completed the setup wizard so new orgs can be
-- redirected to /onboarding on first login.

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS onboarding_complete boolean NOT NULL DEFAULT false;

-- Existing orgs are already set up — mark them complete so they don't get
-- redirected back to the wizard.
UPDATE organizations SET onboarding_complete = true WHERE onboarding_complete = false;
