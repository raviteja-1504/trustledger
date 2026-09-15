-- Migration: real CWE classification for auto-derived Risk Register entries
--
-- deriveRisks() (src/app/risk-register/page.tsx) was attaching a hardcoded,
-- essentially random well-known CVE to each pattern category it derives a
-- risk from (e.g. eval-exec -> CVE-2021-44228, which is Log4Shell -- a
-- specific Java logging library RCE with zero relation to a generic
-- eval() pattern match). A pattern-based static analysis finding is a
-- weakness CLASS, not a specific exploited software instance, so it can
-- never honestly resolve to a CVE -- but it can honestly resolve to a
-- CWE (Common Weakness Enumeration), which is exactly that taxonomy.
--
-- related_cve is left in place and untouched for MANUALLY-entered risks,
-- where a human typing in a real CVE they're genuinely tracking is a
-- legitimate use case -- only the auto-derivation path stops fabricating
-- one. related_cwe is the new, real, auto-derived classification.
alter table risk_register
  add column if not exists related_cwe text;
