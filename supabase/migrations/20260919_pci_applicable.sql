-- Migration: PCI-DSS applicability flag (compliance overhaul -- scope-honesty follow-up)
--
-- PCI-DSS only applies to organisations that actually have a cardholder
-- data environment (CDE) -- unlike SOC2/EU AI Act/ISO27001, its
-- applicability is conditional on a fact about the org, not something
-- every org should see by default. Previously PCI-DSS was shown to every
-- org unconditionally on the Reports page. This is a real, admin-gated
-- org setting (not a per-device localStorage flag) so every team member
-- sees the same, correct answer for their org.
alter table organizations
  add column if not exists pci_applicable boolean not null default false;
