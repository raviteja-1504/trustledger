/**
 * Indicator IDs that represent a detected secret, shared between the
 * Secrets page (full findings list) and the Sidebar (live badge count) so
 * both agree on exactly what counts as a "secret" without duplicating the
 * literal set in two places and risking drift.
 */
export const SECRET_INDICATOR_IDS = new Set(["hardcoded-secret", "high-entropy-secret"]);
