/**
 * Every email address the site publishes for people to write to (contact, privacy, sales, support, updates,
 * security), in one place.
 *
 * They are `<role>@<domain>`. Set NEXT_PUBLIC_CONTACT_DOMAIN to the real domain (e.g. `acme.com`) to switch them
 * all; NEXT_PUBLIC_SECURITY_CONTACT can still override the security address alone. Until then the domain is the
 * reserved `trustledger.example` (RFC 2606): mail there can never be delivered, so messages are lost -- but they
 * also can never reach a stranger, which a made-up real-looking domain could (trustledger.dev is someone
 * else's domain).
 */
export const PLACEHOLDER_CONTACT_DOMAIN = "trustledger.example";
export const PLACEHOLDER_SECURITY_CONTACT = `security@${PLACEHOLDER_CONTACT_DOMAIN}`;

export type ContactRole = "hello" | "privacy" | "sales" | "support" | "updates" | "security";

const DOMAIN_RE = /^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;
const EMAIL_RE = /^[^\s@<>"]+@[^\s@<>"]+\.[A-Za-z]{2,}$/;

/** The published contact domain: NEXT_PUBLIC_CONTACT_DOMAIN when it is a valid domain, else the placeholder. */
export function contactDomain(): string {
  const v = (process.env.NEXT_PUBLIC_CONTACT_DOMAIN ?? "").trim().replace(/^@/, "").toLowerCase();
  return DOMAIN_RE.test(v) ? v : PLACEHOLDER_CONTACT_DOMAIN;
}

/** The published address for one role, e.g. contactEmail("privacy") → privacy@<domain>. */
export function contactEmail(role: ContactRole): string {
  if (role === "security") return securityContact();
  return `${role}@${contactDomain()}`;
}

/** Where vulnerabilities and incidents are reported: NEXT_PUBLIC_SECURITY_CONTACT, else security@<domain>. */
export function securityContact(): string {
  const v = (process.env.NEXT_PUBLIC_SECURITY_CONTACT ?? "").trim();
  return EMAIL_RE.test(v) ? v : `security@${contactDomain()}`;
}

export function isPlaceholderSecurityContact(): boolean {
  return securityContact() === PLACEHOLDER_SECURITY_CONTACT;
}

/** First response to a report, in business days -- the same promise on /security and in SECURITY.md. */
export const SECURITY_ACK_BUSINESS_DAYS = 3;
