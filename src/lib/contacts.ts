/**
 * Every email address the site publishes for people to write to (contact, privacy, sales, support, updates,
 * security), in one place.
 *
 * Today they are all one mailbox, PRIMARY_CONTACT: sales enquiries, support, privacy requests and security reports
 * all reach it. When the company has its own domain, set NEXT_PUBLIC_CONTACT_DOMAIN (e.g. `acme.com`) and each role
 * becomes `<role>@<domain>` instead; NEXT_PUBLIC_SECURITY_CONTACT can still override the security address alone.
 * (trustledger.dev is someone else's domain: never publish an address there.)
 */
export const PRIMARY_CONTACT = "trustledgerapp.dev@gmail.com";

export type ContactRole = "hello" | "privacy" | "sales" | "support" | "updates" | "security";

const DOMAIN_RE = /^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;
const EMAIL_RE = /^[^\s@<>"]+@[^\s@<>"]+\.[A-Za-z]{2,}$/;

/** The company's own contact domain: NEXT_PUBLIC_CONTACT_DOMAIN when it is a valid domain, else null (no domain yet). */
export function contactDomain(): string | null {
  const v = (process.env.NEXT_PUBLIC_CONTACT_DOMAIN ?? "").trim().replace(/^@/, "").toLowerCase();
  return DOMAIN_RE.test(v) ? v : null;
}

/** The published address for one role: <role>@<domain> once a domain is set, else the one primary mailbox. */
export function contactEmail(role: ContactRole): string {
  if (role === "security") return securityContact();
  const domain = contactDomain();
  return domain ? `${role}@${domain}` : PRIMARY_CONTACT;
}

/** Where vulnerabilities and incidents are reported: NEXT_PUBLIC_SECURITY_CONTACT, else security@<domain>, else the primary mailbox. */
export function securityContact(): string {
  const v = (process.env.NEXT_PUBLIC_SECURITY_CONTACT ?? "").trim();
  if (EMAIL_RE.test(v)) return v;
  const domain = contactDomain();
  return domain ? `security@${domain}` : PRIMARY_CONTACT;
}

/** First response to a report, in business days -- the same promise on /security and in SECURITY.md. */
export const SECURITY_ACK_BUSINESS_DAYS = 3;
