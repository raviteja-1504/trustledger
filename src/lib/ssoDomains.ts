/**
 * Email domains an org claims for SSO, and proof that it owns them.
 *
 * A verified domain decides two things: which identity provider "Sign in with SSO" sends a work email to,
 * and which asserted emails that provider may sign in (an IdP can assert ANY email, so an org's IdP is only
 * trusted for addresses at domains the org has proved it controls -- see ssoMembership.ts). Ownership is
 * proved with a DNS TXT record, the same way Google Workspace / Okta / Slack do it.
 */
import { randomBytes } from "crypto";
import { promises as dns } from "dns";

/** Consumer mailbox providers: nobody can own these for SSO. */
export const PUBLIC_EMAIL_DOMAINS = new Set([
  "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com",
  "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net",
  "mail.com", "zoho.com", "yandex.com", "yandex.ru", "qq.com", "163.com", "126.com", "fastmail.com", "hey.com",
  "tutanota.com", "rediffmail.com",
]);

const DOMAIN_RE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** "@Acme.COM", "https://acme.com/", " acme.com " → "acme.com"; null if it isn't a plain domain name. */
export function normalizeDomain(input: string): string | null {
  const d = input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^@/, "").replace(/\/.*$/, "").replace(/\.$/, "");
  return DOMAIN_RE.test(d) ? d : null;
}

/** Why a domain can't be claimed, or null if it can. */
export function domainClaimError(input: string): "invalid_domain" | "public_email_domain" | null {
  const d = normalizeDomain(input);
  if (!d) return "invalid_domain";
  if (PUBLIC_EMAIL_DOMAINS.has(d)) return "public_email_domain";
  return null;
}

/** The part after @, lower-cased; null for anything that isn't an address. */
export function emailDomain(email: string | null | undefined): string | null {
  const m = /^[^@\s]+@([^@\s]+)$/.exec((email ?? "").trim());
  return m ? normalizeDomain(m[1]) : null;
}

/** True if the email's domain is one of `domains` (exact match -- a subdomain is a different domain). */
export function emailInDomains(email: string | null | undefined, domains: string[]): boolean {
  const d = emailDomain(email);
  return !!d && domains.includes(d);
}

export function newVerificationToken(): string {
  return randomBytes(18).toString("base64url");
}

/** The TXT record the org adds to prove ownership. */
export function verificationRecord(domain: string, token: string): { name: string; value: string } {
  return { name: `_trustledger-challenge.${domain}`, value: `trustledger-domain-verification=${token}` };
}

type ResolveTxt = (hostname: string) => Promise<string[][]>;

/** Whether the domain's challenge record carries this token. DNS failures (NXDOMAIN etc.) count as "not yet". */
export async function checkDomainTxt(domain: string, token: string, resolveTxt: ResolveTxt = dns.resolveTxt): Promise<boolean> {
  const { name, value } = verificationRecord(domain, token);
  try {
    const records = await resolveTxt(name);
    // A long TXT value can arrive split into chunks; each record is the chunks joined.
    return records.some(chunks => chunks.join("").trim() === value);
  } catch {
    return false;
  }
}
