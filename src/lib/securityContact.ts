/**
 * Where security researchers and customers report vulnerabilities and incidents. Published in
 * /.well-known/security.txt, on /security and in SECURITY.md.
 *
 * Set NEXT_PUBLIC_SECURITY_CONTACT to the real mailbox. Until then this is a placeholder on the reserved
 * `.example` domain (RFC 2606): it can never deliver mail, so reports are lost -- but it also can never reach
 * a stranger, which a made-up real-looking domain could.
 */
export const PLACEHOLDER_SECURITY_CONTACT = "security@trustledger.example";

export function securityContact(): string {
  const v = (process.env.NEXT_PUBLIC_SECURITY_CONTACT ?? "").trim();
  return /^[^\s@<>"]+@[^\s@<>"]+\.[A-Za-z]{2,}$/.test(v) ? v : PLACEHOLDER_SECURITY_CONTACT;
}

export function isPlaceholderSecurityContact(): boolean {
  return securityContact() === PLACEHOLDER_SECURITY_CONTACT;
}

/** First response to a report, in business days -- the same promise on /security and in SECURITY.md. */
export const SECURITY_ACK_BUSINESS_DAYS = 3;
