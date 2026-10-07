/**
 * GET /.well-known/security.txt -- RFC 9116: where to report a vulnerability. Generated per request so the
 * contact comes from NEXT_PUBLIC_SECURITY_CONTACT and Expires is always within the RFC's "less than a year".
 */
import { NextRequest } from "next/server";
import { securityContact } from "@/lib/contacts";

const EXPIRES_DAYS = 180;

/** The site's canonical origin: the configured app URL, not the request's Host header (this file is cached publicly). */
function canonicalOrigin(req: NextRequest): string {
  const configured = (process.env.NEXT_PUBLIC_APP_URL ?? "").trim().replace(/\/+$/, "");
  return /^https?:\/\/[^/\s]+$/.test(configured) ? configured : req.nextUrl.origin;
}

export function GET(req: NextRequest) {
  const origin = canonicalOrigin(req);
  const expires = new Date(Date.now() + EXPIRES_DAYS * 86400_000);
  expires.setUTCHours(0, 0, 0, 0);
  const body = [
    `Contact: mailto:${securityContact()}`,
    `Expires: ${expires.toISOString()}`,
    `Preferred-Languages: en`,
    `Canonical: ${origin}/.well-known/security.txt`,
    `Policy: ${origin}/security`,
    "",
  ].join("\n");
  return new Response(body, {
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=86400" },
  });
}
