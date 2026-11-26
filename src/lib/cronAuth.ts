/**
 * Who may call a cron endpoint: the caller must present `Authorization: Bearer <CRON_SECRET>` (Vercel Cron sends it
 * automatically when CRON_SECRET is set; anything else that schedules these routes must send it too).
 *
 * Fails closed. Comparing against `Bearer ${process.env.CRON_SECRET}` is wrong when the variable is missing: the expected
 * value becomes the literal "Bearer undefined", which any caller can send, and these routes run with the service-role
 * database client (retention enforcement, audit checkpoints, outbound email). With no secret configured, nobody gets in.
 *
 * Server-only (node:crypto).
 */
import crypto from "node:crypto";

/** The configured secret, trimmed (a stray newline from piping a value into a hosting dashboard must not lock the cron out), or null. */
function cronSecret(): string | null {
  const s = (process.env.CRON_SECRET ?? "").replace(/^﻿/, "").trim();
  return s.length > 0 ? s : null;
}

/** True only when a secret is configured AND the request carries exactly `Bearer <secret>`. Constant-time comparison. */
export function cronAuthorized(req: { headers: { get(name: string): string | null } }): boolean {
  const secret = cronSecret();
  if (!secret) return false;
  const given = Buffer.from(req.headers.get("authorization") ?? "", "utf8");
  const expected = Buffer.from(`Bearer ${secret}`, "utf8");
  // timingSafeEqual needs equal lengths; the length of the expected value is not a secret worth protecting here
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}
