import crypto from "crypto";

/**
 * Constant-time string equality for comparing secrets/tokens against
 * attacker-supplied input. Both sides are hashed first so the comparison
 * time does not depend on where (or whether) the lengths differ, then
 * compared with crypto.timingSafeEqual.
 */
export function safeEqual(a: string, b: string): boolean {
  const ha = crypto.createHash("sha256").update(a).digest();
  const hb = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}
