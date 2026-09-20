/**
 * `/trustledger attest` command logic — extracted out of
 * src/app/api/slack/commands/route.ts because Next.js App Router route
 * files may only export HTTP method handlers (GET/POST/etc.) and a small
 * set of config values; any other named export fails the framework's own
 * route-file type validation. Everything unit-testable lives here instead;
 * the route just imports and calls it from its command switch.
 */

import type { createServiceClient } from "@/lib/supabase";
import { performAttestation } from "@/lib/attestation";

function slackText(text: string) {
  return { response_type: "ephemeral", text };
}
function slackBlocks(blocks: unknown[]) {
  return { response_type: "ephemeral", blocks };
}
function slackError(msg: string) {
  return slackText(`❌ ${msg}`);
}

/** Resolves a Slack user_id to their real email via users.info -- returns
 * null (never throws) if SLACK_BOT_TOKEN isn't configured, the lookup
 * fails, or the workspace doesn't expose email, so callers can fail open
 * into a clear message rather than a crash. */
export async function resolveSlackUserEmail(slackUserId: string): Promise<string | null> {
  const token = process.env.SLACK_BOT_TOKEN;
  if (!token) return null;
  try {
    const res = await fetch(`https://slack.com/api/users.info?user=${encodeURIComponent(slackUserId)}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(8000),
    });
    const data = await res.json() as { ok: boolean; user?: { profile?: { email?: string } } };
    return data.ok ? (data.user?.profile?.email ?? null) : null;
  } catch {
    return null;
  }
}

export async function handleAttest(
  db: ReturnType<typeof createServiceClient>, orgId: string, args: string[], slackUserId: string,
) {
  const [scanId, ...fileParts] = args;
  const filePath = fileParts.join(" ");
  if (!scanId || !filePath) {
    return slackError("Usage: `/trustledger attest <scan_id> <file_path>`");
  }

  const email = await resolveSlackUserEmail(slackUserId);
  if (!email) {
    return slackError("Couldn't resolve your email from Slack — TrustLedger's Slack app may not have a bot token configured, or this workspace restricts email visibility. Attest from the dashboard instead.");
  }

  const result = await performAttestation(db, {
    org_id: orgId, scan_id: scanId, file_path: filePath, reviewer_email: email,
  });

  if (!result.ok) {
    if (result.reason === "scan_not_found") return slackError("Scan not found — check the scan_id and try again.");
    return slackError("Couldn't record that attestation. Please try again or use the dashboard.");
  }

  return slackBlocks([
    { type: "section", text: { type: "mrkdwn", text: `✅ Attested \`${filePath}\` as *${email}*` } },
  ]);
}
