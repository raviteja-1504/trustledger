/**
 * Alert Delivery System
 * Delivers P1/P2 alerts via Slack, email (SendGrid), and in-app.
 * Called from scan completion and violation SLA breach detection.
 */

export interface AlertPayload {
  alert_id:   string;
  severity:   "P1" | "P2" | "P3" | "P4";
  title:      string;
  body:       string;
  repo?:      string;
  scan_id?:   string;
  pr_number?: number;
  runbook?:   string;
  href?:      string;     // link for email CTA override
  org_name:   string;
  app_url:    string;
}

// ── Slack ──────────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<AlertPayload["severity"], string> = {
  P1: "#ef4444",
  P2: "#f97316",
  P3: "#3b82f6",
  P4: "#22c55e",
};

const SEV_EMOJI: Record<AlertPayload["severity"], string> = {
  P1: "🔴",
  P2: "🟠",
  P3: "🔵",
  P4: "🟢",
};

export async function sendSlackAlert(
  webhookUrl: string,
  alert: AlertPayload,
): Promise<boolean> {
  if (!webhookUrl) return false;

  const reviewUrl = alert.scan_id
    ? `${alert.app_url}/pr/${alert.scan_id}`
    : `${alert.app_url}/alerts`;

  const blocks = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: `${SEV_EMOJI[alert.severity]} ${alert.severity} — ${alert.title}`,
        emoji: true,
      },
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: alert.body },
    },
    {
      type: "section",
      fields: [
        ...(alert.repo      ? [{ type:"mrkdwn", text:`*Repository:*\n\`${alert.repo}\`` }] : []),
        ...(alert.pr_number ? [{ type:"mrkdwn", text:`*PR:*\n#${alert.pr_number}` }]      : []),
        { type:"mrkdwn", text:`*Org:*\n${alert.org_name}` },
        { type:"mrkdwn", text:`*Severity:*\n${alert.severity}` },
      ].filter(Boolean),
    },
    {
      type: "actions",
      elements: [
        {
          type: "button",
          text: { type: "plain_text", text: "Review in TrustLedger", emoji: true },
          style: "primary",
          url:   reviewUrl,
        },
        ...(alert.runbook ? [{
          type: "button",
          text: { type: "plain_text", text: "Runbook", emoji: true },
          url:   alert.runbook,
        }] : []),
      ],
    },
    { type:"divider" },
    {
      type: "context",
      elements: [
        { type:"mrkdwn", text:`TrustLedger AI Governance  ·  Alert ID: ${alert.alert_id}  ·  <!date^${Math.floor(Date.now()/1000)}^{date_short_pretty} at {time}|just now>` },
      ],
    },
  ];

  try {
    const res = await fetch(webhookUrl, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({
        text:        `${SEV_EMOJI[alert.severity]} ${alert.severity}: ${alert.title}`,
        attachments: [{ color: SEV_COLOR[alert.severity], blocks }],
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ── Email (SendGrid) ───────────────────────────────────────────────────────────

export async function sendEmailAlert(
  apiKey: string,
  fromEmail: string,
  toEmails: string[],
  alert: AlertPayload,
): Promise<boolean> {
  if (!apiKey || toEmails.length === 0) return false;

  // Use the new beautiful HTML template system
  const { alertEmail } = await import("./email/templates");
  const template = alertEmail({
    severity:  alert.severity,
    title:     alert.title,
    body:      alert.body,
    repo:      alert.repo,
    reviewUrl: alert.scan_id ? `${alert.app_url}/pr/${alert.scan_id}` : `${alert.app_url}/alerts`,
    runbook:   alert.runbook,
    orgName:   alert.org_name,
    appUrl:    alert.app_url,
  });
  const html     = template.html;
  const subject  = template.subject;

  try {
    const res = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method:  "POST",
      headers: {
        Authorization:  `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from:             { email: fromEmail, name: "TrustLedger Alerts" },
        personalizations: [{ to: toEmails.map(e => ({ email: e })) }],
        subject:          subject,
        content:          [{ type: "text/html", value: html }],
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ── PagerDuty ─────────────────────────────────────────────────────────────────

export async function sendPagerDutyAlert(
  integrationKey: string,
  alert: AlertPayload,
): Promise<boolean> {
  if (!integrationKey) return false;

  const urgency: Record<AlertPayload["severity"], string> = {
    P1: "high", P2: "high", P3: "low", P4: "low",
  };

  try {
    const res = await fetch("https://events.pagerduty.com/v2/enqueue", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({
        routing_key:  integrationKey,
        event_action: "trigger",
        dedup_key:    alert.alert_id,
        payload: {
          summary:   `[${alert.org_name}] ${alert.title}`,
          source:    "TrustLedger",
          severity:  urgency[alert.severity],
          component: alert.repo ?? "unknown",
          custom_details: {
            body:       alert.body,
            severity:   alert.severity,
            scan_id:    alert.scan_id,
            pr_number:  alert.pr_number,
            review_url: alert.scan_id ? `${alert.app_url}/pr/${alert.scan_id}` : alert.app_url,
          },
        },
        links: alert.scan_id ? [{ href: `${alert.app_url}/pr/${alert.scan_id}`, text: "Review in TrustLedger" }] : [],
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ── Microsoft Teams ───────────────────────────────────────────────────────────

export async function sendTeamsAlert(webhookUrl: string, alert: AlertPayload): Promise<boolean> {
  if (!webhookUrl) return false;
  const reviewUrl = alert.scan_id
    ? `${alert.app_url}/pr/${alert.scan_id}`
    : `${alert.app_url}/alerts`;

  const color: Record<AlertPayload["severity"], string> = {
    P1: "FF0000", P2: "FF7300", P3: "0078D4", P4: "107C10",
  };

  const card = {
    "@type":       "MessageCard",
    "@context":    "http://schema.org/extensions",
    themeColor:    color[alert.severity],
    summary:       alert.title,
    sections: [{
      activityTitle:    `**[${alert.severity}]** ${alert.title}`,
      activitySubtitle: `${alert.org_name} · TrustLedger`,
      activityText:     alert.body,
      facts: [
        ...(alert.repo      ? [{ name:"Repository", value:alert.repo }]          : []),
        ...(alert.scan_id   ? [{ name:"Scan ID",    value:alert.scan_id.slice(0,8)+"…" }] : []),
        { name:"Severity", value:alert.severity },
      ],
    }],
    potentialAction: [{
      "@type": "OpenUri",
      name:    "Review in TrustLedger",
      targets: [{ os:"default", uri: reviewUrl }],
    }],
  };

  try {
    const res = await fetch(webhookUrl, {
      method:  "POST",
      headers: { "Content-Type":"application/json" },
      body:    JSON.stringify(card),
    });
    return res.ok;
  } catch { return false; }
}

// ── Orchestrator ───────────────────────────────────────────────────────────────

interface OrgAlertConfig {
  slack_webhook?:       string;
  teams_webhook?:       string;
  sendgrid_api_key?:    string;
  alert_from_email?:    string;
  pagerduty_key?:       string;
  alert_emails?:        string[];
}

export async function deliverAlert(
  config: OrgAlertConfig,
  alert: AlertPayload,
): Promise<{ slack: boolean; email: boolean; pagerduty: boolean; teams: boolean }> {
  const [slack, email, pagerduty, teams] = await Promise.all([
    config.slack_webhook
      ? sendSlackAlert(config.slack_webhook, alert)
      : Promise.resolve(false),

    config.sendgrid_api_key && config.alert_emails?.length
      ? sendEmailAlert(
          config.sendgrid_api_key,
          config.alert_from_email ?? "alerts@trustledger.dev",
          config.alert_emails,
          alert,
        )
      : Promise.resolve(false),

    // Only page on P1/P2
    config.pagerduty_key && (alert.severity === "P1" || alert.severity === "P2")
      ? sendPagerDutyAlert(config.pagerduty_key, alert)
      : Promise.resolve(false),

    config.teams_webhook
      ? sendTeamsAlert(config.teams_webhook, alert)
      : Promise.resolve(false),
  ]);

  return { slack, email, pagerduty, teams };
}
