# Security incident response

How TrustLedger handles a suspected or confirmed security incident: who does what, how fast, and how
customers are told. Written for a small team: one person may hold every role below, but each step still
has to happen and be written down.

The public promises this runbook must keep are on `/security`:

- acknowledge a vulnerability report within **3 business days**;
- notify affected customers' account administrators **without undue delay, and within 72 hours** of
  confirming an incident that affects their data.

## 1. What counts as an incident

Anything that may have exposed, changed or destroyed customer data, or given someone access they should
not have. For example:

- a leaked or misused credential (a secret in a commit, in chat, in a log; a stolen laptop with `.env` files);
- one customer able to see another customer's repositories, findings or audit log;
- a valid vulnerability report showing the above is possible;
- unexpected admin actions, API keys, SSO changes or exports in a customer's audit log;
- the audit log's hash chain failing verification (`/audit` → Verify, or the signed export's
  `chain_valid: false`);
- suspicious activity on the GitHub App, Supabase, Vercel or Upstash accounts.

When in doubt, open an incident. Closing one that turns out to be nothing is cheap.

## 2. Severity

| Level | Meaning | Examples | Start working |
|---|---|---|---|
| **SEV1** | Customer data exposed or changed, or production credentials compromised | service-role key leaked; cross-tenant read confirmed; GitHub App private key leaked | immediately, any hour |
| **SEV2** | Real exposure possible but not confirmed, or one customer affected in a limited way | a working exploit reported but no sign of use; one account taken over | same day |
| **SEV3** | Weakness with no customer data at risk right now | a bug needing an unlikely precondition; a non-production secret leaked | within 3 business days |
| **SEV4** | Hardening, informational | missing header, best-practice report | normal backlog |

Raise the severity as soon as new facts justify it; never lower it without writing down why.

## 3. Roles

- **Incident lead** — owns the incident end to end, makes the calls, keeps the timeline.
- **Investigator** — gathers evidence, finds the cause and the blast radius.
- **Communications** — writes customer notices and the reporter's updates.

## 4. Steps

### 4.1 Open the incident (first 15 minutes)

1. Create a private record (a private GitHub issue or a private doc), titled `SEC-YYYYMMDD-short-name`.
2. Write down: who reported it and when, what is known, the severity, the incident lead.
3. Keep a **timeline**: every action and finding, with UTC time. Customer notices and the review are
   built from it.

### 4.2 Preserve evidence (before changing anything, where safe)

Some logs are kept only briefly; capture them first.

- **Vercel**: function logs for the affected time window (Dashboard → project → Logs). On the Hobby plan
  these are kept for about an hour — copy them immediately.
- **Audit log**: download the signed export for each affected organisation
  (`GET /api/export/signed?period_start=…&period_end=…`), which also records whether the hash chain
  is intact.
- **Supabase**: Authentication → Logs (sign-ins, including failed ones), and API/Postgres logs.
- **Trace page** (`/trace`) and Sentry for the affected requests.
- **GitHub**: the App's "Advanced" delivery log; the organisation audit log if a token was involved.

### 4.3 Contain

Stop the damage first; the root-cause fix can come later. Common actions in this system:

| Situation | Action |
|---|---|
| A secret leaked | Rotate it at the provider, update it in Vercel → Settings → Environment Variables, redeploy. See the table below. |
| A customer API key misused | Revoke it (Settings → API keys, or `DELETE /api/keys`). |
| A user account compromised | Sign the user out everywhere: set their `org_members.active_session_id` to `revoked` (any value that is not a real session id — `null` does **not** sign them out). Then reset their password / 2FA, or remove them. |
| A bad deploy introduced the hole | Roll back: Vercel → Deployments → previous good deployment → Promote (or `vercel rollback`). |
| A GitHub installation abused | Suspend the installation on GitHub, or remove the org's repos from scanning (Settings → Repositories). |
| An attack in progress | Tighten rate limits or block the source IP in Vercel's firewall; as a last resort, take the affected route offline with a hotfix. |

**Secrets and what rotating them affects**

| Secret | Where | Effect of rotating |
|---|---|---|
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase → Project settings → API (roll the JWT secret) | Rolling the JWT secret signs **everyone** out. Necessary if this key leaked — it reads all customers' data. |
| `GITHUB_APP_PRIVATE_KEY` | GitHub → App settings → Private keys (generate new, delete old) | None for users. Necessary if leaked — it can read every connected repository. |
| `GITHUB_WEBHOOK_SECRET`, `BITBUCKET_WEBHOOK_SECRET`, `GITLAB_WEBHOOK_TOKEN`, `STRIPE_WEBHOOK_SECRET`, `SLACK_SIGNING_SECRET` | the provider's webhook settings, then Vercel | Webhooks fail until both sides match. |
| `QSTASH_*` signing keys, `QSTASH_TOKEN`, `UPSTASH_REDIS_*` | Upstash console | Queued scans may fail once and be retried. |
| `INTERNAL_SECRET`, `CRON_SECRET`, `INTERNAL_CRON_KEY` | generate (`openssl rand -hex 32`), set in Vercel | None for users. |
| `EXPORT_SIGNING_KEY` | generate, set in Vercel | Earlier signed exports can no longer be checked against the new key; keep the old key in the incident record. |
| `DATA_ENCRYPTION_KEY` | **Do not simply replace.** | 2FA secrets encrypted with the old key become unreadable, and those users lose 2FA. If it leaked: keep the old key, add re-encryption under a new key in code first, then rotate. |
| `SUPABASE_MANAGEMENT_TOKEN` | Supabase → Account → Access tokens | SSO setup page stops working until replaced. |
| `STRIPE_SECRET_KEY`, `SENDGRID_API_KEY`, `SLACK_BOT_TOKEN`, `JIRA_API_TOKEN`, `LINEAR_API_KEY`, `PAGERDUTY_KEY` | the provider | That integration stops until replaced. |

Never paste a secret into chat, an issue or this record. Write down only *which* secret was rotated and when.

### 4.4 Investigate

Answer, with evidence:

1. **What** happened, and the root cause.
2. **When** it started and ended (first and last malicious action).
3. **Who** is affected: which organisations, which users, which repositories.
4. **What data**: source code? findings? audit log? personal data (names, emails)? credentials?
5. **Is it still happening?** If yes, back to 4.3.

Useful places: the audit log of each organisation (who did what), Vercel request logs (who called which
route), Supabase auth logs (who signed in from where), and the GitHub App delivery log.

### 4.5 Notify customers

Notify the **account administrators** of every affected organisation (`org_members` with role `admin`)
when the incident is confirmed to affect their data — without undue delay and **within 72 hours of
confirmation**, even if the investigation is not finished. Do not wait for perfect information; send an
update later.

Also check whether the law requires notifying a regulator (for example, under GDPR, a personal-data
breach is usually reportable to the supervisory authority within 72 hours). Get legal advice for SEV1.

**Initial notice template**

> **Subject: Security incident affecting your TrustLedger account**
>
> On [date, UTC] we confirmed a security incident that affects your organisation, [org name].
>
> **What happened:** [plain-language description].
> **What data was involved:** [e.g. findings for repositories X and Y between date and date]. [What was *not* involved.]
> **What we have done:** [contained how, when; fix status].
> **What you should do:** [e.g. rotate API keys created before date; review your audit log for date range] — or "no action is needed".
>
> We will update you by [date/time]. Questions: [security contact].

Follow up with what the investigation found, and a final notice when it is closed.

### 4.6 Reporter (for vulnerability reports)

- Acknowledge within 3 business days.
- Severity and plan within 10 business days.
- Tell them when it is fixed; ask whether they want credit.
- Keep their identity confidential unless they ask to be credited.

### 4.7 Recover and close

1. Deploy the root-cause fix, with a test that fails without it.
2. Confirm every rotated secret is in place and the old ones are revoked.
3. Re-verify the audit chain for affected organisations.
4. Send the final customer notice.
5. Write the review (below) within 5 business days of closing.

## 5. Post-incident review

Blameless, short, kept with the incident record:

- timeline (from the incident record);
- root cause, and why existing controls did not catch it;
- what went well, what was slow;
- follow-up actions, each with an owner and a date.

## 6. Keep this runbook working

- Review it every 6 months, and after every SEV1/SEV2.
- Keep the security contact on `/security` real and monitored (`NEXT_PUBLIC_SECURITY_CONTACT`).
- Practise once a year: walk through a pretend leak of `SUPABASE_SERVICE_ROLE_KEY` using this document,
  and fix whatever was unclear.
