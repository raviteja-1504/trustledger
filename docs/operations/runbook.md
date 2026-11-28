# Operations runbook

How we know the service is healthy, who hears when it is not, what each alert means, how we tell customers, and what we measure without
looking at their data. Security incidents (data exposure, leaked credentials) follow `docs/security/incident-response.md`; this runbook is
for **availability and correctness** incidents: scans not running, the audit log not writing, the site down.

The only scheduled job is the daily **maintenance run** (section 1, step 5). Detection is **an external monitor polling an endpoint** plus
**alerts sent at the moment something fails**; both are set up once (section 1).

## 1. Set it up once

1. **Alert channel.** Create a Slack-compatible incoming webhook (Slack, Discord's Slack mode, Mattermost…) for a channel someone reads.
   Set `OPS_ALERT_WEBHOOK_URL` in Vercel. Alerts are sent when they happen; the same alert for the same organisation is sent at most once per 15 minutes.
2. **Uptime monitor.** Create two monitors (UptimeRobot, Better Stack, a GitHub Actions job: any HTTP monitor):

   | Monitor | URL | Request | Alert when |
   |---|---|---|---|
   | Site | `https://<app>/api/health` | none | not 200 |
   | Platform | `https://<app>/api/ops/status` | header `Authorization: Bearer <CRON_SECRET>` | not 200 (it answers **503 when any check fails**) |

   Check every 5 minutes. Send the monitor's alerts to the same channel.
3. **Run the migrations** `20261129_scan_jobs.sql` and `20261129_platform_notices.sql`.
4. **Write down who is on call** (one name and a backup) in the channel's topic. A runbook with nobody assigned is a document.
5. **The daily maintenance run.** `/api/cron/pipeline-health` is a Vercel cron in `vercel.json` (03:00 UTC). Vercel calls it with `Authorization: Bearer <CRON_SECRET>`, so
   **`CRON_SECRET` must be set in Vercel** or the run is refused (401). It applies each organisation's data-retention window, deletes operational events older than 30 days,
   records signed audit checkpoints, takes the daily Trust Score snapshot and raises stuck-scan alerts. Check it is working: Vercel → project → Settings → Cron Jobs shows the
   last run and its status; the Audit page shows a new checkpoint after a day with activity. It is safe to call by hand (same header) after an outage. If it is not
   running, retention windows are not applied and operational events are not purged: administrators can still delete eligible records on demand, and create a
   checkpoint from the Audit page.
   Other jobs in `src/app/api/cron/` (SLA, weekly report, webhook retry) are **not** scheduled; the webhook retry needs to run more often than the plan's daily limit allows.

## 2. What the checks mean, and what to do

`GET /api/ops/status` (platform-wide counts only, no customer data). A check passes while its value is within its limit.

| Check | Limit | Failing means | First thing to do |
|---|---|---|---|
| `database` | answers in ≤ 2000 ms | Supabase is down or slow | Supabase status page; project paused? connection limit? Post a notice (section 4) |
| `queue_oldest_waiting` | ≤ 10 min | scans are waiting and not being picked up | Is QStash up? `QSTASH_*` set? Are workers failing (`scans_stuck_running`)? Replay from Settings → Scan queue |
| `scans_stuck_running` | 0 jobs running > 15 min | a worker died mid-scan | the job is taken over automatically after 15 min; if it recurs, look at Vercel function logs for timeouts |
| `scan_jobs_dead_24h` | 0 | scans ran out of attempts | Settings → Scan queue shows each with its reason; fix the cause (GitHub rate limit, bad installation) then **Replay** |
| `audit_write_failures_1h` | 0 | a required audit entry could not be written: **the action was refused or undone, customers see errors** | database permissions/health; `ops_events` (kind `audit.write_failed`) and Vercel logs for the error. Severity 1 if it persists |
| `audit_checkpoints_refused_24h` | 0 | an organisation's audit log failed verification | open that organisation's Audit page → "Check the whole log": forked (review it), missing or changed entries (security incident, `incident-response.md`) |
| `webhooks_given_up_24h` | ≤ 10 | customers' outbound webhooks keep failing | usually the customers' endpoints; look at the organisations named in `failing_orgs`, not the platform |

`failing_orgs` lists the organisations with the most failed scans as **opaque ids and counts**. Look an id up in the database only when you
need to act on it, and only the fields the action needs.

## 3. Handling an incident

**Severity**

| | Meaning | Examples | Respond |
|---|---|---|---|
| **SEV1** | the service is down, or customers' data or audit trail is being lost or refused | site down; `database` failing; `audit_write_failures_1h` > 0 for 15 min | now, any hour |
| **SEV2** | a major function is degraded for many customers | scans delayed > 30 min; all webhooks failing | within 1 hour in working hours |
| **SEV3** | limited: one customer, one integration, a workaround exists | one organisation's scans failing | same working day |

**Steps**
1. **Acknowledge** in the channel ("I have it"). One incident lead.
2. **Assess**: which checks fail, since when (`ops_events`, Vercel logs, the Trace page for one PR). Decide severity; raise it freely, lower it only with a reason.
3. **Communicate**: for SEV1/SEV2 post a status notice within **30 minutes** of confirming (section 4).
4. **Mitigate** before diagnosing in depth: redeploy the last good deployment (Vercel → Deployments → promote), pause the cause, replay failed scans. For data loss use `backup-and-restore.md`.
5. **Update** the notice at least every hour while it is open, even if only to say nothing has changed.
6. **Resolve** only when the failing checks pass again; resolve the notice.
7. **Review** within 5 working days for SEV1/SEV2: timeline, cause, what detected it, what should have, what changes. Write it in the incident's issue; add any new check or alert it showed was missing.

## 4. The status page

`/status` shows the live state of each component (database, scanning, audit log, outbound webhooks) from the real checks, plus the notices
you write. Only real signals are shown: nothing is hard-coded as "operational". Post and update notices in the Supabase SQL editor
(public text only: **never** an organisation's name or data):

```sql
-- start an incident (severity: info | degraded | outage)
insert into platform_notices (severity, title, body)
values ('degraded', 'Scans are delayed', E'We are investigating delayed scans. Pull requests may show "Scanning…" for longer than usual.');

-- update it (the page shows the newest wording and when it was updated)
update platform_notices set body = E'Cause found: our queue provider. Scans are being processed again; the backlog will clear within 30 minutes.', updated_at = now()
where resolved_at is null and title = 'Scans are delayed';

-- resolve it
update platform_notices set resolved_at = now(), updated_at = now(), body = body || E'\n\nResolved: the backlog is clear.'
where resolved_at is null and title = 'Scans are delayed';
```

Resolved notices stay visible for 14 days.

## 5. Telling customers

- **Everyone affected**: the status notice, written plainly: what you may notice, since when, what we are doing, when the next update comes.
- **A specific customer** (one organisation's scans failing; data they should know about): email their account administrators from the support address, with the same facts and what they need to do (usually nothing, or "replay from Settings → Scan queue").
- **Data loss** (a restore with a gap): state the exact period lost and what it affects (scans in that period to be re-run; audit entries in that period missing from the log; checkpoints that cover them).
- Do not speculate about cause until you know it, do not promise a time you cannot keep, and do not include anything about another customer.

Template:

> **What happened:** <one sentence, plain words>.
> **Who is affected:** <everyone / customers using X / your organisation>.
> **What you may notice:** <e.g. PR checks stay in "Scanning…">.
> **What we are doing:** <current action>.
> **What you need to do:** <nothing / replay from Settings → Scan queue>.
> **Next update:** <time>.

## 6. Metrics without leaking customer data

The rule for anything operational (dashboards, alerts, status pages, support): **counts, ages and opaque ids; never names, repositories, people, paths, payloads or error text from customer code.**

- `GET /api/ops/status` and the alerts follow it: a test fails the build if a repository name, email or error text appears in either.
- To investigate one organisation, start from its id in `failing_orgs`, then use the Trace page / `ops_events` for that organisation only.
- Platform administrators see per-organisation operational data only through these tools, which are access-controlled and audit-logged where they change anything.
- Do not paste customer data into the incident channel. Paste ids.

## 7. Release and change management

- Every change reaches production through `master` and a Vercel deployment: no manual edits to production. The commit message says what and why.
- Database changes are migrations in `supabase/migrations` named by date, applied by the owner in order; a deployment that needs one says so in its commit message, and the code tolerates the migration not having run yet where it can.
- A bad deployment is undone by promoting the previous deployment in Vercel (no database change needed unless the migration was destructive: they are not).
- Customer-visible changes are described in `/changelog`.
- After an incident, any new detection or alert it showed was missing is added to section 2 and to `src/lib/opsStatus.ts` the same week.
