# Backup and restore

What is backed up, how much data we can lose (RPO), how long recovery takes (RTO), and how to prove a restore works. A backup that
has never been restored is a hope, not a backup: the **restore drill** in section 4 is part of this document, not an extra.

## 1. What holds what

| What | Where | Backed up by | Lost if not backed up |
|---|---|---|---|
| All customer data: organisations, members, scans, findings, attestations, the audit log, checkpoints, the scan job ledger | **Supabase Postgres** | Supabase backups (section 2) | everything customers have recorded |
| Application code, build, routes | GitHub, Vercel | git history; any commit can be redeployed | nothing: rebuild from git |
| Environment variables and signing keys | Vercel project settings | **nobody, unless you do (section 3)** | the platform cannot sign, decrypt or call GitHub |
| Rate-limit counters, caches | Upstash Redis | not needed: rebuilt on use | nothing important |
| Queued scan jobs in flight | Upstash QStash | the scan job ledger in Postgres holds each job's original payload; replay from Settings → Scan queue | scans that were queued at the moment of loss: replay them |
| Uploaded evidence files | Supabase Storage | Supabase does **not** back up Storage objects with the database backup | the files (the evidence *records* in Postgres survive) |

The audit log and attestations are immutable inside the database, but that protects against edits through the application, not against
losing the database. Signed **checkpoints** (`AUDIT_CHECKPOINT_SINK_URL`, or the export on the Audit page) kept outside the database are
what prove, after a restore, that nothing newer than the backup was silently dropped.

## 2. Targets: RPO and RTO

These are the targets this procedure is written for. **Check them against your Supabase plan before you promise them to anyone**: what
you can really achieve is set by the backup feature you pay for.

| | Target | Needs | How to check what you have |
|---|---|---|---|
| **RPO** (data we can lose) | **15 minutes** | Point-in-time recovery (PITR) enabled | Supabase dashboard → Database → Backups → "Point in time" shows the earliest restore point and that it is on |
| | 24 hours | daily backups only | Database → Backups → "Scheduled backups" lists the last 7 days |
| **RTO** (time to be serving again) | **4 hours** for a full restore into a new project, including DNS/env switch and verification | a practised drill (section 4), the secrets inventory (section 3) | the **measured** time from your last drill |

If only daily backups are available, the honest RPO is 24 hours and the status page and customer commitments must say so. Writing a better
number here does not make it true. Record the real plan and the real numbers in the drill log (section 4.5).

## 3. The secrets inventory (the part nobody backs up)

A restored database is useless if the application cannot decrypt, sign or authenticate. Keep these in a password manager or secrets vault
that more than one trusted person can open, **not only in Vercel** (Vercel will not show you a secret's value after you have set it as sensitive).

| Variable | If lost |
|---|---|
| `DATA_ENCRYPTION_KEY` | **unrecoverable**: sealed values (two-factor secrets) in the restored database cannot be opened; every member with two-factor is locked out and must be reset by hand |
| `ATTESTATION_SIGNING_KEY` | new attestations and checkpoints cannot be signed with the same key; old ones still verify (their public keys are in the database), but you must register a new key |
| `EXPORT_SIGNING_PRIVATE_KEY` | signed exports cannot be produced with the published key; auditors must be given the new public key |
| `SUPABASE_SERVICE_ROLE_KEY`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` | changes with a restore into a **new** project: you will set new values (section 5) |
| `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET` | the GitHub App cannot post checks; generate a new private key in the App's settings |
| `QSTASH_TOKEN`, `QSTASH_CURRENT_SIGNING_KEY`, `QSTASH_NEXT_SIGNING_KEY`, `INTERNAL_SECRET` | scans cannot be queued/verified until replaced |
| `CRON_SECRET`, `OPS_ALERT_WEBHOOK_URL` | monitoring and alerting stop |
| `SENDGRID_API_KEY`, `STRIPE_*` | email / billing stop |

Review this list whenever a new secret is added (the list in `src/lib/env.ts` is the authority) and write down who holds the vault.

## 4. The restore drill

Run it **at least every quarter**, and after any change to how backups are taken. It restores into a **new, separate** Supabase project; it never
touches production.

### 4.1 Before you start
- Note the start time. The drill measures RTO.
- Have the secrets inventory open.

### 4.2 Restore
1. Supabase → the production project → Database → Backups → choose a restore point (for PITR, a time a few minutes ago) → **Restore to a new project**.
2. Wait for the new project to finish. Note its URL and a service role key (Settings → API).

### 4.3 Check the data
```
SUPABASE_URL=https://<restored-ref>.supabase.co SUPABASE_SERVICE_ROLE_KEY=<restored key> \
  node scripts/restore-check.cjs --incident-at <time you chose as "the incident", ISO 8601>
```
It lists each table's rows and newest row, checks every organisation's audit log for entries whose parent is missing, and prints the
**recovery point** (minutes of data lost, from the newest audit entry). Exit code 0 means every check passed.

### 4.4 Check the application against the restored data
1. Deploy a preview of the application (Vercel preview of `master`) with the **restored** project's three Supabase variables and the rest of the inventory.
2. Sign in as a test admin. Open **Audit → "Check the whole log"**: it must say intact (or "forked, reviewed"), not "missing entries" or "changed".
3. Open **Settings → Scan queue**: replay anything that was queued at the restore point.
4. Take a signed export of one organisation and verify it offline: `node scripts/verify-audit-export.cjs <file> <public-key.pem>`.
5. If you keep checkpoints outside the database, compare the newest external checkpoint with the restored chain: the chain must hold at least as many entries as the checkpoint recorded.
   A shorter chain means the restore point is older than the checkpoint: that gap is real data loss, and it is exactly what the checkpoint is for.

### 4.5 Record it
Add a row to the drill log below: date, restore point, **measured RPO** (minutes), **measured RTO** (start to step 4.4 finished), what went wrong, what you changed.

| Date | Plan (PITR / daily) | Measured RPO | Measured RTO | Problems found and fixed |
|---|---|---|---|---|
| _none yet: run the first drill_ | | | | |

Delete the restored project afterwards (it holds a full copy of customer data).

## 5. A real recovery (production is lost or corrupted)

1. Declare an incident (`runbook.md`, section 3). Post a notice on the status page: the service is down and we are restoring.
2. Decide the restore point. Corruption: the last moment before it (look at the Audit page and `ops_events` for when it began). Loss: the newest available.
3. Restore to a new project (4.2). **Do not restore over production in place** unless the platform leaves no other option: a new project can be checked before anyone depends on it.
4. Run `scripts/restore-check.cjs` (4.3) and the application checks (4.4) against it.
5. Switch production: set the three Supabase variables in Vercel to the restored project, redeploy, and check `/api/ops/status` returns 200.
6. Run the migrations that are newer than the restore point (compare `supabase/migrations` with what the restored project has).
7. Replay queued scans (Settings → Scan queue), and tell customers with a stated gap exactly which period was lost (section 6 of the runbook).
8. Record the incident review, and the measured RPO and RTO, in the drill log.

## 6. Things that make recovery easier (do these once)

- Turn on **PITR** in Supabase if the plan allows it, and confirm the retention window.
- Set `AUDIT_CHECKPOINT_SINK_URL` so every signed audit checkpoint is also stored outside the database.
- Keep a periodic `pg_dump` of the database somewhere that is not Supabase (`pg_dump "$DATABASE_URL" -Fc -f trustledger-$(date +%F).dump`), encrypted, for the case where the whole Supabase account is unavailable. It is not a substitute for PITR.
- Export Storage objects separately if evidence files matter to you (Supabase CLI: `supabase storage cp -r ss:///<bucket> ./backup`).
