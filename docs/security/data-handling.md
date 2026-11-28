# Data handling: what we hold, how long, how it is protected

The reference behind the Trust Center (`/trust`) and `SECURITY.md`. Everything here describes what the product does today; where something
is not done yet, it says so. If the product and this document disagree, the product is wrong or the document is: report it.

## 1. What we hold

| Category | Examples | Where |
|---|---|---|
| Account and membership | member emails, names, roles, GitHub login, two-factor settings, sessions | Supabase Postgres |
| Scan results | findings, risk scores, AI-likelihood estimates, traces, and the **content of scanned files** (so reviewers can see the flagged lines when they attest) | Supabase Postgres |
| Review records | attestations (reviewer, time, content hash, signature), violation status, triage decisions, evidence records | Supabase Postgres |
| The audit log | sign-ins, role and key changes, exports, deletions, attestations: hash-chained, with signed checkpoints | Supabase Postgres |
| Integrations | repository connections, GitHub App installation ids, webhook endpoints (secret stored with the endpoint), API key **hashes** | Supabase Postgres |
| Operational events | what the system did for a pull request, for tracing problems: kept 30 days | Supabase Postgres |
| Uploaded evidence files | files an administrator attaches | Supabase Storage |

We **access** only the metadata and changed files of pull requests in repositories you connect, read-only. We never execute your code, never
use it to train models, and never show one customer's data to another.

## 2. Retention

- **Default: nothing is deleted automatically.** An organisation chooses a retention window between **30 days and 7 years** (Settings → data retention).
- A window applies to **closed records and unattested scans only**. It never deletes: **attestations** (they are the audit evidence), **open items**
  (violations and findings still awaiting a decision), or **the audit log**.
- Operational events are meant to be deleted after **30 days**.
- Both of those are done by the platform's daily maintenance run (`/api/cron/pipeline-health`, a Vercel cron at 03:00 UTC). If that run is not happening
  (check the cron in the Vercel dashboard; the runbook says how), a chosen retention window is not applied and operational events are not purged;
  administrators can always delete eligible records on demand (section 3). The maintenance run also records audit checkpoints and raises stuck-scan alerts.

## 3. Deletion

Administrators have four tools, each recorded in the audit log **before** it runs, so nothing is deleted without a record:

| Tool | Deletes | Keeps |
|---|---|---|
| **Delete old records** (Settings; unattested scans, violations, secrets, incidents, alerts older than 7 days) | the chosen records before a date | attestations, audit log, anything newer |
| **Reset organisation data** | scans, repositories, findings, webhook deliveries, API keys | team members, attestations, audit log |
| **Right to erasure** (`delete_account`) | operational data: scans, findings, alerts, incidents, risk register, webhook configuration, repositories | attestations, audit log (the required retention for the evidence) |
| **Delete the organisation** | everything that is customer data: members, repositories, scans, findings, API keys, integrations, webhooks, evidence records, SSO/SCIM configuration | see below |

**Deleting an organisation** is a request, a waiting period, and an explicit execution: an administrator types the organisation's name and passes a
step-up (a current authenticator code, or a sign-in within 10 minutes); the request waits **24 hours** by default (configurable, never under an hour in
production); any administrator can cancel until it runs; then an administrator confirms again. The deletion is a single database transaction: it completes
or changes nothing, and a failed run is visible as failed and can be run again or cancelled. Nothing is scheduled to run it.

**What is kept after an organisation is deleted, and why.** The audit log, attestations and signed audit checkpoints are immutable by design (the database
refuses to delete or edit them): they are the evidence that a review happened and who did it, and deleting them would defeat their purpose. They are kept against an
**anonymised organisation record** (name and slug replaced, GitHub handle and webhook addresses cleared). The scan records that an attestation points to are kept,
detached from their repository, because the attestation refers to them; they contain the scan's metadata (repository name, pull request number, commit), not a copy of
your files. The public keys needed to verify those records stay, too. These records contain reviewer email addresses. If you need them removed for a legal reason,
write to us: we will assess it against our obligation to keep audit evidence, and tell you what we can and cannot do.

## 4. Encryption and credentials

- **In transit:** HTTPS everywhere, with HSTS (two years, includeSubDomains, preload).
- **At rest:** the database and file storage are encrypted at rest by Supabase (our database provider).
- **Two-factor secrets** are additionally sealed with **AES-256-GCM** when `DATA_ENCRYPTION_KEY` is set, and backup codes are stored only as salted hashes. (Without
  the key the platform warns and stores the secret unsealed rather than lock people out: the key must be set in production, and is in the recovery inventory.)
- **API keys and SCIM tokens** are shown once and stored only as SHA-256 hashes: we cannot read them back. **GitHub access** uses short-lived installation tokens
  requested when needed, not stored personal tokens.
- **Signatures:** attestations, audit checkpoints and exports are signed with Ed25519; the public keys are published (`/.well-known/trustledger-export-signing-key`)
  so anyone can verify them without trusting us.
- **Webhooks** (incoming) are rejected unless their signature verifies; **outgoing** webhooks must be public https addresses when they are created or edited, and every delivery is checked again against the address actually connected to (so a name that later points inside our network is refused).

## 5. Access control

Role-based permissions are checked on every API write, and every query on an organisation's data is limited to that organisation (an automated test fails the
build otherwise). Members can use two-factor authentication; an administrator can **require it for the whole organisation**, end any member's sessions, and remove a
member (their access ends on the next request). SAML single sign-on and SCIM provisioning exist and are **switched off by default**; we enable them for an organisation
on request. SCIM can assign roles below admin only: administrators are always made in the application.

## 6. Subprocessors

| Provider | Purpose | Data |
|---|---|---|
| Vercel | Application hosting and serverless functions | All application traffic, transiently |
| Supabase | Postgres database, authentication, file storage | Account data, scan results, scanned file content, audit log |
| Upstash | Job queue (QStash) and Redis cache / rate limiting | Scan job references, rate-limit counters |
| GitHub, GitLab, Bitbucket | Source hosting integrations | Only repositories you connect |
| Sentry | Error monitoring | Error reports and stack traces |
| PostHog | Product analytics, where enabled | Usage events |
| SendGrid | Account and alert email | Recipient address and message |
| Payment processor | Billing, paid plans only | Billing contact and payment details |

Integrations an organisation configures itself (Slack, Jira, PagerDuty, its own webhooks) receive the alerts it routes to them. We will add a provider to this list, and
to `/trust`, before it handles customer data.

## 7. Backups and recovery

Backups are taken by our database provider; the written procedure, the recovery objectives we are working to, and the restore drill are in
[docs/operations/backup-and-restore.md](../operations/backup-and-restore.md). **The restore drill has not been run yet**: we publish recovery objectives
only once it has, and they depend on the provider's backup plan. Uploaded evidence files are not part of the database backup and are exported separately.

## 8. What we do and do not certify

| | |
|---|---|
| SOC 2 (our own controls) | **not certified** |
| ISO 27001 | **not certified** |
| Independent penetration test | **not yet performed** |
| GDPR | administrators can export and delete data (section 3); the privacy policy is at `/privacy` |

TrustLedger records evidence about **your** change-management controls. It does not certify your code, your compliance, or a reviewer's judgement; findings are heuristic
and the AI-likelihood score is an estimate, not proof of authorship. See `SECURITY.md`.
