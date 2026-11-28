# Security Policy

This file is the summary. The detail lives in `docs/security/` and `docs/operations/` (linked below), and the public version of the
commitments is the Trust Center at `/trust`. If this file and the Trust Center ever disagree, that is a bug: tell us.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Email **trustledgerapp.dev@gmail.com** with:

- what you found and where (URL, API endpoint, or component);
- steps to reproduce, and a proof of concept if you have one;
- the impact you believe it has;
- how we can reach you.

The address above is the mailbox the site publishes today. **The live address is always the one on the site's `/security` page and in
`/.well-known/security.txt`** (RFC 9116), which are generated from the same setting (`NEXT_PUBLIC_CONTACT_DOMAIN`, or
`NEXT_PUBLIC_SECURITY_CONTACT` for the security address alone). When that setting changes, this paragraph must change with it: a test
fails the build if the default address here differs from the one the site publishes. See "Before you rely on this mailbox" below.

## What to expect

- Acknowledgement within **3 business days**.
- An initial assessment and severity rating within 10 business days.
- Updates while we fix it, and a note when the fix is deployed.
- Credit in the release notes, if you would like it.

There is no paid bug bounty programme at the moment.

## Safe harbour

We will not pursue legal action against good-faith research that stays within these rules: test only accounts
you own or are allowed to test; access no more data than needed to show the issue (never another customer's
code or findings); do not degrade the service; and allow a reasonable time, normally up to 90 days, before
public disclosure.

## Scope

In scope: the TrustLedger web application and API, the TrustLedger GitHub App, and the scanning pipeline.
Out of scope: social engineering, physical attacks, denial-of-service, third-party services we use, and
best-practice findings without a demonstrated security impact.

## How we respond to a report

1. The report is acknowledged (above) and a private incident record is opened with a severity (SEV1 to SEV4).
2. We reproduce it, find the blast radius (which customers, which data), and preserve evidence before changing anything.
3. We fix it, deploy, and check the fix. A fix that touches customer data is verified against the audit trail.
4. We tell the reporter, and customers where they are affected (below).
5. Within five working days of a SEV1 or SEV2 we write a review: what happened, what detected it, what changes.

The full procedure, with roles and timings, is [docs/security/incident-response.md](docs/security/incident-response.md).

## Telling customers about an incident

If we **confirm** an incident that affects a customer's data, we notify that customer's account administrators **without undue delay
and within 72 hours of confirming it**, with what happened, what data was involved, what we have done, and what they should do.
Outages and degraded service (no data involved) are announced on the public status page at `/status`; how is described in
[docs/operations/runbook.md](docs/operations/runbook.md).

## What we hold, how long, and how it is protected

[docs/security/data-handling.md](docs/security/data-handling.md) is the reference for: what is stored, retention windows and what is
never deleted automatically, how deletion works (including what is kept as evidence), encryption, who our subprocessors are, and
backups and recovery. The Trust Center publishes the same facts.

## What TrustLedger does and does not certify

We are precise about this because customers rely on it.

- **Not certified:** SOC 2, ISO 27001, or any other third-party attestation of **our own** controls. No independent penetration test has been
  performed yet. We will say so on `/trust` until that changes and never list a certification we do not hold.
- **What the product records:** who approved what, when, bound to the exact file content, in an audit trail that is tamper-evident
  (hash-chained, with signed checkpoints and signed exports you can verify offline). That is **evidence for your controls**; it is not a
  certification of your code or of your compliance.
- **Findings are not guarantees.** The scanner is heuristic: it can miss real issues and flag harmless code. The AI-likelihood score is an
  estimate of how likely code was machine-generated, not proof of authorship.
- **Attestations are human decisions.** An attestation means a named person reviewed and accepted a file at a point in time. TrustLedger
  records it faithfully; it does not judge whether the person was right.
- **Not legal advice.** Reports mapped to SOC 2, the EU AI Act or PCI-DSS help you gather evidence; whether it satisfies an auditor or a
  regulator is for them and for you.

## Before you rely on this mailbox

A published security address is only a commitment if someone reads it. Until the site is configured with an address on the company's own
domain that a named person monitors, the site publishes one shared mailbox. Before telling a customer that it is monitored:

1. Set `NEXT_PUBLIC_CONTACT_DOMAIN` (or `NEXT_PUBLIC_SECURITY_CONTACT`) to a mailbox on your own domain, and redeploy.
2. Confirm `/.well-known/security.txt` and `/security` show it.
3. Send it a test message from outside the organisation and confirm a named person answers within the 3 business days we promise.
4. Put that person (and a backup) in the on-call line of the operations runbook.

The admin **Go-live checklist** (`/admin/go-live`) flags this until step 1 is done.

## Related documents

| Document | What it covers |
|---|---|
| [docs/security/incident-response.md](docs/security/incident-response.md) | security incidents: severity, roles, evidence, customer notification |
| [docs/security/data-handling.md](docs/security/data-handling.md) | data, retention, deletion, encryption, subprocessors, recovery, certifications |
| [docs/security/secret-detection.md](docs/security/secret-detection.md) | how leaked secrets are found and handled |
| [docs/operations/runbook.md](docs/operations/runbook.md) | availability incidents, monitoring, status page, customer communication |
| [docs/operations/backup-and-restore.md](docs/operations/backup-and-restore.md) | backups, recovery objectives, the restore drill |
