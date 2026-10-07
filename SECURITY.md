# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Email **security@trustledger.example** with:

- what you found and where (URL, API endpoint, or component);
- steps to reproduce, and a proof of concept if you have one;
- the impact you believe it has;
- how we can reach you.

> The address above is a placeholder until the real security mailbox is set up. The live address is always
> the one on the site's `/security` page and in `/.well-known/security.txt` (set with
> `NEXT_PUBLIC_CONTACT_DOMAIN`, or `NEXT_PUBLIC_SECURITY_CONTACT` for this address alone). Update this file
> when that changes.

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

## Incident handling

How we handle a confirmed security incident, including customer notification, is described in
[docs/security/incident-response.md](docs/security/incident-response.md).
