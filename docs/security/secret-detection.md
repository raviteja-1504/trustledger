# Secret detection

How TrustLedger finds hardcoded credentials, what it is measured against, and what it does not do.

## What it checks

Four layers, from most to least certain. All run on every file type (the AI-authorship scoring skips config files; the
secret checks do not).

1. **Provider formats** (`SECRET_PATTERNS` in `scanner.ts`). A distinctive prefix, shape or context word makes the match a
   credential on its own: AWS, GitHub (classic and fine-grained), GitLab, Stripe (secret, restricted, webhook), Slack
   (tokens, webhooks), OpenAI, Anthropic, Hugging Face, Groq, Replicate, Notion, Linear, Databricks, Square, SendGrid,
   Mailchimp, Twilio, Telegram, Discord (bot token, webhook), DigitalOcean, npm, PyPI, Azure (storage key, SAS, AD client
   secret), Google (API key, service-account key id), HashiCorp Vault, Datadog, PASETO/PASERK, JWTs, private keys,
   database URLs with a password, and `Bearer` / `Basic` headers (a Basic value must decode to `user:password`).
   These also run in comments and in test files: a real key pasted into either is still a leak.
2. **Credentials assigned to a name that says what they are** (`credentialAssignments.ts`): `"consumerSecret": "..."`,
   `MYSQL_ROOT_PASSWORD: ...`, `--password=...`. The name is the evidence, so the rule is mostly a set of reasons NOT to
   report: keys that describe a credential (`_PATH`, `_ID`, `_HASH`, `_URL`...), references and templates, identifiers
   (`ResetPassword`, `base64EncodedKey`), config key paths (`session.secret`), OIDs, placeholders, sequences. Unquoted
   `NAME=value` counts only in files where that is how settings are written (`.env`, YAML, TOML, shell, `.s3cfg`...).
3. **Files that exist to hold credentials** (`credentialFiles.ts`): `.netrc`, `.pgpass`, `.git-credentials`, `.npmrc`,
   htpasswd/shadow hashes, Rails `master.key`, unencrypted PuTTY keys, Docker `config.json` auth, XML `<Password>`
   elements, bcrypt hashes. The format is the evidence, so a short value still counts.
4. **High entropy** next to a credential-looking name (`findHighEntropySecrets`), including a bare long hex value
   (`Key = 8cd6...`).

Generic rules (2 and the older word=value patterns) do not run in test directories, and defer to the infrastructure
detectors (Kubernetes Secret, CloudFormation, Serverless, Terraform, Dockerfile, Compose), which report the same line
with a more specific fix.

## How it is measured

Four public benchmarks, none of them written by us:

| Benchmark | What it is | Measures |
|---|---|---|
| **CredData** (Samsung) | ~74,000 manually labelled lines from 297 real repositories; 6% are real credentials | recall AND false positives on real code |
| **ProwlBench** | 24,603 labelled snippets (16,552 secrets, 8,051 hard negatives), 40 secret types, 4 difficulty tiers | per-type recall, hard-negative rate |
| **leaky-repo** (Plazmaz) | a repository of classic leaked config files, with per-file risk counts | file-format coverage |
| **secret-scan** (power-tester) | a multi-service repo with a documented inventory of planted secrets | planted-secret coverage |

CredData numbers use a subset (21 repositories, 1,202 files, 7,664 scored lines) built with CredData's own download and
obfuscation script, because the full dataset is 297 repositories and expects Linux. ProwlBench numbers use every 10th
case (2,461 of 24,603). Both are samples; do not quote them as full-benchmark results.

### Results (before this work, then now)

| | Before | Now |
|---|---|---|
| ProwlBench: recall / precision / F1 | 32.4% / 93.2% / 48.1% | **66.3% / 95.1% / 78.1%** |
| ProwlBench: structured provider tokens, recall | 48% | **93%** |
| ProwlBench: generic password/key in code context, recall | 15% | **71%** |
| CredData subset: recall / precision / F1 | 7.2% / 94.7% / 13.4% | **27.3% / 98.3% / 42.8%** |
| CredData subset: false-positive rate | 0.3% | 0.3% |
| leaky-repo: files with a risky line that are detected | 21 of 42 | **40 of 42** (none flagged without a labelled risk) |
| secret-scan: planted-secret lines flagged | not measured | 81% |

For scale, ProwlBench's own published run gives gitleaks 41% recall (93% precision), TruffleHog 30% (94%) and
detect-secrets 42% (85%) on the full set. Those figures come from the benchmark's authors, not from our run, and the
benchmark's own tool leads its table, so treat the comparison as indicative.

## What it does not do

- **Git history.** Only the files in the scan are read. A secret deleted from the current tree but present in history is
  not found.
- **Verification.** A match is not checked against the provider. A finding is "looks like a credential", never "is live".
- **Test directories** are skipped by the generic rules. CredData labels about half of its true credentials as sitting in
  test-style paths, so this is a deliberate precision/recall trade, and the main reason CredData recall is 27%.
- **Short random lowercase passwords** (`twqoek`) cannot be told from words and are not reported. CredData's obfuscation
  turns many real passwords into exactly these.
- **Prose.** Provider tokens pasted into a sentence are found; "the password is hunter2" is not.
- **Hard negatives that look like tokens.** ProwlBench labels some real-format tokens as "not a secret" because the
  sentence around them says "checksum" or "staging colour". We report them; its false-positive rate rose from 4.9% to
  7.1% largely for this reason.
- **Placeholders and examples** (`AKIAIOSFODNN7EXAMPLE`, `sk-xxxxxxxx`, sequences like `1234567890abcdef`, `user:pass@host`)
  are deliberately not reported.

## Reproducing

The harness is a scratch jest test that runs `analyzeFile` over a corpus and records every `hardcoded-secret` finding,
plus small scorers per benchmark. It is not committed. Test fixtures in this repository build every token at run time
(a prefix plus a pseudo-random body) so no complete token-shaped literal sits in the source.
