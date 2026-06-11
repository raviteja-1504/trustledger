# TrustLedger Dashboard

AI code provenance, attestation, and compliance for every pull request.

---

## Quick Start (Demo Mode)

No backend required — runs entirely from localStorage.

```bash
npm install
npm run dev
```

Open http://localhost:3000/seed → Click **"Seed data"** → http://localhost:3000/dashboard

---

## Production Setup

### 1. Supabase (Database + Auth)

1. Create a project at [supabase.com](https://supabase.com)
2. Run all migrations:
   ```bash
   # Using Supabase CLI
   supabase db push
   
   # Or manually in Supabase SQL Editor:
   # Run supabase/migrations/001_initial.sql through 007_2fa_and_profile.sql in order
   ```
3. Enable GitHub OAuth in Supabase Auth → Providers

### 2. GitHub App

1. Go to https://github.com/settings/apps/new (or use the one-click manifest at `/api/github-app/manifest`)
2. Set webhook URL: `https://your-domain.com/api/webhook/github`
3. Set permissions: Pull Requests (read), Contents (read), Checks (write)
4. Subscribe to events: pull_request, push

### 3. Environment Variables

Copy `.env.example` to `.env.local` and fill in:

```bash
# Required
NEXT_PUBLIC_SUPABASE_URL=https://xxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...
SUPABASE_SERVICE_ROLE_KEY=eyJ...
NEXT_PUBLIC_APP_URL=https://your-domain.com
NEXT_PUBLIC_ORG=your-org-slug

# GitHub App
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
GITHUB_WEBHOOK_SECRET=your-random-secret

# Optional — alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
SENDGRID_API_KEY=SG.xxx
ALERT_FROM_EMAIL=alerts@your-domain.com

# Optional — billing
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Optional — rate limiting
UPSTASH_REDIS_REST_URL=https://...
UPSTASH_REDIS_REST_TOKEN=...

# Cron jobs
CRON_SECRET=a-long-random-secret
```

### 4. Deploy

**Vercel (recommended):**
```bash
npm install -g vercel
vercel --prod
```

**Docker:**
```bash
docker compose up -d
```

**Manual build:**
```bash
npm run build
npm start
```

---

## Development

```bash
npm run dev          # Start dev server (port 3000)
npm test             # Unit tests
npm run test:e2e     # Playwright E2E tests
npm run lint         # ESLint
npx tsc --noEmit     # TypeScript check
```

---

## Architecture

```
src/
├── app/
│   ├── api/          # API routes (Next.js Route Handlers)
│   │   ├── scans/    # POST /api/scans — submit files for scanning
│   │   ├── attest/   # POST /api/attest — record attestation
│   │   ├── webhook/  # GitHub, GitLab, Bitbucket webhooks
│   │   └── ...
│   ├── dashboard/    # Main dashboard page
│   ├── violations/   # Violations management
│   └── ...
├── components/       # React components
├── lib/
│   ├── scanner.ts    # Static analysis engine
│   ├── supabase.ts   # Database client
│   ├── auth.tsx      # Supabase Auth provider
│   ├── validation.ts # Zod schemas
│   └── ...
└── ...
```

---

## Key Features

- **AI Code Scanning** — Detects AI-generated code, hardcoded secrets, SQL injection, eval/exec
- **Attestation** — Immutable, cryptographically-signed reviewer sign-offs
- **Compliance Reports** — SOC 2, EU AI Act, PCI-DSS PDF reports
- **GitHub/GitLab/Bitbucket** — PR status checks and rich comments
- **Realtime** — Supabase Realtime for live dashboard updates
- **SCIM 2.0** — Okta/Azure AD user provisioning
- **Stripe Billing** — Subscription management
- **Rate Limiting** — Upstash Redis sliding window

---

## SDKs

```bash
pip install trustledger          # Python SDK
npm install @trustledger/sdk     # Node.js SDK
```

CLI:
```bash
trustledger scan --repo org/repo --dir ./src
```

VS Code extension: Search "TrustLedger" in Extensions.

---

## License

Proprietary — © 2026 TrustLedger
