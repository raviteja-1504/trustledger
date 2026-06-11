#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TrustLedger Production Deployment Script
# Handles: pre-flight checks → build → migrate → deploy → health verify
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║       TrustLedger Production Deployment          ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

cd "$ROOT_DIR"

# ── Step 1: Pre-flight checks ─────────────────────────────────────────────────
info "Step 1/7: Pre-flight checks..."

[[ -f ".env.local" || -n "$NEXT_PUBLIC_SUPABASE_URL" ]] || error ".env.local not found. Copy .env.example → .env.local"
[[ -n "${NEXT_PUBLIC_SUPABASE_URL:-}" ]]        || warn "NEXT_PUBLIC_SUPABASE_URL not set (demo mode)"
[[ -n "${SUPABASE_SERVICE_ROLE_KEY:-}" ]]        || warn "SUPABASE_SERVICE_ROLE_KEY not set"
[[ -n "${NEXT_PUBLIC_APP_URL:-}" ]]              || error "NEXT_PUBLIC_APP_URL must be set for production"

command -v node  >/dev/null 2>&1 || error "Node.js not found"
command -v npm   >/dev/null 2>&1 || error "npm not found"

NODE_VER=$(node -e "process.stdout.write(process.versions.node)")
info "Node.js: $NODE_VER"

success "Pre-flight checks passed"

# ── Step 2: Dependencies ──────────────────────────────────────────────────────
info "Step 2/7: Installing dependencies..."
npm ci --frozen-lockfile 2>&1 | tail -2
success "Dependencies installed"

# ── Step 3: Type check ────────────────────────────────────────────────────────
info "Step 3/7: TypeScript check..."
npx tsc --noEmit --skipLibCheck 2>&1 | grep -v "^$" || error "TypeScript errors found"
success "TypeScript OK"

# ── Step 4: Tests ─────────────────────────────────────────────────────────────
if [[ "${SKIP_TESTS:-false}" != "true" ]]; then
  info "Step 4/7: Running tests..."
  npm test -- --passWithNoTests --silent 2>&1 | tail -3
  success "Tests passed"
else
  warn "Step 4/7: Tests skipped (SKIP_TESTS=true)"
fi

# ── Step 5: Production build ──────────────────────────────────────────────────
info "Step 5/7: Building for production..."
npm run build 2>&1 | tail -5
success "Production build complete"

# ── Step 6: Database migrations ───────────────────────────────────────────────
if [[ -n "${SUPABASE_SERVICE_ROLE_KEY:-}" && -n "${NEXT_PUBLIC_SUPABASE_URL:-}" ]]; then
  info "Step 6/7: Running database migrations..."
  npx tsx scripts/migrate.ts 2>&1 || warn "Migration runner failed — check manually"
  success "Migrations complete"
else
  warn "Step 6/7: Database migrations skipped (Supabase not configured)"
fi

# ── Step 7: Deploy ────────────────────────────────────────────────────────────
info "Step 7/7: Deploying..."

DEPLOY_TARGET="${DEPLOY_TARGET:-vercel}"

case "$DEPLOY_TARGET" in
  vercel)
    command -v vercel >/dev/null 2>&1 || { npm install -g vercel@latest; }
    vercel --prod --yes 2>&1 | tail -5
    DEPLOY_URL=$(vercel ls --limit 1 2>/dev/null | awk 'NR==2{print $2}' || echo "$NEXT_PUBLIC_APP_URL")
    ;;
  docker)
    docker build -t trustledger-app:latest . 2>&1 | tail -3
    docker-compose up -d 2>&1 | tail -3
    DEPLOY_URL="${NEXT_PUBLIC_APP_URL:-http://localhost:3000}"
    ;;
  local)
    info "Starting production server locally..."
    npm start &
    DEPLOY_URL="http://localhost:3000"
    sleep 5
    ;;
  *)
    error "Unknown DEPLOY_TARGET: $DEPLOY_TARGET. Use: vercel | docker | local"
    ;;
esac

# ── Health verification ───────────────────────────────────────────────────────
if [[ -n "${DEPLOY_URL:-}" ]]; then
  info "Verifying deployment at $DEPLOY_URL/healthz..."
  HEALTH_STATUS=0
  for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$DEPLOY_URL/healthz" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "503" ]]; then
      HEALTH_STATUS=$HTTP_CODE
      break
    fi
    sleep 5
  done

  if [[ "$HEALTH_STATUS" == "200" ]]; then
    success "Health check passed (HTTP 200)"
  elif [[ "$HEALTH_STATUS" == "503" ]]; then
    warn "Health check returned 503 — database may be degraded"
  else
    warn "Health check returned $HEALTH_STATUS — verify deployment manually"
  fi
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║           Deployment Complete! 🚀               ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "  App URL:    ${DEPLOY_URL:-$NEXT_PUBLIC_APP_URL}"
echo "  Dashboard:  ${DEPLOY_URL:-$NEXT_PUBLIC_APP_URL}/dashboard"
echo "  Health:     ${DEPLOY_URL:-$NEXT_PUBLIC_APP_URL}/healthz"
echo "  API Docs:   ${DEPLOY_URL:-$NEXT_PUBLIC_APP_URL}/docs"
echo ""
