#!/usr/bin/env bash
# Full E2E test runner.
# Starts BFT Core + Aggregator, runs the TypeScript SDK tests, then cleans up.
#
# Usage:
#   run-e2e-test.sh           # use existing e2e-data (re-run setup if missing)
#   run-e2e-test.sh --setup   # always re-run setup first (fresh BFT Core state)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SDK_DIR="$REPO_ROOT/state-transition-sdk"
ENV_FILE="$REPO_ROOT/e2e-data/aggregator.env"
SETUP_SCRIPT="$REPO_ROOT/scripts/e2e/setup-bft-core.sh"

# ── Parse args ────────────────────────────────────────────────────────────────
RUN_SETUP=false
for arg in "$@"; do
  case "$arg" in
    --setup) RUN_SETUP=true ;;
  esac
done

# ── Setup ─────────────────────────────────────────────────────────────────────
if $RUN_SETUP || [ ! -f "$ENV_FILE" ]; then
  echo "==> Running E2E setup..."
  "$SETUP_SCRIPT"
fi

# ── Kill leftover processes ───────────────────────────────────────────────────
echo "==> Killing any previous BFT Core / Aggregator instances..."
pkill -f "ubft root-node" 2>/dev/null || true
pkill -f "aggregator$" 2>/dev/null || true
# Wait until port 3000 and 26652 are free
for i in $(seq 1 10); do
  lsof -i :3000 -sTCP:LISTEN > /dev/null 2>&1 || break
  sleep 1
done
for i in $(seq 1 10); do
  lsof -i :26652 -sTCP:LISTEN > /dev/null 2>&1 || break
  sleep 1
done

cleanup() {
  echo ""
  echo "==> Stopping services..."
  [ -n "${BFT_PID:-}" ] && kill "$BFT_PID" 2>/dev/null || true
  [ -n "${AGG_PID:-}" ] && kill "$AGG_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Start BFT Core ────────────────────────────────────────────────────────────
echo "==> Starting BFT Core..."
"$REPO_ROOT/scripts/e2e/start-bft-core.sh" &
BFT_PID=$!

# Wait for BFT Core port to be ready (max 15s)
echo "==> Waiting for BFT Core to listen on :26652..."
for i in $(seq 1 15); do
  if lsof -i :26652 -sTCP:LISTEN > /dev/null 2>&1; then
    echo "    BFT Core is up!"
    break
  fi
  if [ "$i" -eq 15 ]; then
    echo "ERROR: BFT Core did not start within 15s"
    exit 1
  fi
  sleep 1
done

# ── Start aggregator ──────────────────────────────────────────────────────────
echo "==> Starting Aggregator..."
"$REPO_ROOT/scripts/e2e/start-aggregator.sh" &
AGG_PID=$!

# Wait for aggregator HTTP to be ready
echo "==> Waiting for aggregator health check..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
    echo "    Aggregator is up!"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: Aggregator health check timed out"
    exit 1
  fi
  sleep 1
done

# ── Build SDK ─────────────────────────────────────────────────────────────────
echo "==> Building TypeScript SDK..."
(cd "$SDK_DIR" && npm install --silent && npm run build --silent)

# ── Run E2E tests ─────────────────────────────────────────────────────────────
echo ""
echo "==> Running E2E tests..."
(cd "$SDK_DIR" && npm run test:e2e -- --testTimeout=60000)

echo ""
echo "✓ E2E tests passed!"
