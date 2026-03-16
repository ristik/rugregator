#!/usr/bin/env bash
# Full E2E test runner.
# Starts BFT Core + Aggregator, runs the TypeScript SDK tests, then cleans up.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SDK_DIR="$REPO_ROOT/state-transition-sdk"
ENV_FILE="$REPO_ROOT/e2e-data/aggregator.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: Run scripts/e2e/setup-bft-core.sh first"
  exit 1
fi

# Kill any leftover processes from previous runs
echo "==> Killing any previous BFT Core / Aggregator instances..."
pkill -f "ubft root-node" 2>/dev/null || true
pkill -f "target/release/aggregator" 2>/dev/null || true
# Wait until port 3000 is free
for i in $(seq 1 10); do
  lsof -i :3000 -sTCP:LISTEN > /dev/null 2>&1 || break
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

# Start BFT Core
echo "==> Starting BFT Core..."
"$REPO_ROOT/scripts/e2e/start-bft-core.sh" &
BFT_PID=$!
sleep 3

# Start aggregator
echo "==> Starting Aggregator..."
"$REPO_ROOT/scripts/e2e/start-aggregator.sh" &
AGG_PID=$!
sleep 3

# Wait for aggregator to be healthy
echo "==> Waiting for aggregator health check..."
for i in $(seq 1 20); do
  if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
    echo "    Aggregator is up!"
    break
  fi
  if [ "$i" -eq 20 ]; then
    echo "ERROR: Aggregator health check timed out"
    exit 1
  fi
  sleep 1
done

# Build SDK if needed
echo "==> Building TypeScript SDK..."
(cd "$SDK_DIR" && npm install --silent && npm run build --silent)

# Run the E2E tests
echo ""
echo "==> Running E2E tests..."
(cd "$SDK_DIR" && npm run test:e2e -- --testTimeout=60000)

echo ""
echo "✓ E2E tests passed!"
