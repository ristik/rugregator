#!/usr/bin/env bash
# Start the Rust aggregator for E2E testing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENV_FILE="$REPO_ROOT/e2e-data/aggregator.env"
BIN="$REPO_ROOT/target/release/aggregator"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: Run scripts/e2e/setup-bft-core.sh first"
  exit 1
fi

if [ ! -f "$BIN" ]; then
  echo "==> Building aggregator..."
  (cd "$REPO_ROOT" && cargo build --release)
fi

echo "==> Starting Rust aggregator (loading $ENV_FILE)"
echo ""

set -a; source "$ENV_FILE"; set +a
exec "$BIN"
