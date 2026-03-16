#!/usr/bin/env bash
# Start the single-node BFT Core root node for E2E testing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
UBFT="$REPO_ROOT/bft-core/build/ubft"
ROOT_HOME="$REPO_ROOT/e2e-data/root-node"

if [ ! -f "$ROOT_HOME/keys.json" ]; then
  echo "ERROR: Run scripts/e2e/setup-bft-core.sh first"
  exit 1
fi

# Find the shard-conf file
SHARD_CONF=$(ls "$ROOT_HOME"/shard-conf-*.json 2>/dev/null | head -1)
if [ -z "$SHARD_CONF" ]; then
  echo "ERROR: No shard-conf file found in $ROOT_HOME"
  exit 1
fi

echo "==> Starting BFT Core root node"
echo "    Home:       $ROOT_HOME"
echo "    Shard-conf: $SHARD_CONF"
echo "    Address:    /ip4/127.0.0.1/tcp/26652"
echo ""

exec "$UBFT" root-node run \
  --home "$ROOT_HOME" \
  --trust-base "$ROOT_HOME/trust-base.json" \
  --shard-conf "$SHARD_CONF" \
  --address "/ip4/0.0.0.0/tcp/26652" \
  --rpc-server-address "127.0.0.1:26660"
