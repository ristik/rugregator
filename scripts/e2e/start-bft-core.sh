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

RPC_ADDR="127.0.0.1:26660"

echo "==> Starting BFT Core root node"
echo "    Home:       $ROOT_HOME"
echo "    Shard-conf: $SHARD_CONF (uploaded via RPC after launch)"
echo "    Address:    /ip4/127.0.0.1/tcp/26652"
echo ""

"$UBFT" root-node run \
  --home "$ROOT_HOME" \
  --trust-base "$ROOT_HOME/trust-base.json" \
  --address "/ip4/0.0.0.0/tcp/26652" \
  --rpc-server-address "$RPC_ADDR" \
  --log-format console \
  --block-rate 1000 \
  --log-level DEBUG &
NODE_PID=$!
trap 'kill $NODE_PID 2>/dev/null' INT TERM EXIT

# Give the RPC server a moment to come up, then upload the shard conf.
sleep 2
echo "==> Uploading shard conf to http://$RPC_ADDR/api/v1/configurations"
curl -sS -w "\n    HTTP %{http_code}\n" -X PUT \
  -H "Content-Type: application/json" \
  --data-binary "@$SHARD_CONF" \
  "http://$RPC_ADDR/api/v1/configurations" || echo "    shard-conf upload failed"

wait $NODE_PID
