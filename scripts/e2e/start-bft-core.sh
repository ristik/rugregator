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

RPC_ADDR="127.0.0.1:26660"

echo "==> Starting BFT Core root node"
echo "    Home:       $ROOT_HOME"
echo "    Address:    /ip4/127.0.0.1/tcp/26652"
echo ""

script -q /dev/null "$UBFT" root-node run \
  --home "$ROOT_HOME" \
  --trust-base "$ROOT_HOME/trust-base.json" \
  --address "/ip4/0.0.0.0/tcp/26652" \
  --rpc-server-address "$RPC_ADDR" \
  --log-format console \
  --block-rate 1000 \
  --log-level DEBUG \
 | grep -Ev 'consensus/consensus_manager.go'

# TODO: remove the filtering on line above if setting up multinode bft core
