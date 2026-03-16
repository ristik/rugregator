#!/usr/bin/env bash
# Set up a single-node BFT Core for E2E testing.
# Run once; re-run only when you need fresh keys/state.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
UBFT="$REPO_ROOT/bft-core/build/ubft"
E2E_DATA="$REPO_ROOT/e2e-data"
ROOT_HOME="$E2E_DATA/root-node"
AGG_HOME="$E2E_DATA/agg-node"
SDK_E2E="$REPO_ROOT/state-transition-sdk/tests/e2e"

if [ ! -f "$UBFT" ]; then
  echo "ubft binary not found at $UBFT. Building..."
  (cd "$REPO_ROOT/bft-core" && make build)
fi

echo "==> Cleaning previous E2E data"
rm -rf "$E2E_DATA"
mkdir -p "$ROOT_HOME" "$AGG_HOME"

NETWORK_ID=3
PARTITION_ID=1
PARTITION_TYPE_ID=1
SHARD_ID="0x80"
TRUST_EPOCH=1
SHARD_EPOCH=0

# ── Root node (BFT consensus) ─────────────────────────────────────────────────
echo "==> Generating root node keys and node-info"
"$UBFT" root-node init --generate --home "$ROOT_HOME"

echo "==> Generating trust-base"
"$UBFT" trust-base generate \
  --network-id "$NETWORK_ID" \
  --node-info "$ROOT_HOME/node-info.json" \
  --epoch "$TRUST_EPOCH" \
  --epoch-start 1 \
  --home "$ROOT_HOME"

echo "==> Signing trust-base with root node key"
"$UBFT" trust-base sign \
  --home "$ROOT_HOME" \
  --trust-base "$ROOT_HOME/trust-base.json"

echo "==> Verifying trust-base"
"$UBFT" trust-base verify \
  --trust-base "$ROOT_HOME/trust-base.json"

ROOT_NODE_ID=$("$UBFT" node-id --home "$ROOT_HOME")
echo "    Root node PeerId: $ROOT_NODE_ID"

# ── Aggregator node (partition validator / shard node) ────────────────────────
echo ""
echo "==> Generating aggregator node keys and node-info"
"$UBFT" shard-node init --generate --home "$AGG_HOME"

AGG_NODE_ID=$("$UBFT" node-id --home "$AGG_HOME")
echo "    Aggregator PeerId: $AGG_NODE_ID"

# ── Shard config (includes aggregator as the shard validator) ─────────────────
echo ""
echo "==> Generating shard config (partition $PARTITION_ID, epoch=$SHARD_EPOCH, validator=$AGG_NODE_ID)"
"$UBFT" shard-conf generate \
  --network-id "$NETWORK_ID" \
  --partition-id "$PARTITION_ID" \
  --partition-type-id "$PARTITION_TYPE_ID" \
  --shard-id "$SHARD_ID" \
  --epoch "$SHARD_EPOCH" \
  --epoch-start 1 \
  --node-info "$AGG_HOME/node-info.json" \
  --home "$ROOT_HOME"

# ── Aggregator config ─────────────────────────────────────────────────────────
echo ""
echo "==> Writing aggregator config"
cat > "$E2E_DATA/aggregator.env" <<EOF
AGGREGATOR_LISTEN=0.0.0.0:3000
AGGREGATOR_BFT_MODE=live
AGGREGATOR_PARTITION_ID=$PARTITION_ID
AGGREGATOR_BFT_PEER_ID=$ROOT_NODE_ID
AGGREGATOR_BFT_ADDR=/ip4/127.0.0.1/tcp/26652
AGGREGATOR_P2P_ADDR=/ip4/0.0.0.0/tcp/0
AGGREGATOR_AUTH_KEY=$(jq -r '.authKey.privateKey' "$AGG_HOME/keys.json" | sed 's/0x//')
AGGREGATOR_SIG_KEY=$(jq -r '.sigKey.privateKey' "$AGG_HOME/keys.json" | sed 's/0x//')
EOF
echo "    Aggregator env: $E2E_DATA/aggregator.env"

# ── Copy trust-base.json to SDK test directory ────────────────────────────────
cp "$ROOT_HOME/trust-base.json" "$SDK_E2E/trust-base.json"
echo "    trust-base.json copied to $SDK_E2E/"

echo ""
echo "✓ E2E setup complete!"
echo "  Root node:    $ROOT_HOME  (PeerId: $ROOT_NODE_ID)"
echo "  Aggregator:   $AGG_HOME   (PeerId: $AGG_NODE_ID)"
echo "  BFT addr:     /ip4/127.0.0.1/tcp/26652"
echo ""
echo "Next:"
echo "  scripts/e2e/start-bft-core.sh   (keep running in terminal 1)"
echo "  scripts/e2e/start-aggregator.sh  (keep running in terminal 2)"
echo "  scripts/e2e/run-e2e-test.sh      (from terminal 3)"
