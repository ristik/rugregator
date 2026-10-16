#!/usr/bin/env bash
# Start/stop S2 (aggregator-go + real BFT root, unsharded) for the interop matrix.
#   s2.sh up    AGG_GO_DIR=<aggregator-go checkout> S2_DATA=<empty dir> [S2_PORT=13000]
#   s2.sh down
# S2_DATA must be under $HOME (the colima VM only mounts the home directory).
# `up` takes the shared Docker lock (/tmp/uc-docker.lock, see orchestration/dev-rules.md) and keeps it until
# `down`; it prints nothing on stdout except the trust base path. The trust base is $S2_DATA/genesis/trust-base.json.
set -euo pipefail
cd "$(dirname "$0")"
export S2_DIR="$PWD" S2_PORT="${S2_PORT:-13000}" USER_UID="$(id -u)" USER_GID="$(id -g)"
export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.colima/default/docker.sock}"
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock TESTCONTAINERS_RYUK_DISABLED=true
: "${AGG_GO_DIR:?}" "${S2_DATA:?}"
LOCK=/tmp/uc-docker.lock
compose() { docker compose -p ixs2 -f docker-compose.yml "$@"; }

case "${1:-}" in
up)
  mkdir -p "$S2_DATA/genesis" "$S2_DATA/genesis-root"
  chmod -R 777 "$S2_DATA"
  until mkdir "$LOCK" 2>/dev/null; do sleep 15; done
  touch "$S2_DATA/lock-held"
  ok=0
  # a failed start gives the lock and the containers back; a successful one keeps the lock until `down`
  trap 'if [ "$ok" != 1 ]; then compose logs --no-color > "$S2_DATA/compose-failed.log" 2>&1 || true; compose down -v --remove-orphans >&2 || true; rm -f "$S2_DATA/lock-held"; rmdir "$LOCK" 2>/dev/null || true; fi' EXIT
  compose up -d --build >&2
  for _ in $(seq 1 120); do
    if curl -fsS -m 3 -X POST "http://127.0.0.1:$S2_PORT/" -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"get_block_height","params":{}}' 2>/dev/null | grep -q blockNumber; then
      ok=1
      echo "$S2_DATA/genesis/trust-base.json"
      exit 0
    fi
    sleep 5
  done
  compose logs --tail 60 >&2
  exit 1
  ;;
down)
  compose logs --no-color > "$S2_DATA/compose.log" 2>&1 || true
  compose down -v --remove-orphans >&2 || true
  if [ -f "$S2_DATA/lock-held" ]; then rm -f "$S2_DATA/lock-held"; rmdir "$LOCK" 2>/dev/null || true; fi
  ;;
*) echo "usage: s2.sh up|down" >&2; exit 2 ;;
esac
