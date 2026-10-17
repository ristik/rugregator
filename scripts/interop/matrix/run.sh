#!/usr/bin/env bash
# Interop matrix: one server x clients. Results: $OUT/<server>-<client>.jsonl (one JSON line per scenario).
#
#   run.sh s1 [go] [rust] [js]       S1 = rugregator (this checkout), started fresh for every client
#   run.sh s2 [go] [rust] [js]       S2 = aggregator-go with real BFT, already started with s2/s2.sh up
#
# Environment (checkouts are never modified except for the copied driver files):
#   AGG_GO_DIR    aggregator-go checkout   (Go client; also needs `go`)
#   SDK_RUST_DIR  state-transition-sdk-rust checkout (`cargo`)
#   SDK_JS_DIR    state-transition-sdk-js checkout   (`node`, `npm ci` done)
#   OUT           results directory (default ./results)
#   S1: RUG_TARGET (default <repo>/target/release; needs `aggregator` and `stub-anchor`, built with
#       `cargo build --release -p uni-aggregator --bins`), S1_PORT (default 18080)
#   S2: S2_URL (default http://127.0.0.1:13000), S2_TRUSTBASE (printed by s2.sh up), S2_PARTITION (default 7)
#   IX_N (requests per client, default 6)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
OUT="${OUT:-$HERE/results}"; mkdir -p "$OUT"
server="${1:?usage: run.sh s1|s2 [go] [rust] [js]}"; shift
clients=("$@"); [ ${#clients[@]} -gt 0 ] || clients=(go rust js)
export IX_CASES="$HERE/envelope_cases.json" IX_N="${IX_N:-6}"

start_s1() {
  local target="${RUG_TARGET:-$REPO/target/release}" port="${S1_PORT:-18080}"
  S1_DIR="$(mktemp -d)"
  "$target/stub-anchor" trust-base > "$S1_DIR/trust-base.json"
  "$target/aggregator" --bft-mode stub --listen "127.0.0.1:$port" --round-duration-ms 1000 > "$S1_DIR/server.log" 2>&1 &
  S1_PID=$!
  for _ in $(seq 1 50); do
    curl -fsS -m 2 -X POST "http://127.0.0.1:$port/" -d '{"jsonrpc":"2.0","id":1,"method":"get_block_height","params":{}}' >/dev/null 2>&1 && break
    sleep 0.2
  done
  export IX_URL="http://127.0.0.1:$port" IX_TRUSTBASE="$S1_DIR/trust-base.json" IX_PARTITION=1 IX_RETAINED=32 IX_ROUND_MS=1000
}
stop_s1() { [ -n "${S1_PID:-}" ] && kill "$S1_PID" 2>/dev/null; wait "$S1_PID" 2>/dev/null; cp "$S1_DIR/server.log" "$OUT/$server-$1-server.log" 2>/dev/null; S1_PID=; }

run_client() {
  local c="$1" f="$OUT/$server-$c.jsonl"
  : > "$f"
  case "$c" in
    go)
      mkdir -p "$AGG_GO_DIR/cmd/interop-matrix"
      cp "$HERE/go/main.go" "$AGG_GO_DIR/cmd/interop-matrix/main.go"
      (cd "$AGG_GO_DIR" && go run ./cmd/interop-matrix) 2> "$OUT/$server-$c.stderr" | grep '^{"client"' > "$f" ;;
    rust)
      cp "$HERE/rust/interop_matrix.rs" "$SDK_RUST_DIR/tests/interop_matrix.rs"
      (cd "$SDK_RUST_DIR" && cargo test --features http --test interop_matrix -- --ignored --nocapture) 2> "$OUT/$server-$c.stderr" | grep '^{"client"' > "$f" ;;
    js)
      mkdir -p "$SDK_JS_DIR/tests/interop"
      cp "$HERE/js/InteropMatrixTest.ts" "$SDK_JS_DIR/tests/interop/InteropMatrixTest.ts"
      (cd "$SDK_JS_DIR" && IX_OUT="$f" npx jest --testPathPatterns=tests/interop --coverage=false --runInBand) > "$OUT/$server-$c.stderr" 2>&1 ;;
  esac
  echo "== $server x $c: $(grep -c '"PASS"' "$f") PASS, $(grep -c '"FAIL"' "$f") FAIL, $(grep -c '"N-A"' "$f") N-A" >&2
}

case "$server" in
  s1) for c in "${clients[@]}"; do start_s1; run_client "$c"; stop_s1 "$c"; done ;;
  s2)
    export IX_URL="${S2_URL:-http://127.0.0.1:13000}" IX_TRUSTBASE="${S2_TRUSTBASE:?S2_TRUSTBASE}" IX_PARTITION="${S2_PARTITION:-7}" IX_RETAINED="${S2_RETAINED:-16}" IX_ROUND_MS=1000
    for c in "${clients[@]}"; do run_client "$c"; done ;;
  *) echo "unknown server $server" >&2; exit 2 ;;
esac
