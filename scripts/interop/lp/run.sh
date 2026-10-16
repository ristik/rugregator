#!/usr/bin/env bash
# Long-poll interop: one server x the Rust driver. Results: $OUT/<tag>-rust.jsonl
#
#   run.sh s1lp                     rugregator (reservation-only), started fresh from RUG_TARGET
#   run.sh s2lp|s2base|s2cap0       aggregator-go already started with ../matrix/s2/s2.sh up
#                                   (s2base = non-inclusion a3527521; s2lp = long-poll branch;
#                                    s2cap0 = long-poll branch started with LONG_POLL_MAX_WAITERS=0)
#
# Environment: SDK_RUST_DIR (state-transition-sdk-rust checkout; the build puts a target/ there),
#   OUT (default ./results), S1: RUG_TARGET (default <repo>/target/release), S1_PORT (default 18080)
#   S2: S2_URL (default http://127.0.0.1:13000), S2_TRUSTBASE (printed by s2.sh up)
#   IX_SCEN (e.g. L7), IX_N, IX_RATE, IX_ROUND_MS
# Exit status: 0 only if the driver exited 0, printed at least one line and no line is FAIL.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
OUT="${OUT:-$HERE/results}"; mkdir -p "$OUT"
server="${1:?usage: run.sh s1lp|s2lp|s2base|s2cap0}"
: "${SDK_RUST_DIR:?}"
export IX_SERVER="$server" IX_CASES="$REPO/scripts/interop/matrix/envelope_cases.json"
tag="$server${IX_SCEN:+-$(echo "$IX_SCEN" | tr ',' '_')}"
DEST="$SDK_RUST_DIR/tests/interop_lp.rs"
dir=""; pid=""; copied=0

cleanup() {
  [ -n "$pid" ] && { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; }
  [ -n "$dir" ] && { cp "$dir/server.log" "$OUT/$tag-server.log" 2>/dev/null; rm -rf "$dir"; }
  [ "$copied" = 1 ] && rm -f "$DEST"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if [ -e "$DEST" ] && ! cmp -s "$DEST" "$HERE/rust/interop_lp.rs"; then
  echo "refusing to overwrite a different $DEST" >&2; exit 2
fi

if [ "$server" = s1lp ]; then
  target="${RUG_TARGET:-$REPO/target/release}"; port="${S1_PORT:-18080}"
  if curl -fsS -m 2 -X POST "http://127.0.0.1:$port/" -d '{}' >/dev/null 2>&1; then
    echo "port $port already answers: refusing to test an unknown server (set S1_PORT)" >&2; exit 2
  fi
  dir="$(mktemp -d)"
  "$target/stub-anchor" trust-base > "$dir/trust-base.json"
  "$target/aggregator" --bft-mode stub --listen "127.0.0.1:$port" --round-duration-ms 1000 > "$dir/server.log" 2>&1 &
  pid=$!
  ready=0
  for _ in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || break
    curl -fsS -m 2 -X POST "http://127.0.0.1:$port/" -d '{"jsonrpc":"2.0","id":1,"method":"get_block_height","params":{}}' >/dev/null 2>&1 && { ready=1; break; }
    sleep 0.2
  done
  if [ "$ready" != 1 ] || ! kill -0 "$pid" 2>/dev/null; then
    echo "S1 did not start (see $OUT/$tag-server.log)" >&2; exit 2
  fi
  export IX_URL="http://127.0.0.1:$port" IX_TRUSTBASE="$dir/trust-base.json" IX_ROUND_MS=1000
else
  export IX_URL="${S2_URL:-http://127.0.0.1:13000}" IX_TRUSTBASE="${S2_TRUSTBASE:?S2_TRUSTBASE}" IX_ROUND_MS="${IX_ROUND_MS:-1000}"
fi

f="$OUT/$tag-rust.jsonl"
cp "$HERE/rust/interop_lp.rs" "$DEST"; copied=1
(cd "$SDK_RUST_DIR" && cargo test --features http --test interop_lp -- --ignored --nocapture) 2> "$OUT/$tag-rust.stderr" | grep '^{.*"client":"rust"' > "$f"
status=("${PIPESTATUS[@]}")
cargo_status="${status[0]}"
pass=$(grep -c '"status":"PASS"' "$f"); fail=$(grep -c '"status":"FAIL"' "$f"); na=$(grep -c '"status":"N-A"' "$f")
lines=$(grep -c '"status"' "$f")
echo "== $tag x rust: $pass PASS, $fail FAIL, $na N-A (driver exit $cargo_status)" >&2
if [ "$cargo_status" != 0 ]; then echo "FAIL: driver exited $cargo_status, see $OUT/$tag-rust.stderr" >&2; exit 1; fi
if [ "$lines" = 0 ]; then echo "FAIL: the driver printed no result line, see $OUT/$tag-rust.stderr" >&2; exit 1; fi
[ "$fail" = 0 ] || exit 1
