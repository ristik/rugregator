#!/usr/bin/env bash
# Go client column (A4 `cmd/commitment`): 3 submissions with long-poll on and off against $IX_URL.
# Prints one JSON line per run: {"client":"go","server":..,"longPoll":..,"attempts":..,"elapsed":..,"verified":..}
# usage: AGG_GO_DIR=<aggregator-go long-poll checkout> IX_URL=http://127.0.0.1:13000 go-commitment.sh <server-label> [runs]
set -uo pipefail
label="${1:?server label}"; runs="${2:-3}"
cd "${AGG_GO_DIR:?}"
go build -o "${TMPDIR:-/tmp}/ix-commitment" ./cmd/commitment || exit 1
for lp in true false; do
  for _ in $(seq 1 "$runs"); do
    out="$("${TMPDIR:-/tmp}/ix-commitment" -url "${IX_URL:?}" -timeout 60s -poll-interval 1s -v=false -long-poll=$lp 2>&1)"
    line="$(echo "$out" | grep -E 'Valid inclusion proof received' | tail -1)"
    ok=false; echo "$out" | grep -q 'successfully submitted and verified' && ok=true
    attempts="$(echo "$line" | sed -E 's/.* after ([0-9]+) attempt.*/\1/')"
    elapsed="$(echo "$line" | sed -E 's/.* in ([0-9.a-zµ]+) after.*/\1/')"
    printf '{"client":"go","server":"%s","longPoll":%s,"attempts":"%s","elapsed":"%s","verified":%s}\n' "$label" "$lp" "$attempts" "$elapsed" "$ok"
  done
done
rm -f "${TMPDIR:-/tmp}/ix-commitment"
