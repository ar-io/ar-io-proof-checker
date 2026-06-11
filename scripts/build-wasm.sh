#!/usr/bin/env bash
# Reproducible WASM build of the Go reference verifier (ar-io-agent pkg/proof)
# at the commit pinned in wasm/PIN. Output: src/wasm/ario-proof.wasm.
#
#   AGENT_SRC=../ar-io-agent bash scripts/build-wasm.sh
#
# The agent repo is read/build-only for this repo: the pinned commit is
# materialized as a detached, temporary `git worktree` (per the v1.2
# shared-checkout discipline) — the sibling checkout's working tree is never
# touched. Build is -trimpath so the output is reproducible across machines;
# the binary's SHA-256 is recorded in wasm/PIN and re-verified by
# test/wasm-agreement.test.ts on every test run.
set -euo pipefail

cd "$(dirname "$0")/.."
AGENT_SRC="${AGENT_SRC:-../ar-io-agent}"
PIN_FILE="wasm/PIN"
OUT="src/wasm/ario-proof.wasm"

pin_commit="$(grep '^agent_commit=' "$PIN_FILE" | cut -d= -f2)"
[ -n "$pin_commit" ] || { echo "no agent_commit in $PIN_FILE" >&2; exit 1; }

git -C "$AGENT_SRC" rev-parse --verify "${pin_commit}^{commit}" >/dev/null \
  || { echo "pinned commit $pin_commit not present in $AGENT_SRC — git fetch first" >&2; exit 1; }

rm -rf wasm/agent-src
git -C "$AGENT_SRC" worktree add --detach "$(pwd)/wasm/agent-src" "$pin_commit" >/dev/null
trap 'git -C "$AGENT_SRC" worktree remove --force "$(pwd)/wasm/agent-src" >/dev/null 2>&1 || true' EXIT

(cd wasm && GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -o "../$OUT" .)

sha="$(sha256sum "$OUT" | cut -d' ' -f1)"
goversion="$(cd wasm && go env GOVERSION)"
sed -i "s/^wasm_sha256=.*/wasm_sha256=$sha/; s/^go_version=.*/go_version=$goversion/" "$PIN_FILE"

echo "built  $OUT ($(stat -c%s "$OUT") bytes)"
echo "sha256 $sha"
echo "pin    $pin_commit ($goversion)"
