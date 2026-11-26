#!/usr/bin/env bash
# Local side-channel checkpoint. Run on an idle machine; no builds concurrently.
set -euo pipefail
cd "$(dirname "$0")/.."

printf '== dudect: signing (20k) ==\n'
./target/release/vorb3-attack dudect 20000

printf '== dudect: verification (20k) ==\n'
./target/release/vorb3-attack dudect-verify 20000

printf '== cachegrind: fixed key ==\n'
valgrind --tool=cachegrind --cache-sim=yes --branch-sim=yes \
  --cachegrind-out-file=/tmp/opencode/vorb3-fixed.cachegrind \
  ./target/release/vorb3-attack bench

printf '== cachegrind: second key ==\n'
valgrind --tool=cachegrind --cache-sim=yes --branch-sim=yes \
  --cachegrind-out-file=/tmp/opencode/vorb3-other.cachegrind \
  ./target/release/vorb3-attack bench-other

printf '== assembly audit ==\n'
rm -rf /tmp/opencode/vorb3-asm
CARGO_PROFILE_RELEASE_LTO=false CARGO_TARGET_DIR=/tmp/opencode/vorb3-asm \
  cargo rustc -p vorb3 --release --lib --offline -- --emit asm
asm=$(find /tmp/opencode/vorb3-asm -name 'vorb3-*.s' -print -quit)
python3 scripts/asm_audit.py "$asm"

printf 'SIDE-CHANNEL CHECKPOINT COMPLETE (evidence, not a formal proof)\n'
