#!/usr/bin/env bash
# Phase-9 style side-channel checkpoint. Run after fuzzing, on a quiet machine.
set -euo pipefail
cd "$(dirname "$0")/.."

printf '== dudect-style timing smoke ==\n'
./target/release/vorb3-attack dudect 5000

printf '== cachegrind fixed benchmark ==\n'
valgrind --tool=cachegrind --cache-sim=yes --branch-sim=yes \
  --cachegrind-out-file=/tmp/opencode/vorb3.cachegrind \
  ./target/release/vorb3-attack bench

printf '== assembly emission ==\n'
cargo rustc --release --lib --offline -- --emit asm

printf '== branch scan (manual review input) ==\n'
find target/release/deps -name 'vorb3-*.s' -print -quit | while read -r asm; do
  printf '%s\n' "$asm"
  grep -E '^\s+j[a-z]+' "$asm" | head -40 || true
done

printf 'SIDE-CHANNEL CHECKPOINT COMPLETE (review the counts/assembly manually)\n'
