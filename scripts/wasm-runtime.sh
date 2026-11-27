#!/usr/bin/env bash
# Run the functional WASI test graph under wasmtime. The stack test is omitted:
# WASI preview1 has no user-controlled thread stack, so that host-specific test
# is not applicable.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v wasmtime >/dev/null || {
  printf 'wasmtime is required (https://wasmtime.dev/)\n' >&2
  exit 1
}
export CARGO_TARGET_WASM32_WASIP1_RUNNER='wasmtime run --dir .'

cargo test -p vorb3 --target wasm32-wasip1 --release --all-features --lib --offline
for test in attack bench_api blake3 field_diff field keys model_diff profile rain \
  redteam sign signature; do
  cargo test -p vorb3 --target wasm32-wasip1 --release --all-features \
    --test "$test" --offline
done
printf 'WASM-RUNTIME PASS (stack test not applicable on WASI preview1)\n'
