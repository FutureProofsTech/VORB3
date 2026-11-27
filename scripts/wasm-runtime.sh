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
feature_args=(--features bench-api)
if [ -n "${VORB3_FEATURES:-}" ]; then
  feature_args=(--features "$VORB3_FEATURES,bench-api")
fi

cargo test -p vorb3 --target wasm32-wasip1 --release "${feature_args[@]}" --lib --offline
for test in attack bench_api blake3 field_diff field keys model_diff profile rain \
  redteam sign signature nist_profile; do
  cargo test -p vorb3 --target wasm32-wasip1 --release "${feature_args[@]}" \
    --test "$test" --offline
done
printf '== WASI 32 KiB wasm stack: sign+verify KAT ==\n'
if [ -n "${VORB3_FEATURES:-}" ]; then
  CARGO_TARGET_WASM32_WASIP1_RUNNER='wasmtime run --dir . -W max-wasm-stack=32768' \
    cargo test -p vorb3 --target wasm32-wasip1 --release "${feature_args[@]}" \
    --test nist_profile profile_constants_and_kat --offline
else
  CARGO_TARGET_WASM32_WASIP1_RUNNER='wasmtime run --dir . -W max-wasm-stack=32768' \
    cargo test -p vorb3 --target wasm32-wasip1 --release \
    --test sign --offline
fi

printf 'WASM-RUNTIME PASS (thread-stack test not applicable on WASI preview1;\n'
printf 'single-thread sign+verify passes with a 32 KiB wasm stack)\n'
