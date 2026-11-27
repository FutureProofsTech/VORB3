#!/usr/bin/env bash
# Local Phase-1 gate. No network, no third-party crates.
set -euo pipefail
cd "$(dirname "$0")/.."

printf '== fmt ==\n'
cargo fmt --all --check

printf '== clippy ==\n'
cargo clippy --workspace --all-targets --features "${VORB3_FEATURES:-bench-api}" --locked --offline -- -D warnings

printf '== tests ==\n'
cargo test --workspace --features "${VORB3_FEATURES:-bench-api}" --locked --offline

printf '== stack target (release, 32 KiB) ==\n'
stack_test=stack
profile_args=()
if [ -n "${VORB3_FEATURES:-}" ]; then
  stack_test=nist_stack
  profile_args=(--features "$VORB3_FEATURES")
fi
if [ "$stack_test" = nist_stack ]; then
  VORB3_STACK_KB=32 cargo test --package vorb3 --test "$stack_test" --release \
    --features "${VORB3_FEATURES:-bench-api}" --locked --offline -- --ignored
else
  VORB3_STACK_KB=32 cargo test --package vorb3 --test "$stack_test" --release \
    --features "${VORB3_FEATURES:-bench-api}" --locked --offline
fi

printf '== release build ==\n'
cargo build --workspace --release --features "${VORB3_FEATURES:-bench-api}" --locked --offline

printf '== bare-metal no_std lib build ==\n'
cargo build --package vorb3 --lib --target thumbv7em-none-eabihf --locked --offline \
  "${profile_args[@]}"

printf '== dependency proof ==\n'
./scripts/check-no-deps.sh

printf 'LOCAL GATE (PHASE 1-7): PASS\n'
