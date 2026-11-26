#!/usr/bin/env bash
# Local Phase-1 gate. No network, no third-party crates.
set -euo pipefail
cd "$(dirname "$0")/.."

printf '== fmt ==\n'
cargo fmt --all --check

printf '== clippy ==\n'
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings

printf '== tests ==\n'
cargo test --workspace --locked --offline

printf '== release build ==\n'
cargo build --workspace --release --locked --offline

printf '== bare-metal no_std lib build ==\n'
cargo build --package vorb3 --lib --target thumbv7em-none-eabihf --locked --offline

printf '== dependency proof ==\n'
./scripts/check-no-deps.sh

printf 'LOCAL GATE (PHASE 1-4): PASS\n'
