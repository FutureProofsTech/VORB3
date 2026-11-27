#!/usr/bin/env bash
# Gate for one NIST-tier profile pack: nist1 or nist3.
set -euo pipefail
cd "$(dirname "$0")/.."

profile="${1:-}"
case "$profile" in
  nist1|nist3) ;;
  *) printf 'usage: %s nist1|nist3\n' "$0" >&2; exit 2 ;;
esac

printf '== fmt ==\n'
cargo fmt --all --check

printf '== clippy (%s) ==\n' "$profile"
cargo clippy -p vorb3 --all-targets --features "$profile" --offline -- -D warnings

printf '== all targets (%s) ==\n' "$profile"
cargo test -p vorb3 --all-targets --features "$profile" --offline

printf '== bench-api (%s) ==\n' "$profile"
cargo test -p vorb3 --features "$profile,bench-api" --test nist_bench_api --offline

printf '== 32 KiB release stack (%s) ==\n' "$profile"
VORB3_STACK_KB=32 cargo test -p vorb3 --features "$profile" --release --test nist_stack --offline -- --ignored

printf '== Kani (%s) ==\n' "$profile"
cargo kani -p vorb3 --features "$profile"

printf '== ASan (%s) ==\n' "$profile"
RUSTFLAGS='-Zsanitizer=address' cargo +nightly test -p vorb3 --features "$profile" --all-targets --offline

printf '== coverage (%s) ==\n' "$profile"
CARGO_PROFILE_TEST_OPT_LEVEL=0 VORB3_STACK_KB=256 \
  cargo llvm-cov -p vorb3 --features "$profile,bench-api" --tests --summary-only --offline

printf 'NIST GATE PASS: %s\n' "$profile"
