#!/usr/bin/env bash
# Deep phase-boundary gate: formal + Miri. Slower than scripts/gate.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

printf '== Kani ==\n'
cargo kani

printf '== Miri: CT ==\n'
cargo +nightly miri test --lib ct::tests

printf '== Miri: zeroization ==\n'
cargo +nightly miri test --lib zeroize::tests

printf '== Miri: profile ==\n'
cargo +nightly miri test --test profile

printf '== Miri: short BLAKE3 ==\n'
cargo +nightly miri test --test blake3 blake3_xof_keyed_derive

printf '== Miri: field/keys/signature ==\n'
MIRIFLAGS='-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check' \
  cargo +nightly miri test --test field
MIRIFLAGS='-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check' \
  cargo +nightly miri test --test keys
MIRIFLAGS='-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check' \
  cargo +nightly miri test --test signature

printf 'DEEP GATE: PASS\n'
