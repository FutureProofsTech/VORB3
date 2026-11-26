#!/usr/bin/env bash
# Local red-team umbrella. Heavy campaigns are opt-in.
set -euo pipefail
cd "$(dirname "$0")/.."

printf '== gates ==\n'
./scripts/gate.sh
./scripts/gate-deep.sh

printf '== nextest ==\n'
cargo nextest run --workspace --all-features --offline

printf '== dependency/license scans ==\n'
cargo audit --no-fetch
cargo deny check advisories licenses bans sources

printf '== coverage ==\n'
./scripts/coverage.sh

printf '== exhaustive single-bit signature sweep ==\n'
./target/release/vorb3-attack bitflip

printf '== timing ==\n'
./target/release/vorb3-attack dudect 20000
./target/release/vorb3-attack dudect-verify 20000

printf '== cachegrind/assembly ==\n'
./scripts/sidechannel.sh

if [[ "${1:-}" == "--fuzz" ]]; then
  printf '== multi-target fuzz campaign ==\n'
  ./scripts/fuzz-campaign.sh
fi

if [[ "${1:-}" == "--mutants" ]]; then
  printf '== mutation testing ==\n'
  RUST_TEST_THREADS=1 cargo mutants -p vorb3 --test-tool cargo \
    --jobs 8 --timeout 8 --build-timeout 30 --copy-target false \
    -E 'kani_proofs|bench_api|bench::|prefix_tests|::tests::'
fi

printf 'REDTEAM GATE COMPLETE\n'
