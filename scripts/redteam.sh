#!/usr/bin/env bash
# Local red-team umbrella. Heavy campaigns are opt-in.
set -euo pipefail
cd "$(dirname "$0")/.."

printf '== gates ==\n'
./scripts/gate.sh
./scripts/gate-deep.sh

printf '== nextest ==\n'
cargo nextest run --workspace --features bench-api --offline

printf '== dependency/license scans ==\n'
cargo audit --no-fetch
cargo deny check advisories licenses bans sources

printf '== coverage ==\n'
./scripts/coverage.sh

printf '== exhaustive single-bit signature sweep ==\n'
./target/release/vorb3-attack bitflip

printf '== timing ==\n'
./target/release/vorb3-attack dudect 50000
./target/release/vorb3-attack dudect-verify 50000

printf '== cachegrind/assembly ==\n'
./scripts/sidechannel.sh

printf '== ctgrind ==\n'
./scripts/ctgrind.sh

printf '== mutation equivalences (Z3) ==\n'
python3 scripts/verify_mutation_equivalences.py

case "${1:-}" in
  --fuzz)
    printf '== multi-target fuzz campaign ==\n'
    ./scripts/fuzz-campaign.sh
    ;;
  --mutants)
    printf '== mutation testing ==\n'
    RUST_TEST_THREADS=1 cargo mutants -p vorb3 --test-tool cargo \
      --jobs 8 --timeout 15 --build-timeout 60 --copy-target false \
      -E 'kani_proofs|bench_api|bench::|prefix_tests|::tests::'
    ;;
  --cross)
    printf '== cross-architecture runtime ==\n'
    ./scripts/cross-runtime.sh
    printf '== ppc64/Windows runtime ==\n'
    ./scripts/portable-runtime.sh
    ;;
  --wasm)
    printf '== wasm32-wasip1 runtime ==\n'
    ./scripts/wasm-runtime.sh
    ;;
  --all)
    printf '== reproducibility ==\n'
    ./scripts/reproducible.sh
    printf '== SBOM ==\n'
    ./scripts/sbom.sh
    printf '== cross-architecture runtime ==\n'
    ./scripts/cross-runtime.sh
    printf '== ppc64/Windows runtime ==\n'
    ./scripts/portable-runtime.sh
    printf '== wasm32-wasip1 runtime ==\n'
    ./scripts/wasm-runtime.sh
    printf '== AFL++ parse campaign ==\n'
    ./scripts/afl-campaign.sh 300
    printf '== multi-target fuzz campaign ==\n'
    ./scripts/fuzz-campaign.sh
    printf '== mutation testing ==\n'
    RUST_TEST_THREADS=1 cargo mutants -p vorb3 --test-tool cargo \
      --jobs 8 --timeout 15 --build-timeout 60 --copy-target false \
      -E 'kani_proofs|bench_api|bench::|prefix_tests|::tests::'
    ;;
esac

printf 'REDTEAM GATE COMPLETE\n'
