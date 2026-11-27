#!/usr/bin/env bash
# Coverage gate/report for the shipped library.
#
# CARGO_PROFILE_TEST_OPT_LEVEL=0 keeps #[inline] wrappers out of the test
# harness so line/function mapping reflects the library rather than inlining.
set -euo pipefail
cd "$(dirname "$0")/.."

export CARGO_PROFILE_TEST_OPT_LEVEL=0
# Coverage instrumentation inflates unoptimized frames; the operational 32 KiB
# stack claim is tested separately in the release gate.
export VORB3_STACK_KB=256
out=target/coverage
mkdir -p "$out"

printf '== clean coverage data ==\n'
cargo llvm-cov clean --workspace >/dev/null

printf '== production profile (default features) ==\n'
cargo llvm-cov -p vorb3 --tests --summary-only --offline \
  --fail-under-functions 100 --fail-under-lines 99.5 \
  | tee "$out/summary-default.txt"

printf '== profile features (bench-api or VORB3_COVERAGE_FEATURES) ==\n'
cargo llvm-cov -p vorb3 --features "${VORB3_COVERAGE_FEATURES:-bench-api}" --tests --summary-only --offline \
  --fail-under-functions 100 --fail-under-lines 99.5 \
  | tee "$out/summary-profile.txt"

printf '== artifacts ==\n'
cargo llvm-cov report --html --output-dir "$out" >/dev/null
cargo llvm-cov report --json --output-path "$out/coverage.json" >/dev/null
cargo llvm-cov report --lcov --output-path "$out/lcov.info" >/dev/null
cargo llvm-cov report --text --show-missing-lines --output-path "$out/missing-lines.txt" >/dev/null

if [[ "${1:-}" == "--workspace" ]]; then
  printf '== workspace including dev tools ==\n'
  cargo llvm-cov --workspace --features "${VORB3_COVERAGE_FEATURES:-bench-api}" --tests --summary-only --offline \
    | tee "$out/summary-workspace.txt"
fi

printf 'COVERAGE GATE COMPLETE\n'
printf 'summary: %s\n' "$out/summary-profile.txt"
printf 'html:    %s\n' "$out/html/index.html"
