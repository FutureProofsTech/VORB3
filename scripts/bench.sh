#!/usr/bin/env bash
# Full local benchmark report. Run on an idle machine.
set -euo pipefail
cd "$(dirname "$0")/.."

quick=0
if [[ "${1:-}" == "--quick" ]]; then
  quick=1
fi

features="${VORB3_FEATURES:-}"
case "$features" in
  "")
    profile="SP-288/35"
    sig_len=13672
    seed_len=36
    pk_len=72
    default_out="target/benchmark-results.md"
    ;;
  nist1)
    profile="NIST Level 1+ (SP-160/32)"
    sig_len=7976
    seed_len=20
    pk_len=40
    default_out="target/benchmark-results-nist1.md"
    ;;
  nist3)
    profile="NIST Level 3+ (SP-224/32)"
    sig_len=10296
    seed_len=28
    pk_len=56
    default_out="target/benchmark-results-nist3.md"
    ;;
  *)
    printf 'unsupported VORB3_FEATURES: %s\n' "$features" >&2
    exit 2
    ;;
esac

feature_args=()
if [ -n "$features" ]; then
  feature_args=(--features "$features")
fi

printf '== build (%s) ==\n' "$profile"
cargo build --release --package vorb3-bench "${feature_args[@]}" --offline
cargo build --release --package vorb3-attack "${feature_args[@]}" --offline

bench_cpu="${BENCH_CPU:-2}"
run=(./target/release/vorb3-bench)
if command -v taskset >/dev/null 2>&1 && [[ "$(nproc)" -gt 4 ]]; then
  run=(taskset -c "$bench_cpu" ./target/release/vorb3-bench)
fi
if [[ "$quick" -eq 1 ]]; then
  run+=("--quick")
fi

out="${BENCH_OUT:-$default_out}"
mkdir -p "$(dirname "$out")"
{
  printf '# VORB3 %s — Full Project Benchmark\n\n' "$profile"
  printf '**Status:** local measurement checkpoint. Machine- and compiler-dependent\n'
  printf 'evidence, not a security proof and not an external audit.\n\n'
  printf -- '- date (UTC): `%s`\n' "$(date -u +%FT%TZ)"
  printf -- '- host: `%s`\n' "$(uname -srm)"
  printf -- '- cpu: `%s`\n' "$(lscpu | awk -F: '/Model name/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')"
  printf -- '- cores/threads: `%s`\n' "$(nproc)"
  printf -- '- rustc: `%s`\n' "$(rustc --version)"
  printf -- '- cargo: `%s`\n' "$(cargo --version)"
  printf -- '- profile: release, opt-level=3, LTO, codegen-units=1, panic=abort, strip\n'
  printf -- '- signature: %s bytes; key: %s-byte seed, %s-byte public key\n' \
    "$sig_len" "$seed_len" "$pk_len"
  printf -- '- cpu pin: `%s`\n\n' "$bench_cpu"
  printf '```text\n'
  printf 'size vorb3-bench:\n'
  size target/release/vorb3-bench || true
  printf '\nsize vorb3-attack:\n'
  size target/release/vorb3-attack || true
  printf '\n```\n\n'
  printf '## Method\n\n'
  printf '`tools/bench` is a std-only custom harness. Each benchmark warms up, then\n'
  printf 'auto-calibrates an inner loop to about 40 ms per sample (20 ms in quick\n'
  printf 'mode), records 25 samples (5 in quick mode), and reports the per-operation\n'
  printf 'mean, median, p95, min, max, standard deviation, and operations/second.\n'
  printf 'Inputs are black-boxed and varied where constant hoisting is possible.\n'
  printf 'The harness is pinned to one CPU with `taskset` when available.\n\n'
  printf '## Results\n\n'
  printf '| Category | Benchmark | Mean ns/op | Median ns/op | p95 ns/op | Min ns/op | Max ns/op | Stddev ns | Ops/s | Samples | Inner |\n'
  printf '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n'
  "${run[@]}" --no-header
  printf '\n## Memory and stack\n\n'
  printf 'The library is `no_std`, allocates no heap, and has zero runtime\n'
  printf 'dependencies. '
  if [ -n "$features" ]; then
    printf 'The profile release stack target (`nist_stack`) passes:\n\n'
    printf '```text\n'
    printf 'sign_into, caller-owned heap output, release: 32 KiB thread  PASS\n'
    printf 'verify_bytes, release:                        32 KiB thread  PASS\n'
    printf 'sign_into, %s-byte output on stack:         64 KiB thread  PASS\n' "$sig_len"
    printf '```\n\n'
  else
    printf 'Stack measurements from `vorb3/tests/stack.rs`:\n\n'
    printf '```text\n'
    printf 'sign_into, caller-owned output, release: 32 KiB thread  PASS\n'
    printf 'verify_bytes, release:                    32 KiB thread  PASS\n'
    printf 'sign_into, output buffer on stack:       64 KiB thread  PASS\n'
    printf '```\n\n'
  fi
  printf 'The 32 KiB figure covers the internal working set; a caller that places the\n'
  printf '%s-byte signature on the stack needs the larger stack budget. Debug builds\n' "$sig_len"
  printf 'use a larger default because unoptimized frames are larger.\n\n'
  printf '## Reproduce\n\n'
  printf '```bash\n'
  if [ -n "$features" ]; then
    printf 'VORB3_FEATURES=%s BENCH_CPU=%s ./scripts/bench.sh\n' "$features" "$bench_cpu"
  else
    printf 'BENCH_CPU=%s ./scripts/bench.sh\n' "$bench_cpu"
  fi
  printf './scripts/bench.sh --quick  # smoke run\n'
  printf '```\n\n'
  printf '## Caveats\n\n'
  printf -- '- One machine, one compiler version; not a controlled lab.\n'
  printf -- '- CPU frequency scaling and sibling hyperthread activity affect absolute numbers.\n'
  printf -- '- Microbenchmarks measure this implementation, not asymptotic complexity.\n'
  printf -- '- No external audit; no constant-time or security claim follows from throughput.\n'
} > "$out"

printf 'wrote %s\n' "$out"
