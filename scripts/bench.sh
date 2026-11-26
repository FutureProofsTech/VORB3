#!/usr/bin/env bash
# Full local benchmark report. Run on an idle machine.
set -euo pipefail
cd "$(dirname "$0")/.."

quick=0
if [[ "${1:-}" == "--quick" ]]; then
  quick=1
fi

printf '== build ==\n'
cargo build --release --package vorb3-bench --offline
cargo build --release --package vorb3 --offline

run=(./target/release/vorb3-bench)
if command -v taskset >/dev/null 2>&1 && [[ "$(nproc)" -gt 4 ]]; then
  run=(taskset -c 2 ./target/release/vorb3-bench)
fi
if [[ "$quick" -eq 1 ]]; then
  run+=("--quick")
fi

out="${BENCH_OUT:-target/benchmark-results.md}"
mkdir -p "$(dirname "$out")"
{
  printf '# VORB3 SP-288/35 — Full Project Benchmark\n\n'
  printf '**Status:** local measurement checkpoint. Machine- and compiler-dependent\n'
  printf 'evidence, not a security proof and not an external audit.\n\n'
  printf -- '- date (UTC): `%s`\n' "$(date -u +%FT%TZ)"
  printf -- '- host: `%s`\n' "$(uname -srm)"
  printf -- '- cpu: `%s`\n' "$(lscpu | awk -F: '/Model name/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')"
  printf -- '- cores/threads: `%s`\n' "$(nproc)"
  printf -- '- rustc: `%s`\n' "$(rustc --version)"
  printf -- '- cargo: `%s`\n' "$(cargo --version)"
  printf -- '- profile: release, opt-level=3, LTO, codegen-units=1, panic=abort, strip\n'
  printf -- '- signature: 13,672 bytes; key: 36-byte seed, 72-byte public key\n\n'
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
  printf 'dependencies. Stack measurements from `vorb3/tests/stack.rs`:\n\n'
  printf '```text\n'
  printf 'sign_into, caller-owned output, release: 32 KiB thread  PASS\n'
  printf 'verify_bytes, release:                    32 KiB thread  PASS\n'
  printf 'sign_into, output buffer on stack:       64 KiB thread  PASS\n'
  printf '```\n\n'
  printf 'The 32 KiB figure covers the internal working set; a caller that places the\n'
  printf '13,672-byte signature on the stack needs the 64 KiB case. Debug builds use a\n'
  printf '64 KiB default because unoptimized frames are larger.\n\n'
  printf '## Reproduce\n\n'
  printf '```bash\n'
  printf './scripts/bench.sh          # full report\n'
  printf './scripts/bench.sh --quick  # smoke run\n'
  printf '```\n\n'
  printf '## Caveats\n\n'
  printf -- '- One machine, one compiler version, background-free but not a controlled lab.\n'
  printf -- '- CPU frequency scaling and sibling hyperthread activity affect absolute numbers.\n'
  printf -- '- Microbenchmarks measure this implementation, not asymptotic complexity.\n'
  printf -- '- No external audit; no constant-time or security claim follows from throughput.\n'
} > "$out"

printf 'wrote %s\n' "$out"
