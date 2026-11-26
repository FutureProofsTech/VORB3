# VORB3 SP-288/35 — Coverage Report

**Status:** local coverage checkpoint (2026-11-26).
**Tooling:** `cargo-llvm-cov 0.9.1`, rustc 1.99.0, `llvm-tools`.
**Coverage configuration:** `CARGO_PROFILE_TEST_OPT_LEVEL=0` so `#[inline]`
wrappers do not hide library lines inside test-harness code.

Coverage is test evidence, not a correctness or security proof. No external
audit is claimed. The coverage script raises the stack-test override because
coverage instrumentation inflates unoptimized frames; the operational 32 KiB
release stack claim is tested separately by `scripts/gate.sh`.

## Headline

| Scope | Functions | Lines | Regions |
|---|---:|---:|---:|
| `vorb3` default features (shipped library) | **100.00%** (167/167) | **99.89%** (1789/1791) | 98.71% |
| `vorb3` all features (includes `bench-api`) | **100.00%** (193/193) | **99.90%** (2012/2014) | 98.79% |
| Whole workspace including dev CLIs | 72.83% (193/265) | 75.61% (2012/2661) | 73.56% |

The workspace total is lower only because `tools/attack` and `tools/bench` are
CLI harnesses with no unit tests. They are not shipped library code. Their
benchmark/attack behavior is exercised by `scripts/bench.sh` and
`tools/attack`, not by the unit-test graph.

## Per-file, all features

| File | Functions | Lines | Regions |
|---|---:|---:|---:|
| `bench_api.rs` | 100.00% | 100.00% | 100.00% |
| `blake3.rs` | 100.00% | 99.75% | 99.11% |
| `ct.rs` | 100.00% | 100.00% | 100.00% |
| `field.rs` | 100.00% | 100.00% | 97.63% |
| `ggm.rs` | 100.00% | 100.00% | 99.12% |
| `keys.rs` | 100.00% | 100.00% | 99.03% |
| `rain.rs` | 100.00% | 100.00% | 97.35% |
| `sign.rs` | 100.00% | 99.83% | 98.63% |
| `signature.rs` | 100.00% | 100.00% | 100.00% |
| `transcript.rs` | 100.00% | 100.00% | 99.49% |
| `zeroize.rs` | 100.00% | 100.00% | 100.00% |

## Residual lines

LLVM's line summary still counts **two** lines as missed:

- one closing-brace / `if let` false-region in `blake3::push_cv`;
- one closing-brace / `if let` false-region in `sign::fill_openings`.

These are region-attribution artifacts, not unexecuted protocol statements.
`--show-instantiations` shows the executed copies of the same functions with
non-zero counts. There are no unexecuted public APIs or protocol phases; every
library function is executed.

Region coverage is lower (98.84%) because defensive bounds checks and
`if let` false paths (fixed-size buffers, checked offsets) are intentionally
kept and are not all triggered. Lines and functions are the requested metrics.

## What improved coverage

- Added `tests/keys.rs`: public/secret key encoding, zero-key rejection.
- Added `tests/signature.rs`: signature encoding, equality, debug.
- Added field operator `Sub`/`Debug` tests and defensive helper tests
  (`chain_lookup`, `product_bit`).
- Added `tests/bench_api.rs` (required feature `bench-api`) to exercise every
  benchmark-phase wrapper.
- Added sign/keys bounds tests for checked offsets and overflow paths.
- Added a `blake3::push_cv` defensive zero-left merge test.
- Replaced fallible fixed-size `append` assembly in GGM and checked
  `try_from` copies with exact-size `split_at`/`copy_from_slice` writes.
- Added key/error mapping paths (`InvalidSecretKey`) without untestable
  unreachable branches.
- Added a WH512 prefix/full-hash equality test covering the GGM prefix-state
  optimization.

## Reproduce

```bash
./scripts/coverage.sh              # default + all features, HTML/JSON/LCOV
./scripts/coverage.sh --workspace  # also the dev-tool scope
```

Artifacts:

```text
target/coverage/summary-default.txt
target/coverage/summary-all-features.txt
target/coverage/html/index.html
target/coverage/coverage.json
target/coverage/lcov.info
target/coverage/missing-lines.txt
```

The coverage script fails if function coverage is below 100% or line coverage
falls below the configured thresholds (99.5% default, 99.8% all-features).

## Caveat

Coverage measures which lines/functions executed under the local test graph.
It does not prove cryptographic correctness, constant-time behavior, or
security. The security evidence remains in `PHASE7-ATTACK-REPORT.md`,
`SIDE-CHANNEL.md`, and `RAIN-CRYPTANALYSIS.md`.
