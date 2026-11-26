# Side-Channel Measurement Plan (Phase 9 Preview)

**Status:** methodology fixed; measurements run only on a quiet machine after
the fuzz campaign.

## Timing

- `tools/attack dudect <N>` performs alternating fixed-key vs second-key signing
  with `sign_into`, records nanoseconds, and reports Welch's t.
- A 1M–5M sample smoke is used first; the full 50M campaign is a separate
  release-stage run.
- The machine must be pinned/idle; fuzzing must be stopped.

## Cache/instruction audit

- `valgrind --tool=cachegrind --cache-sim=yes --branch-sim=yes` on the fixed
  benchmark.
- Repeat with a second key profile and compare instruction/cache counts.
- Record that data-dependent differences are expected only for public inputs.

## Assembly audit

- `cargo rustc --release --lib -- --emit asm`.
- Review secret-carrying functions (`field`, `rain`, `ggm::hidden_opening`,
  `sign`) for secret-dependent conditional branches or indexing.
- The masked GGM scans are expected to have public loop branches only.

## Acceptance

- dudect |t| < 4.5 at the configured sample size;
- cachegrind instruction counts identical for fixed-vs-random at the same
  public transcript path, modulo documented public branches;
- manual assembly review finds no secret-dependent branch/index.

This is evidence, not a formal constant-time proof.
