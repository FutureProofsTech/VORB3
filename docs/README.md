# VORB3 Documentation Index

**Status:** Phase 7 local implementation/attack checkpoint (2026-11-26).
The production `no_std` crate is implemented and locally exercised; this is not
a release certificate and no external audit is claimed.

| Document | Purpose |
|---|---|
| `../PLAN.md` | Master plan |
| `PHASE0-REPORT.md` | Phase 0 findings, corrections, model results |
| `VORB3-SPEC-1.md` | Frozen protocol/equation/wire specification |
| `WIRE-BINDING.md` | Byte-by-byte binding table |
| `THREAT-MODEL.md` | Assets, adversaries, trust boundaries |
| `ASSURANCE.md` | Requirement → evidence matrix and Phase 7 status |
| `SECURITY-CASE.md` | Security target, F-33 union bound, assumptions |
| `DECISIONS.md` | ADRs D1–D23 and findings F-01–F-33 |
| `PHASE0-REDTEAM.md` | Internal adversarial review |
| `PHASE1-7-REPORT.md` | Phase 1–7 implementation and evidence checkpoint |
| `PHASE7-ATTACK-REPORT.md` | Bit-flip, fuzz, stack, Kani, cachegrind, assembly |
| `SIDE-CHANNEL.md` | Timing/cache/assembly measurement report |
| `RAIN-CRYPTANALYSIS.md` | Rain-SP1 local cryptanalysis dossier |
| `BENCHMARKS.md` | Full latency/throughput/memory/build benchmark report |
| `OPTIMIZATIONS.md` | Field/BLAKE3/GGM optimization report and speedups |
| `COVERAGE.md` | llvm-cov line/function/region coverage report |
| `../model/vorb3_model.py` | Independent Python/py-blake3 model |
| `../model/README.md` | Model usage and limitations |

## Frozen profile

**D21 = SP-288/35:** GF(2^288), 35 trees, depth 8, 15 rounds, 13,672-byte
signature, conservative ~140-bit quantum floor. The 256-bit profile is ~125-bit
under the F-33 bound and is not used for a 128-bit claim.

## Local gates

```bash
./scripts/gate.sh        # fmt, clippy, tests, 32 KiB release stack, builds
./scripts/gate-deep.sh   # Kani helper proofs + Miri
```

Deferred by direction: the 72-hour / 1-billion-execution fuzz soak. Open release
gates include full symbolic Kani sign/verify, full Rain-SP1 cryptanalysis,
cross-architecture KATs, reproducible-build comparison, coverage/mutation
scores, and external review.
