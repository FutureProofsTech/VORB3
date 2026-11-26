# vorb3

Frozen profile: **SP-288/35** — GF(2^288), 35 GGM trees, depth 8, 15 rounds,
13,672-byte signature.

This is the production `no_std` library. Phase 1 (repository/toolchain/lint/
zero-dependency gate), Phase 2 (constant-time/GF(2^288)), Phase 3
(BLAKE3/WH512), Phase 4 (Rain-SP1), Phase 5 (GGM/Merkle/transcript), and Phase 6
(QuickSilver/sign/verify) and the Phase 7 hardening/attack checkpoint are
implemented. The 109,376-bit signature sweep, 1-hour fuzz, 32 KiB per-operation
release stack target, canary scan, cachegrind/assembly evidence, and Kani helper
proofs are recorded under `../docs/`. The optimization checkpoint is in
`../docs/OPTIMIZATIONS.md`: Rain-SP1 encryption is 0.287 ms and sign is 7.07 ms
for the 32-byte KAT message in the local benchmark. This is not a release
certificate and no external audit is claimed.

- No `std`, no `alloc`.
- `forbid(unsafe_code)`.
- Zero third-party runtime dependencies.
- No demo binary.

Specification: `../docs/VORB3-SPEC-1.md`.
Reference model: `../model/vorb3_model.py`.
