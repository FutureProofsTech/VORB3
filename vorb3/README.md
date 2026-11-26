# vorb3

Frozen profile: **SP-288/35** — GF(2^288), 35 GGM trees, depth 8, 15 rounds,
13,672-byte signature.

This is the production `no_std` library. Phase 1 (repository/toolchain/lint/
zero-dependency gate), Phase 2 (constant-time/GF(2^288)), Phase 3
(BLAKE3/WH512), Phase 4 (Rain-SP1), Phase 5 (GGM/Merkle/transcript), and Phase 6
(QuickSilver/sign/verify) are implemented. Hardening and attack campaigns follow.

- No `std`, no `alloc`.
- `forbid(unsafe_code)`.
- Zero third-party runtime dependencies.
- No demo binary.

Specification: `../docs/VORB3-SPEC-1.md`.
Reference model: `../model/vorb3_model.py`.
