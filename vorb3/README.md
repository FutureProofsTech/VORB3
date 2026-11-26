# vorb3

Frozen profile: **SP-288/35** — GF(2^288), 35 GGM trees, depth 8, 15 rounds,
13,672-byte signature.

This is the production `no_std` library. Phase 1 (repository/toolchain/lint/
zero-dependency gate) is complete; Phase 2 has started with constant-time
primitives and GF(2^288) arithmetic. The remaining crypto modules follow.

- No `std`, no `alloc`.
- `forbid(unsafe_code)`.
- Zero third-party runtime dependencies.
- No demo binary.

Specification: `../docs/VORB3-SPEC-1.md`.
Reference model: `../model/vorb3_model.py`.
