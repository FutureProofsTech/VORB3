# vorb3

`vorb3` is the shipped `no_std` Rust library for VORB3-SP1, a compact
post-quantum signature design built from Rain-SP1, GGM vector commitments, and
QuickSilver.

- Default profile: **SP-288/35**, 13,672-byte signatures, 72-byte public keys.
- `nist1`: **SP-160/32** (NIST Level 1+), 7,976-byte signatures, 40-byte keys.
- `nist3`: **SP-224/32** (NIST Level 3+), 10,296-byte signatures, 56-byte keys.
- `bench-api`: internal measurement API, not a stable public interface.

`nist1` and `nist3` are mutually exclusive; do not enable both.

The crate is `#![no_std]`, forbids unsafe code, has no allocator, and has zero
third-party runtime dependencies. It is a locally verified candidate
implementation, not an externally audited or certified product.

See the repository root [`README.md`](../README.md) for architecture, security
status, benchmarks, release history, and the full documentation map.

License: **GPL-3.0-or-later**.
