# VORB3 Releases

## v1.0.0 — 2026-11-27

**Profile:** SP-288/35 — GF(2^288), 35 GGM trees, depth 8, 15 Rain rounds,
13,672-byte signature.

**Status:** Official local release. This is a locally verified candidate
implementation, not an external audit or a “certified secure” claim.

### Frozen surface

```text
SPEC_VERSION       VORB3-SP1-FROZEN-288/35-2026-11-26
Field              GF(2^288), x^288 + x^11 + x^10 + x + 1
Trees / depth      35 / 8
Rounds             15
Signature          13,672 B
Public key         72 B
Compact seed       36 B
Expanded secret    108 B
Merkle / WH512     64 B
```

### Frozen hashes

```text
signature KAT SHA-256
c073c7e3f7b31192ba1932f9ed990b32bc4f321453347a23837803ef4fa9b68b

release rlib SHA-256 (two clean builds)
60e98d9c4c469ad8f5539345f55be33364d2995fff22dd7dfeaf4c323abf1bd4
```

### Evidence at release

- 405,581,569 libFuzzer executions across the 10-minute and 1-hour campaigns;
  9,963,205 AFL++ parse executions; zero crashes.
- 494 mutants: 371 caught, 27 Z3-checked equivalents, 3 unobservable `Drop`
  wipes, 84 unviable, 9 timeouts.
- 18/18 Kani harnesses; full sign+verify Miri pass; ASan, memcheck, careful-mode
  pass.
- 100% function coverage; 99.90% line coverage (all features).
- Full test graphs and 32 KiB stack target on x86_64, AArch64, s390x,
  ppc64, i686, Windows/Wine, and WASI.
- Reproducible rlib; zero external runtime dependencies; `forbid(unsafe_code)`.

### Versioning

This release is the SP-288/35 baseline. NIST-tier packs are released as
parameter-set versions; they do not change the v1.0.0 frozen artifacts.

See `REDTEAM-CAMPAIGN.md`, `COVERAGE.md`, `SECURITY-CASE.md`, and
`ASSURANCE.md` for the detailed evidence.
