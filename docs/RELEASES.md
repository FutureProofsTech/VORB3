# VORB3 Releases

## v1.2.0 — NIST Level 3+ (SP-224/32), 2026-11-27

**Tag:** staged on the v1.1.0 source line; cut after the final Level 3+ evidence
check. The two profile features remain mutually exclusive.

**Profile:** GF(2^224), 32 GGM trees, depth 8, 15 rounds, 10,296-byte
signature. Conservative floor ≈108.5-bit quantum / 217-bit classical, above
NIST Level 3 (96q / 192c).

```text
poly        x^224 + x^9 + x^8 + x^3 + 1
seed        4248e3fd7934f9f31cdbc77bc269a69b7a7e7521ec433956b075c7f1257deabc
public key  753312d0a19f42f0d15f8e597efb0bb7e790512af2a95168bafa9b014f1ca73e
signature   3ad501e141327a2844641096b98cb074164f5ac0aa93ef6a3d96d0a14034fc49
```

Build/test: `cargo test -p vorb3 --features nist3,bench-api`,
`cargo kani -p vorb3 --features nist3`, `./scripts/nist-gate.sh nist3`.

Evidence: 18,848,000 libFuzzer executions (300 s × 6 targets, 0 crashes);
82,368 single-bit mutations rejected; 403 targeted mutants (316 caught, 24
missed/classified, 53 unviable, 10 timeouts); Kani 16/16; ASan pass; coverage
100% functions / 99.70% lines; 32 KiB stack pass; selected field/key Miri pass;
AArch64/s390x/i686/ppc64/Windows/WASI runtime passes; dudect 50k sign t=0.026, verify t=0.012;
local quick bench sign ≈17.0 ms / verify ≈5.6 ms; reproducible rlib
SHA-256 `e6dc131a245ad306a753d4c0da81c2b81627ad5db04e8e38ee962cd9758f55f5`.

## v1.1.0 — NIST Level 1+ (SP-160/32), 2026-11-27

**Profile:** GF(2^160), 32 GGM trees, depth 8, 15 rounds, 7,976-byte
signature. Conservative floor ≈76.5-bit quantum / 153-bit classical, above
NIST Level 1 (64q / 128c).

```text
poly        x^160 + x^5 + x^3 + x^2 + 1
seed        88b90539aae174724c9decd2a9ef890c453a1aa1062a28c13efcacf0edcbde5c
public key  7a0756e507991f5bfdcf42f9bce1a860981560983d7aa1b0c4dcb74247dd600d
signature   43dcf2de9720219ff5c228e7f777e59fb3b3f8b8aa62cf7819c30b1d4a55be80
```

Build/test: `cargo test -p vorb3 --features nist1,bench-api`,
`cargo kani -p vorb3 --features nist1`, `./scripts/nist-gate.sh nist1`.

Evidence: 7,260,135 libFuzzer executions (300 s × 6 targets, 0 crashes);
63,808 single-bit mutations rejected; 403 targeted mutants (316 caught, 24
missed/classified, 53 unviable, 10 timeouts); Kani 16/16; ASan pass; coverage
100% functions / 99.70% lines; 32 KiB stack pass; selected field/key Miri pass;
AArch64/s390x/i686/ppc64/Windows/WASI runtime passes; dudect 50k sign t=-1.820, verify t=2.113;
local quick bench sign ≈10.5 ms / verify ≈5.3 ms; reproducible rlib
SHA-256 `15a140a64e549e1cce5d284b1259041fe7660ab362e9aa17cb003e83af8cac36`.

Both packs use the frozen 15-round protocol; 32 trees is the hard minimum
(31 wires + mask). The v1.1.0 source line also carries the Level 3+
implementation and tests, released as v1.2.0; only one profile feature may be
enabled at a time. See `NIST-PACKS.md` for full security/evidence tables.

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
