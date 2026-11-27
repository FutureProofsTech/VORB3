# VORB3 Releases

## v1.3.0 — Compact-field performance release, 2026-11-27

**Profiles:** the SP-288/35 default profile is unchanged. Level 1+
(SP-160/32) and Level 3+ (SP-224/32) keep the same wire format, KATs, and
signature sizes, with optimized compact-field arithmetic. The frozen KAT
hashes are unchanged from v1.1.0/v1.2.0.

**Performance (25-sample medians, same host):**

| Operation | Level 1+ | Level 3+ | SP-288/35 |
|---|---:|---:|---:|
| Sign, 32 B | 4.855 ms | 5.105 ms | 6.364 ms |
| Verify, 32 B | 4.639 ms | 4.648 ms | 5.676 ms |
| Key generation | 74.2 µs | 151.8 µs | 266.1 µs |
| Rain-SP1 encryption | 69.4 µs | 146.7 µs | 257.9 µs |
| Field multiplication | 216 ns | 409 ns | 712 ns |
| Field squaring | 10.5 ns | 11.8 ns | 13.4 ns |
| Field inversion | 4.43 µs | 9.40 µs | 17.36 µs |

Both compact packs are now faster to sign and verify than the baseline while
retaining their smaller signatures. GGM/BLAKE3 root derivation is the
remaining sign-time bottleneck (about 93–96%).

**Change:** bit-interleaved squaring, word-level reduction for
`BITS % 32 == 0`, and an Itoh–Tsujii inversion chain for the fixed public
exponent `2^BITS - 2`. Control flow remains fixed-iteration and branches only
on public values.

**Evidence:** 12,310,692 / 24,575,666 libFuzzer executions; 427 targeted
mutants each (335 caught, 29 missed, 53 unviable, 10 timeouts; 21 Z3-checked
equivalence classes); Kani 16/16 each; ASan pass; coverage 100% functions /
99.70% lines; strict Miri field/key checks; 32 KiB release stack; AArch64,
s390x, i686, ppc64, Windows/Wine, and WASI passes; dudect 50k Level 1+ sign
t=-0.317 / verify t=-0.468 and Level 3+ sign t=1.460 / verify t=0.977;
byte-identical release rlibs: Level 1+
`bc245cdb11174194cc6cb6ca4f1dfcea8817b59e6bd859d47686980daec1bd0d`,
Level 3+
`cf198c13ad60a2bde5a148895bb61d1707667efaee8bcea7a328969a9873d20b`.

Full tables: `NIST-BENCHMARKS.md`. Long-form papers:
`docs/papers/VORB3-SP1-Whitepaper.pdf` and
`docs/papers/VORB3-SP1-Yellow-Paper.pdf`. This is local evidence only, not an
external audit or a security certificate.

## v1.2.0 — NIST Level 3+ (SP-224/32), 2026-11-27

**Tag:** v1.2.0. The two profile features remain mutually exclusive.

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
SHA-256 `805891376f7f6c3ff828d569a5770e7e19c519a73f770a473725f2123dabb5fa`.

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
