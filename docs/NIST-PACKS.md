# VORB3 NIST-Tier Packs

**Status:** v1.3.0 releases both Level 1+ and Level 3+ with the optimized
compact-field arithmetic. Local evidence only; no external audit or
“certified secure” claim.

The protocol requires `T >= 2R+2 = 32` GGM trees for 15 rounds: 31 secret
wires plus one mask leaf. The 18/27-tree idea is therefore not implementable
without reducing rounds. The NIST packs keep the frozen 15-round protocol and
vary the field size with the mandatory 32 trees.

## 1. Ladder

| Pack | Version | Field | Trees | Signature | Public key | Seed | Quantum floor | Classical floor |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Level 5 baseline | v1.0.0 | GF(2^288) | 35 | 13,672 B | 72 B | 36 B | ≈140 | 256 |
| NIST Level 1+ | v1.3.0 | GF(2^160) | 32 | 7,976 B | 40 B | 20 B | ≈76.5 | 153 |
| NIST Level 3+ | v1.3.0 | GF(2^224) | 32 | 10,296 B | 56 B | 28 B | ≈108.5 | 217 |

Standard NIST categories used here:

```text
Level 1: 64-bit quantum / 128-bit classical
Level 3: 96-bit quantum / 192-bit classical
Level 5: 128-bit quantum / 256-bit classical
```

The Level 1+ and Level 3+ packs were introduced in v1.1.0 and v1.2.0;
v1.3.0 optimizes their field arithmetic without changing parameters or KATs.
The packs are labelled “+” because each floor is above its nominal category.
The Level 1+ margin is 12.5 quantum bits over Level 1; the Level 3+ margin is
12.5 quantum bits over Level 3; v1.0.0 is 12 quantum bits over Level 5.

## 2. Parameter definitions

```text
SP-160/32
  field       GF(2^160), x^160 + x^5 + x^3 + x^2 + 1
  trees       32, depth 8
  rounds      15
  gates       60
  signature   128 + 34*20 + 32*(8*20 + 64) = 7,976 B

SP-224/32
  field       GF(2^224), x^224 + x^9 + x^8 + x^3 + 1
  trees       32, depth 8
  rounds      15
  gates       60
  signature   128 + 34*28 + 32*(8*28 + 64) = 10,296 B
```

The field elements use 32-bit limbs; 160 and 224 bits are 5 and 7 limbs. All
value-dependent operations are mask-based, inversion uses the fixed public
exponent `2^BITS - 2`, and the shipped crate remains `no_std`,
`forbid(unsafe_code)`, with zero runtime dependencies.

## 3. Security table

| Pack | Field check (q/c) | Tree challenge (q/c) | Key (q/c) | WH512 (q/c) | Overall (q/c) |
|---|---:|---:|---:|---:|---:|
| SP-160/32 | 76.5 / 153.1 | 128 / 256 | 80 / 160 | 170 / 256 | **76.5 / 153.1** |
| SP-224/32 | 108.5 / 217.1 | 128 / 256 | 112 / 224 | 170 / 256 | **108.5 / 217.1** |
| SP-288/35 | 140.5 / 281.1 | 140 / 280 | 144 / 288 | 170 / 256 | **140 / 256** |

The overall floor is the minimum component. The tree challenge is 256 bits for
both compact packs because T=32; the field-check floor is lower.

## 4. Frozen KAT hashes

```text
SP-160/32
seed        88b90539aae174724c9decd2a9ef890c453a1aa1062a28c13efcacf0edcbde5c
public key  7a0756e507991f5bfdcf42f9bce1a860981560983d7aa1b0c4dcb74247dd600d
signature   43dcf2de9720219ff5c228e7f777e59fb3b3f8b8aa62cf7819c30b1d4a55be80
sign diff   89853bd01b1cf90d1bcfe36e36299debe323141d8feb7c869f388b282cd31714
field diff  af6ca8e8878644e15367063aaad68076d03739f4e5225b4dd355600ccf9d01ee

SP-224/32
seed        4248e3fd7934f9f31cdbc77bc269a69b7a7e7521ec433956b075c7f1257deabc
public key  753312d0a19f42f0d15f8e597efb0bb7e790512af2a95168bafa9b014f1ca73e
signature   3ad501e141327a2844641096b98cb074164f5ac0aa93ef6a3d96d0a14034fc49
sign diff   4f2b4f152aab8b5099401db6398145b1b6da2916dc5a7060c6693550de857176
field diff  bea4067ebcaedfe447f5a2122b003eb63613e70062cd300fdf9d763997420ccd
```

## 5. Evidence per pack

Both packs have:

- model-generated seed/public-key/signature KAT;
- 28-case Rust/Python signature differential (0–8192 B);
- 4,096-record Python field differential;
- SymPy irreducibility check for both field polynomials;
- structured envelope/replay/damage/swap attacks;
- full single-bit signature sweep: 63,808 mutations (160/32) and 82,368
  (224/32), zero accepted;
- 16/16 Kani helpers each;
- dudect 50,000 samples: Level 1+ sign t=-0.317, verify t=-0.468;
  Level 3+ sign t=1.460, verify t=0.977;
- ASan full test graph;
- selected Miri field/key primitives under strict provenance and symbolic
  alignment: field 12.2 s / keys 93.1 s (Level 1+), field 24.0 s / keys
  181.7 s (Level 3+);
- coverage 100% functions / 99.70% lines (the six residual lines are guard
  returns inside test code, not protocol statements);
- 300-second six-target libFuzzer campaigns: 12,310,692 executions
  (Level 1+) and 24,575,666 (Level 3+), zero crashes;
- targeted mutation runs: 427 mutants each, 335 caught, 29 missed, 53
  unviable, 10 timeouts; 21 equivalence classes discharged with Z3
  (`scripts/verify_mutation_equivalences.py`);
- 32 KiB stack target in release;
- byte-identical release rlibs across two clean builds
  (`bc245cdb…bd0d` Level 1+, `cf198c13…d20b` Level 3+);
- cross-architecture and portable-runtime checks;
- full benchmark medians on the build host (25 samples): sign 4.86 ms /
  verify 4.64 ms (160/32); sign 5.10 ms / verify 4.65 ms (224/32);
  field inversion 4.43 / 9.40 µs and squaring 10.5 / 11.8 ns;
- full benchmark report: `NIST-BENCHMARKS.md` (25 samples per benchmark,
  same-session SP-288/35 comparison).

The Valgrind `ctgrind` C-ABI harness remains baseline-only (fixed 288/35 buffer
sizes); its wrapper is compiled out for `nist1`/`nist3` builds. The compact
packs use the randomized dudect and ASan evidence above.

Detailed numbers are recorded in `REDTEAM-CAMPAIGN.md`; release hashes are in
`RELEASES.md`.

## 6. Compact-field optimization

The compact field originally reused schoolbook multiplication for squaring
and a sequential square-and-multiply inversion. Three changes removed that
bottleneck without changing the wire format or KATs:

- **Bit-interleaved squaring:** squaring inserts zero coefficients, so each
  32-bit limb is spread into even bit positions and reduced once.
- **Word-level reduction:** when `BITS` is a multiple of 32, high product words
  reduce in one descending pass by XORing four shifted copies at
  `word - BITS/32`; this replaced the per-bit reduction loop.
- **Itoh–Tsujii inversion:** the fixed public exponent `2^BITS - 2` is built
  with `BITS - 1` squarings and about `log2(BITS)` multiplications instead of
  `BITS - 1` multiplications.

Measured medians (25 samples, same host):

| Operation | L1+ before | L1+ after | L3+ before | L3+ after |
|---|---:|---:|---:|---:|
| Field multiplication | 903 ns | **216 ns** | 1.34 µs | **409 ns** |
| Field squaring | 937 ns | **10.5 ns** | 1.36 µs | **11.8 ns** |
| Field inversion | 300.4 µs | **4.43 µs** | 601.6 µs | **9.40 µs** |
| Rain-SP1 encryption | 4.418 ms | **69.4 µs** | 9.082 ms | **146.7 µs** |
| Key generation | 4.665 ms | **74.2 µs** | 9.244 ms | **151.8 µs** |
| Sign, 32 B | 9.602 ms | **4.855 ms** | 15.186 ms | **5.105 ms** |
| Verify, 32 B | 4.761 ms | **4.639 ms** | 5.412 ms | **4.648 ms** |

All KAT hashes and differential vectors are unchanged. The operations remain
fixed-iteration and branch on public values only, so the constant-time
properties and 32 KiB stack target are preserved. With Rain no longer
dominant, GGM/BLAKE3 root derivation is now ~93–96% of signing time.

## 7. Commands

```bash
cargo test -p vorb3 --features nist1,bench-api
cargo test -p vorb3 --features nist3,bench-api
cargo kani -p vorb3 --features nist1
cargo kani -p vorb3 --features nist3

VORB3_FEATURES=nist1 ./scripts/cross-runtime.sh
VORB3_FEATURES=nist3 ./scripts/cross-runtime.sh
VORB3_FEATURES=nist1 ./scripts/reproducible.sh
VORB3_FEATURES=nist3 ./scripts/reproducible.sh

VORB3_FEATURES=nist1 BENCH_CPU=4 ./scripts/bench.sh
VORB3_FEATURES=nist3 BENCH_CPU=4 ./scripts/bench.sh

FUZZ_FEATURES=nist1 FUZZ_TAG=n1 ./scripts/fuzz-campaign.sh 300
FUZZ_FEATURES=nist3 FUZZ_TAG=n3 ./scripts/fuzz-campaign.sh 300
```
