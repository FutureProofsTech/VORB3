# VORB3 NIST-Tier Full Benchmarks

**Status:** local measurement checkpoint (2026-11-27). Machine- and
compiler-dependent evidence, not a security proof and not an external audit.

This report covers the two compact packs plus the SP-288/35 baseline measured
on the same host in the same session. The raw tables are emitted by
`scripts/bench.sh`; this file is the curated snapshot. See
`docs/BENCHMARKS.md` for the earlier baseline analysis.

- host: `Linux 7.2.9-200.fc44.x86_64 x86_64`
- cpu: `Intel(R) Core(TM) i5-14400F`
- cores/threads: `16`
- rustc: `rustc 1.99.0 (b940084d7 2026-09-28)`
- cargo: `cargo 1.99.0 (5f94df478 2026-08-27)`
- profile: release, opt-level=3, LTO, codegen-units=1, panic=abort, strip
- benchmark CPU pin: `4`
- signatures: SP-288/35 13,672 B; Level 1+ 7,976 B; Level 3+ 10,296 B
- keys: SP-288/35 36/72 B; Level 1+ 20/40 B; Level 3+ 28/56 B

## 1. Headline results

Medians from 25 samples per benchmark. Throughput is `1 / median`.

| Operation | SP-288/35 | Level 1+ | Level 3+ | L1+ / base | L3+ / base |
|---|---:|---:|---:|---:|---:|
| Key generation | 266.10 µs (3,758/s) | 4.665 ms (214.4/s) | 9.244 ms (108.2/s) | 17.53× | 34.74× |
| Sign, 32 B | 6.364 ms (157.1/s) | 9.602 ms (104.1/s) | 15.186 ms (65.8/s) | 1.51× | 2.39× |
| Verify, 32 B | 5.676 ms (176.2/s) | 4.761 ms (210.0/s) | 5.412 ms (184.8/s) | 0.84× | 0.95× |
| Sign + verify, 32 B | 12.007 ms (83.3/s) | 14.156 ms (70.6/s) | 19.515 ms (51.2/s) | 1.18× | 1.63× |
| Field multiplication | 712 ns (1,404,494/s) | 903 ns (1,107,420/s) | 1.34 µs (748,503/s) | 1.27× | 1.88× |
| Field squaring | 13.4 ns (74,626,866/s) | 937 ns (1,067,236/s) | 1.36 µs (736,377/s) | 69.93× | 101.34× |
| Field inversion | 17.36 µs (57,597/s) | 300.37 µs (3,329/s) | 601.62 µs (1,662/s) | 17.30× | 34.65× |
| Rain-SP1 encryption | 257.88 µs (3,878/s) | 4.418 ms (226.3/s) | 9.082 ms (110.1/s) | 17.13× | 35.22× |
| GGM roots (all trees) | 5.855 ms (170.8/s) | 5.156 ms (193.9/s) | 5.285 ms (189.2/s) | 0.88× | 0.90× |
| GGM root reconstruction | 5.621 ms (177.9/s) | 4.976 ms (201.0/s) | 4.779 ms (209.2/s) | 0.89× | 0.85× |
| QuickSilver prove | 263.66 µs (3,793/s) | 383.79 µs (2,606/s) | 554.20 µs (1,804/s) | 1.46× | 2.10× |
| QuickSilver verify | 177.03 µs (5,649/s) | 230.41 µs (4,340/s) | 333.06 µs (3,002/s) | 1.30× | 1.88× |
| Public-key parse | 15.8 ns (63,291,139/s) | 10.6 ns (94,339,623/s) | 13.2 ns (75,757,576/s) | 0.67× | 0.84× |
| Signature parse | 209 ns (4,784,689/s) | 88.1 ns (11,350,738/s) | 136 ns (7,352,941/s) | 0.42× | 0.65× |

### Observations

- Level 1+ signing is **1.51×** the SP-288/35 baseline; Level 3+ is **2.39×**.
  The compact packs are smaller but slower to sign.
- Verification is **0.84×** (Level 1+) and **0.95×** (Level 3+) the baseline:
  32 trees instead of 35 offsets the compact-field cost.
- Rain-SP1 encryption accounts for the signing regression: **4.42 ms**
  (Level 1+) and **9.08 ms** (Level 3+) versus **0.258 ms** baseline. The
  compact field uses fixed-exponent inversion, costing **300 µs / 602 µs**
  versus **17.4 µs** for the specialized 288-bit field.
- Compact-field squaring is implemented as a generic multiplication
  (**0.94 µs / 1.36 µs**), while the 288-bit field has specialized squaring
  (**13.4 ns**). Inversion is a square-and-multiply chain over the fixed
  public exponent.
- GGM roots and root reconstruction are **0.88–0.90×** the baseline because
  the packs use 32 trees instead of 35; BLAKE3 cost is unchanged.
- Public-key and signature parsing are cheaper for the compact packs in
  proportion to their smaller encodings.

## 2. Where signing time goes

Independent phase medians; the measured phase sum can differ from the
end-to-end operation by a few percent because each row is sampled separately.

### Level 1+

| Phase | Median | Share of phase sum |
|---|---:|---:|
| GGM root derivation | 5.156 ms | 51.31% |
| Rain-SP1 encryption | 4.418 ms | 43.96% |
| QuickSilver prover | 383.79 µs | 3.82% |
| Hidden openings | 51.99 µs | 0.52% |
| Wire/tag construction | 30.57 µs | 0.30% |
| Transcript | 8.37 µs | 0.08% |
| Master seed | 253 ns | <0.01% |
| Salt | 209 ns | <0.01% |
| Public-key hash | 198 ns | <0.01% |
| **Measured phase sum** | **10.050 ms** | **100%** |
| Full operation | 9.602 ms | 95.55% of phase sum |

### Level 3+

| Phase | Median | Share of phase sum |
|---|---:|---:|
| GGM root derivation | 5.285 ms | 35.14% |
| Rain-SP1 encryption | 9.082 ms | 60.39% |
| QuickSilver prover | 554.20 µs | 3.68% |
| Hidden openings | 64.58 µs | 0.43% |
| Wire/tag construction | 44.10 µs | 0.29% |
| Transcript | 8.89 µs | 0.06% |
| Master seed | 320 ns | <0.01% |
| Salt | 210 ns | <0.01% |
| Public-key hash | 318 ns | <0.01% |
| **Measured phase sum** | **15.039 ms** | **100%** |
| Full operation | 15.186 ms | 100.98% of phase sum |

## 3. Where verification time goes

### Level 1+

| Phase | Median | Share of phase sum |
|---|---:|---:|
| GGM root reconstruction | 4.976 ms | 94.81% |
| QuickSilver verifier | 230.41 µs | 4.39% |
| Wire openings | 29.63 µs | 0.56% |
| Transcript | 8.37 µs | 0.16% |
| Rain constants | 4.13 µs | 0.08% |
| **Measured phase sum** | **5.249 ms** | **100%** |
| Full operation | 4.761 ms | 90.71% of phase sum |

### Level 3+

| Phase | Median | Share of phase sum |
|---|---:|---:|
| GGM root reconstruction | 4.779 ms | 92.44% |
| QuickSilver verifier | 333.06 µs | 6.44% |
| Wire openings | 44.59 µs | 0.86% |
| Transcript | 8.89 µs | 0.17% |
| Rain constants | 4.40 µs | 0.09% |
| **Measured phase sum** | **5.170 ms** | **100%** |
| Full operation | 5.412 ms | 104.68% of phase sum |

## 4. Message-size scaling

| Message | L1+ sign | L1+ verify | L3+ sign | L3+ verify |
|---:|---:|---:|---:|---:|
| 0B | 9.491 ms | 5.038 ms | 14.336 ms | 5.001 ms |
| 32B | 9.602 ms | 4.761 ms | 15.186 ms | 5.412 ms |
| 1KiB | 9.556 ms | 4.817 ms | 14.345 ms | 5.504 ms |
| 64KiB | 9.611 ms | 5.352 ms | 14.761 ms | 5.082 ms |
| 1MiB | 12.470 ms | 6.748 ms | 17.588 ms | 7.016 ms |
| 16MiB | 63.530 ms | 38.304 ms | 68.982 ms | 40.171 ms |

At 16 MiB, signing costs about **3.38 ms/MiB** (Level 1+) and
**3.42 ms/MiB** (Level 3+) over the empty-message case; verification costs
about **2.08 ms/MiB** and **2.20 ms/MiB**. The baseline slopes are
3.06 ms/MiB and 2.11 ms/MiB. Signing hashes the message twice; verification
hashes it once.

## 5. Build and memory

| Profile | bench text | bench data | bench bss | bench dec | attack text | attack data | attack bss | attack dec | Max RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| SP-288/35 | 716220 | 10960 | 3954 | 731134 | 463230 | 11968 | 2042 | 477240 | 20 MiB |
| Level 1+ | 686172 | 10960 | 1234 | 698366 | 441334 | 11968 | 3450 | 456752 | 20 MiB |
| Level 3+ | 696020 | 10960 | 3666 | 710646 | 444518 | 11968 | 266 | 456752 | 20 MiB |

The library remains `no_std`, allocates no heap, and has zero runtime
dependencies. The profile `nist_stack` tests pass at 32 KiB for sign/verify
and 64 KiB when the 7,976/10,296-byte signature buffer itself is placed on the
stack.

The `public_key.profile` and `signature.profile` rows parse the profile's
40/56-byte public key and 7,976/10,296-byte signature respectively.

## 6. Full Level 1+ results

| Category | Benchmark | Mean ns/op | Median ns/op | p95 ns/op | Min ns/op | Max ns/op | Stddev ns | Ops/s | Samples | Inner |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| field | add | 0.90 | 0.92 | 0.96 | 0.82 | 0.97 | 0.05 | 1,105,294,609 | 25 | 2000000 |
| field | mul | 914 | 903 | 983 | 901 | 1,010 | 26.8 | 1,093,626 | 25 | 43835 |
| field | square | 948 | 937 | 1,024 | 902 | 1,028 | 46.1 | 1,054,426 | 25 | 43426 |
| field | inverse | 306,059 | 300,368 | 327,291 | 288,685 | 328,431 | 15,038 | 3,267 | 25 | 124 |
| field | from_bytes | 0.82 | 0.69 | 1.12 | 0.62 | 1.13 | 0.21 | 1,222,311,796 | 25 | 2000000 |
| field | to_bytes | 0.61 | 0.61 | 0.64 | 0.59 | 0.67 | 0.02 | 1,643,972,557 | 25 | 2000000 |
| hash | blake3.empty | 66.3 | 64.5 | 72.0 | 63.8 | 72.0 | 3.13 | 15,077,460 | 25 | 527704 |
| hash | blake3.64B | 75.5 | 77.2 | 79.6 | 70.2 | 80.4 | 4.06 | 13,241,590 | 25 | 432900 |
| hash | blake3.1KiB | 986 | 1,002 | 1,044 | 916 | 1,069 | 53.6 | 1,014,644 | 25 | 42996 |
| hash | blake3.1MiB | 1,028,210 | 1,015,870 | 1,063,347 | 998,521 | 1,081,821 | 25,802 | 973 | 25 | 39 |
| hash | blake3_xof.64B | 75.7 | 74.7 | 81.1 | 72.0 | 84.1 | 3.51 | 13,210,559 | 25 | 461361 |
| hash | keyed_hash.64B | 61.0 | 60.5 | 63.6 | 60.1 | 64.9 | 1.22 | 16,402,869 | 25 | 524934 |
| hash | derive_key.profile_field | 137 | 137 | 140 | 135 | 143 | 1.95 | 7,303,018 | 25 | 292825 |
| hash | wh512.profile_field | 131 | 127 | 139 | 124 | 150 | 6.65 | 7,661,841 | 25 | 308641 |
| hash | wh512.2048B | 4,081 | 4,107 | 4,361 | 3,827 | 4,372 | 214 | 245,040 | 25 | 10472 |
| rain | constants_derive | 4,238 | 4,135 | 4,584 | 4,062 | 4,598 | 195 | 235,948 | 25 | 8828 |
| rain | encrypt | 4,458,598 | 4,418,279 | 4,647,234 | 4,350,929 | 4,782,579 | 112,945 | 224 | 25 | 9 |
| ggm | tree_root.1 | 148,129 | 146,561 | 155,830 | 143,876 | 157,709 | 3,946 | 6,751 | 25 | 279 |
| ggm | hidden_opening.1 | 1,448 | 1,436 | 1,568 | 1,403 | 1,595 | 46.5 | 690,654 | 25 | 28445 |
| ggm | reconstruct_root.1 | 158,874 | 159,695 | 166,115 | 141,873 | 175,804 | 7,552 | 6,294 | 25 | 245 |
| ggm | roots.32 | 5,106,636 | 5,156,288 | 5,176,586 | 4,750,957 | 5,188,946 | 125,865 | 196 | 25 | 7 |
| ggm | openings.32 | 50,705 | 51,988 | 52,251 | 46,350 | 52,312 | 2,069 | 19,722 | 25 | 765 |
| ggm | reconstruct_roots.32 | 4,850,717 | 4,976,263 | 5,074,719 | 4,492,110 | 5,146,658 | 228,689 | 206 | 25 | 7 |
| transcript | challenges.32B | 8,386 | 8,366 | 8,952 | 8,026 | 9,047 | 285 | 119,252 | 25 | 4656 |
| transcript | challenges.1MiB | 2,143,637 | 2,145,940 | 2,254,543 | 2,012,540 | 2,256,902 | 82,376 | 466 | 25 | 15 |
| sign-phase | master_seed.32B | 250 | 253 | 255 | 229 | 256 | 6.08 | 3,995,185 | 25 | 140597 |
| sign-phase | master_seed.1MiB | 1,068,027 | 1,089,811 | 1,126,948 | 995,141 | 1,134,798 | 52,239 | 936 | 25 | 38 |
| sign-phase | salt | 207 | 209 | 213 | 190 | 213 | 6.49 | 4,836,745 | 25 | 178491 |
| sign-phase | pk_hash | 198 | 198 | 208 | 186 | 209 | 8.24 | 5,056,778 | 25 | 206398 |
| sign-phase | wires.31 | 30,326 | 30,569 | 31,839 | 28,125 | 32,055 | 1,276 | 32,975 | 25 | 1434 |
| quicksilver | prove.60gates | 392,015 | 383,789 | 432,331 | 364,666 | 444,675 | 20,076 | 2,551 | 25 | 105 |
| quicksilver | opened_wires.31 | 29,757 | 29,631 | 31,708 | 28,080 | 32,199 | 1,321 | 33,606 | 25 | 1284 |
| quicksilver | check_proof.60gates | 235,935 | 230,409 | 254,658 | 219,956 | 255,883 | 13,575 | 4,238 | 25 | 171 |
| keys | secret_key_wrap | 1.36 | 1.33 | 1.47 | 1.31 | 1.49 | 0.06 | 737,975,966 | 25 | 2000000 |
| keys | expand | 290 | 296 | 304 | 270 | 305 | 14.2 | 3,450,701 | 25 | 130633 |
| keys | public_key | 4,528,278 | 4,442,750 | 4,946,609 | 4,343,243 | 4,999,160 | 189,824 | 221 | 25 | 9 |
| keys | keygen_full | 4,663,700 | 4,665,137 | 4,934,071 | 4,372,927 | 4,973,409 | 215,825 | 214 | 25 | 9 |
| parse | public_key.profile | 10.6 | 10.6 | 10.7 | 10.5 | 10.8 | 0.05 | 94,478,364 | 25 | 2000000 |
| parse | signature.profile | 88.9 | 88.1 | 94.6 | 87.6 | 98.4 | 2.45 | 11,247,339 | 25 | 336417 |
| full | sign.0B | 9,594,268 | 9,490,891 | 10,298,155 | 9,410,593 | 10,388,685 | 287,196 | 104 | 25 | 4 |
| full | verify.0B | 5,037,554 | 5,038,112 | 5,348,303 | 4,732,236 | 5,354,449 | 239,076 | 199 | 25 | 8 |
| full | sign.32B | 9,823,522 | 9,602,316 | 10,530,269 | 9,379,031 | 10,586,553 | 457,866 | 102 | 25 | 3 |
| full | verify.32B | 4,840,157 | 4,761,275 | 5,187,721 | 4,721,283 | 5,208,762 | 166,171 | 207 | 25 | 7 |
| full | sign.1KiB | 9,736,002 | 9,555,818 | 10,546,618 | 9,393,046 | 10,549,644 | 378,416 | 103 | 25 | 4 |
| full | verify.1KiB | 4,937,752 | 4,817,277 | 5,330,003 | 4,728,608 | 5,341,893 | 224,448 | 203 | 25 | 8 |
| full | sign.64KiB | 9,827,356 | 9,611,350 | 10,733,640 | 9,539,488 | 10,881,661 | 389,060 | 102 | 25 | 3 |
| full | verify.64KiB | 5,204,435 | 5,352,371 | 5,455,932 | 4,848,120 | 5,464,360 | 266,849 | 192 | 25 | 8 |
| full | sign.1MiB | 12,525,122 | 12,470,360 | 13,190,434 | 12,370,531 | 13,285,838 | 223,368 | 80 | 25 | 3 |
| full | verify.1MiB | 6,833,253 | 6,748,143 | 6,963,622 | 6,719,220 | 8,405,515 | 332,206 | 146 | 25 | 5 |
| full | sign.16MiB | 65,224,545 | 63,530,183 | 72,581,886 | 58,547,743 | 73,099,344 | 4,004,395 | 15 | 25 | 1 |
| full | verify.16MiB | 38,495,080 | 38,304,458 | 41,385,348 | 36,887,262 | 41,434,776 | 1,242,844 | 26 | 25 | 1 |
| full | sign_wrapper.32B | 9,895,221 | 9,607,426 | 10,586,709 | 9,366,599 | 10,635,751 | 513,143 | 101 | 25 | 4 |
| full | verify_wrapper.32B | 5,016,054 | 5,002,620 | 5,352,359 | 4,724,634 | 5,354,562 | 234,903 | 199 | 25 | 7 |
| full | sign_verify.32B | 14,277,688 | 14,156,352 | 15,166,961 | 14,113,508 | 15,290,902 | 306,259 | 70 | 25 | 2 |

## 7. Full Level 3+ results

| Category | Benchmark | Mean ns/op | Median ns/op | p95 ns/op | Min ns/op | Max ns/op | Stddev ns | Ops/s | Samples | Inner |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| field | add | 5.07 | 5.18 | 5.20 | 4.65 | 5.22 | 0.21 | 197,191,340 | 25 | 2000000 |
| field | mul | 1,346 | 1,336 | 1,378 | 1,332 | 1,466 | 27.9 | 742,850 | 25 | 30041 |
| field | square | 1,385 | 1,358 | 1,515 | 1,331 | 1,523 | 66.1 | 722,190 | 25 | 29520 |
| field | inverse | 610,492 | 601,622 | 645,572 | 596,697 | 668,766 | 20,180 | 1,638 | 25 | 66 |
| field | from_bytes | 4.42 | 4.42 | 4.46 | 4.39 | 4.47 | 0.02 | 226,135,998 | 25 | 2000000 |
| field | to_bytes | 3.98 | 3.97 | 3.99 | 3.95 | 4.17 | 0.04 | 251,217,704 | 25 | 2000000 |
| hash | blake3.empty | 65.3 | 64.1 | 72.4 | 63.9 | 72.8 | 2.77 | 15,307,193 | 25 | 567375 |
| hash | blake3.64B | 82.8 | 82.2 | 88.0 | 78.1 | 88.6 | 3.83 | 12,072,566 | 25 | 400000 |
| hash | blake3.1KiB | 1,126 | 1,115 | 1,207 | 1,073 | 1,209 | 47.4 | 888,380 | 25 | 33294 |
| hash | blake3.1MiB | 1,058,050 | 1,041,592 | 1,137,588 | 997,868 | 1,138,216 | 54,650 | 945 | 25 | 39 |
| hash | blake3_xof.64B | 81.6 | 81.2 | 84.4 | 79.7 | 84.4 | 1.65 | 12,255,676 | 25 | 446927 |
| hash | keyed_hash.64B | 75.9 | 75.1 | 79.1 | 74.4 | 80.2 | 1.68 | 13,174,457 | 25 | 518806 |
| hash | derive_key.profile_field | 139 | 137 | 146 | 135 | 147 | 3.39 | 7,209,931 | 25 | 285103 |
| hash | wh512.profile_field | 141 | 144 | 146 | 129 | 168 | 8.68 | 7,116,485 | 25 | 293255 |
| hash | wh512.2048B | 4,095 | 4,129 | 4,315 | 3,827 | 4,343 | 181 | 244,220 | 25 | 10446 |
| rain | constants_derive | 4,384 | 4,398 | 4,608 | 4,082 | 4,638 | 196 | 228,079 | 25 | 8703 |
| rain | encrypt | 9,311,912 | 9,081,652 | 10,093,573 | 8,979,186 | 10,094,959 | 430,078 | 107 | 25 | 4 |
| ggm | tree_root.1 | 159,714 | 163,402 | 170,548 | 147,405 | 172,208 | 8,345 | 6,261 | 25 | 272 |
| ggm | hidden_opening.1 | 1,921 | 1,951 | 1,981 | 1,734 | 1,983 | 70.9 | 520,473 | 25 | 20435 |
| ggm | reconstruct_root.1 | 153,389 | 157,192 | 159,196 | 140,418 | 166,270 | 6,727 | 6,519 | 25 | 255 |
| ggm | roots.32 | 5,137,542 | 5,285,229 | 5,449,624 | 4,719,876 | 5,464,684 | 270,209 | 195 | 25 | 8 |
| ggm | openings.32 | 62,586 | 64,577 | 65,500 | 57,695 | 65,626 | 2,827 | 15,978 | 25 | 681 |
| ggm | reconstruct_roots.32 | 4,840,883 | 4,779,282 | 5,095,939 | 4,512,019 | 5,162,777 | 217,327 | 207 | 25 | 8 |
| transcript | challenges.32B | 9,011 | 8,887 | 9,590 | 8,468 | 9,901 | 468 | 110,975 | 25 | 4058 |
| transcript | challenges.1MiB | 2,417,505 | 2,448,005 | 2,471,488 | 2,178,383 | 2,678,977 | 98,360 | 414 | 25 | 16 |
| sign-phase | master_seed.32B | 314 | 320 | 324 | 286 | 326 | 12.1 | 3,186,827 | 25 | 127105 |
| sign-phase | master_seed.1MiB | 1,022,285 | 1,016,373 | 1,080,089 | 998,163 | 1,146,020 | 31,845 | 978 | 25 | 40 |
| sign-phase | salt | 205 | 210 | 212 | 190 | 215 | 8.13 | 4,870,939 | 25 | 198906 |
| sign-phase | pk_hash | 322 | 318 | 347 | 307 | 351 | 14.1 | 3,104,571 | 25 | 126143 |
| sign-phase | wires.31 | 43,956 | 44,101 | 46,401 | 41,368 | 46,664 | 1,605 | 22,750 | 25 | 973 |
| quicksilver | prove.60gates | 547,064 | 554,197 | 571,843 | 501,633 | 625,065 | 27,863 | 1,828 | 25 | 80 |
| quicksilver | opened_wires.31 | 44,462 | 44,591 | 47,083 | 41,298 | 47,118 | 2,196 | 22,491 | 25 | 834 |
| quicksilver | check_proof.60gates | 339,939 | 333,060 | 363,970 | 325,459 | 368,865 | 13,878 | 2,942 | 25 | 118 |
| keys | secret_key_wrap | 4.90 | 4.83 | 5.37 | 4.80 | 5.41 | 0.17 | 203,880,954 | 25 | 2000000 |
| keys | expand | 279 | 273 | 303 | 271 | 326 | 13.1 | 3,586,410 | 25 | 147547 |
| keys | public_key | 9,132,539 | 9,023,462 | 9,746,312 | 8,961,363 | 10,102,299 | 294,559 | 109 | 25 | 4 |
| keys | keygen_full | 9,399,751 | 9,243,705 | 10,089,735 | 9,000,646 | 10,094,435 | 423,997 | 106 | 25 | 3 |
| parse | public_key.profile | 13.0 | 13.2 | 13.3 | 11.7 | 13.3 | 0.45 | 77,156,841 | 25 | 2000000 |
| parse | signature.profile | 134 | 136 | 140 | 123 | 140 | 6.76 | 7,489,926 | 25 | 231213 |
| full | sign.0B | 14,676,292 | 14,336,046 | 16,069,980 | 14,255,795 | 16,461,276 | 646,730 | 68 | 25 | 2 |
| full | verify.0B | 5,048,415 | 5,001,381 | 5,433,436 | 4,912,230 | 5,438,874 | 153,042 | 198 | 25 | 8 |
| full | sign.32B | 15,346,621 | 15,186,327 | 16,063,462 | 14,282,846 | 18,831,902 | 977,934 | 65 | 25 | 2 |
| full | verify.32B | 5,299,765 | 5,412,316 | 5,636,365 | 4,907,406 | 5,651,472 | 293,718 | 189 | 25 | 8 |
| full | sign.1KiB | 14,523,621 | 14,344,821 | 15,348,849 | 14,277,622 | 16,071,312 | 419,450 | 69 | 25 | 2 |
| full | verify.1KiB | 5,367,661 | 5,504,465 | 5,763,133 | 4,908,247 | 5,774,834 | 294,078 | 186 | 25 | 8 |
| full | sign.64KiB | 15,032,831 | 14,760,859 | 16,089,514 | 14,451,730 | 17,179,647 | 706,051 | 67 | 25 | 2 |
| full | verify.64KiB | 5,139,816 | 5,081,773 | 5,345,454 | 5,031,236 | 5,668,852 | 142,464 | 195 | 25 | 7 |
| full | sign.1MiB | 18,118,373 | 17,587,750 | 20,405,227 | 17,279,889 | 24,063,769 | 1,478,763 | 55 | 25 | 2 |
| full | verify.1MiB | 7,057,411 | 7,016,391 | 7,526,582 | 6,923,115 | 7,695,124 | 180,274 | 142 | 25 | 5 |
| full | sign.16MiB | 67,924,561 | 68,981,759 | 70,893,634 | 62,978,667 | 70,940,989 | 2,645,996 | 15 | 25 | 1 |
| full | verify.16MiB | 40,053,562 | 40,171,041 | 41,736,622 | 37,445,360 | 41,771,521 | 1,231,658 | 25 | 25 | 1 |
| full | sign_wrapper.32B | 14,632,152 | 14,410,193 | 16,033,975 | 14,282,231 | 16,067,387 | 510,741 | 68 | 25 | 2 |
| full | verify_wrapper.32B | 5,105,649 | 4,976,094 | 5,510,371 | 4,908,956 | 6,171,686 | 287,599 | 196 | 25 | 7 |
| full | sign_verify.32B | 20,011,078 | 19,514,959 | 21,546,531 | 19,205,111 | 21,717,747 | 865,727 | 50 | 25 | 1 |

## 8. Reproduce

```bash
BENCH_CPU=4 ./scripts/bench.sh
VORB3_FEATURES=nist1 BENCH_CPU=4 BENCH_OUT=target/benchmark-results-nist1.md ./scripts/bench.sh
VORB3_FEATURES=nist3 BENCH_CPU=4 BENCH_OUT=target/benchmark-results-nist3.md ./scripts/bench.sh
python3 scripts/gen_nist_bench_report.py
```

The harness auto-calibrates each inner loop, records 25 samples, and reports
mean, median, p95, min, max, standard deviation, and operations/second.

## 9. Caveats

- One machine and one compiler version; this is not a controlled lab.
- The benchmark was pinned to CPU 4; other long-running host jobs were
  restricted to CPUs 8-11 for the duration. Absolute numbers remain sensitive
  to frequency scaling, sibling-thread activity, and memory bandwidth.
- Microbenchmarks measure this implementation, not asymptotic complexity.
- No external audit; no constant-time or security claim follows from
  throughput.
