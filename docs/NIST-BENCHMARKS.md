# VORB3 NIST-Tier Full Benchmarks

**Status:** local measurement checkpoint (2026-11-27). Machine- and
compiler-dependent evidence, not a security proof and not an external audit.

This report covers the two compact packs plus the SP-288/35 baseline measured
on the same host in the same session. The raw tables are emitted by
`scripts/bench.sh`; this file is the curated snapshot. See
`docs/BENCHMARKS.md` for the earlier baseline analysis. The compact packs use
bit-interleaved squaring, word-level reduction, and an Itoh-Tsujii inversion
chain; the SP-288/35 baseline is unchanged.

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
| Key generation | 266.10 µs (3,758/s) | 74.25 µs (13,469/s) | 151.82 µs (6,587/s) | 0.28× | 0.57× |
| Sign, 32 B | 6.364 ms (157.1/s) | 4.855 ms (206.0/s) | 5.105 ms (195.9/s) | 0.76× | 0.80× |
| Verify, 32 B | 5.676 ms (176.2/s) | 4.639 ms (215.6/s) | 4.648 ms (215.1/s) | 0.82× | 0.82× |
| Sign + verify, 32 B | 12.007 ms (83.3/s) | 9.501 ms (105.3/s) | 9.834 ms (101.7/s) | 0.79× | 0.82× |
| Field multiplication | 712 ns (1,404,494/s) | 216 ns (4,629,630/s) | 409 ns (2,444,988/s) | 0.30× | 0.57× |
| Field squaring | 13.4 ns (74,626,866/s) | 10.5 ns (95,238,095/s) | 11.8 ns (84,745,763/s) | 0.78× | 0.88× |
| Field inversion | 17.36 µs (57,597/s) | 4.43 µs (225,581/s) | 9.40 µs (106,338/s) | 0.26× | 0.54× |
| Rain-SP1 encryption | 257.88 µs (3,878/s) | 69.39 µs (14,411/s) | 146.65 µs (6,819/s) | 0.27× | 0.57× |
| GGM roots (all trees) | 5.855 ms (170.8/s) | 4.672 ms (214.0/s) | 4.776 ms (209.4/s) | 0.80× | 0.82× |
| GGM root reconstruction | 5.621 ms (177.9/s) | 4.508 ms (221.8/s) | 4.540 ms (220.3/s) | 0.80× | 0.81× |
| QuickSilver prove | 263.66 µs (3,793/s) | 81.02 µs (12,342/s) | 152.43 µs (6,560/s) | 0.31× | 0.58× |
| QuickSilver verify | 177.03 µs (5,649/s) | 52.82 µs (18,931/s) | 99.34 µs (10,066/s) | 0.30× | 0.56× |
| Public-key parse | 15.8 ns (63,291,139/s) | 11.2 ns (89,285,714/s) | 11.6 ns (86,206,897/s) | 0.71× | 0.73× |
| Signature parse | 209 ns (4,784,689/s) | 88.8 ns (11,261,261/s) | 121 ns (8,264,463/s) | 0.42× | 0.58× |

### Observations

- Level 1+ signing is **0.76×** the SP-288/35 baseline;
  Level 3+ is **0.80×** (below 1.00× is faster).
- Verification is **0.82×** (Level 1+) and
  **0.82×** (Level 3+); the packs use 32 trees instead of 35.
- Rain-SP1 encryption is 69.39 µs (Level 1+) and 146.65 µs
  (Level 3+) versus 257.88 µs baseline. Field inversion is
  4.43 µs / 9.40 µs versus 17.36 µs; the
  Itoh-Tsujii chain uses `n = BITS - 1` squarings and about `log2(n)`
  multiplications instead of `n - 1` multiplications.
- Compact-field squaring is now 10.5 ns / 11.8 ns, close to
  the 288-bit specialized squaring (13.4 ns).
- GGM roots are 0.80× / 0.82× and root
  reconstruction is 0.80× / 0.81× the
  baseline because the packs use 32 trees instead of 35.
- Public-key parsing is 0.71× / 0.73× and signature
  parsing is 0.42× / 0.58× baseline, in
  proportion to the smaller encodings.

## 2. Where signing time goes

Independent phase medians; the measured phase sum can differ from the
end-to-end operation by a few percent because each row is sampled separately.

### Level 1+

| Phase | Median | Share of phase sum |
|---|---:|---:|
| GGM root derivation | 4.672 ms | 95.64% |
| Rain-SP1 encryption | 69.39 µs | 1.42% |
| QuickSilver prover | 81.02 µs | 1.66% |
| Hidden openings | 46.84 µs | 0.96% |
| Wire/tag construction | 6.68 µs | 0.14% |
| Transcript | 8.22 µs | 0.17% |
| Master seed | 231 ns | <0.01% |
| Salt | 186 ns | <0.01% |
| Public-key hash | 186 ns | <0.01% |
| **Measured phase sum** | **4.885 ms** | **100%** |
| Full operation | 4.855 ms | 99.39% of phase sum |

### Level 3+

| Phase | Median | Share of phase sum |
|---|---:|---:|
| GGM root derivation | 4.776 ms | 92.67% |
| Rain-SP1 encryption | 146.65 µs | 2.85% |
| QuickSilver prover | 152.43 µs | 2.96% |
| Hidden openings | 57.23 µs | 1.11% |
| Wire/tag construction | 12.67 µs | 0.25% |
| Transcript | 8.08 µs | 0.16% |
| Master seed | 287 ns | <0.01% |
| Salt | 188 ns | <0.01% |
| Public-key hash | 299 ns | <0.01% |
| **Measured phase sum** | **5.154 ms** | **100%** |
| Full operation | 5.105 ms | 99.04% of phase sum |

## 3. Where verification time goes

### Level 1+

| Phase | Median | Share of phase sum |
|---|---:|---:|
| GGM root reconstruction | 4.508 ms | 98.43% |
| QuickSilver verifier | 52.82 µs | 1.15% |
| Wire openings | 6.72 µs | 0.15% |
| Transcript | 8.22 µs | 0.18% |
| Rain constants | 4.21 µs | 0.09% |
| **Measured phase sum** | **4.580 ms** | **100%** |
| Full operation | 4.639 ms | 101.28% of phase sum |

### Level 3+

| Phase | Median | Share of phase sum |
|---|---:|---:|
| GGM root reconstruction | 4.540 ms | 97.34% |
| QuickSilver verifier | 99.34 µs | 2.13% |
| Wire openings | 12.62 µs | 0.27% |
| Transcript | 8.08 µs | 0.17% |
| Rain constants | 4.11 µs | 0.09% |
| **Measured phase sum** | **4.664 ms** | **100%** |
| Full operation | 4.648 ms | 99.65% of phase sum |

## 4. Message-size scaling

| Message | L1+ sign | L1+ verify | L3+ sign | L3+ verify |
|---:|---:|---:|---:|---:|
| 0B | 4.857 ms | 4.643 ms | 5.132 ms | 4.655 ms |
| 32B | 4.855 ms | 4.639 ms | 5.105 ms | 4.648 ms |
| 1KiB | 4.905 ms | 4.648 ms | 5.170 ms | 4.696 ms |
| 64KiB | 5.106 ms | 4.767 ms | 5.343 ms | 4.785 ms |
| 1MiB | 8.019 ms | 6.750 ms | 8.111 ms | 6.723 ms |
| 16MiB | 54.988 ms | 38.453 ms | 54.222 ms | 37.615 ms |

At 16 MiB, signing costs about **3.13 ms/MiB** (Level 1+) and
**3.07 ms/MiB** (Level 3+) over the empty-message case;
verification costs about **2.11 ms/MiB** and
**2.06 ms/MiB**. The baseline slopes are 3.06
ms/MiB and 2.11 ms/MiB. Signing hashes the message twice;
verification hashes it once.

## 5. Build and memory

| Profile | bench text | bench data | bench bss | bench dec | attack text | attack data | attack bss | attack dec | Max RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| SP-288/35 | 716220 | 10960 | 3954 | 731134 | 463230 | 11968 | 2042 | 477240 | 20 MiB |
| Level 1+ | 691460 | 10960 | 4130 | 706550 | 447238 | 11968 | 1642 | 460848 | 20 MiB |
| Level 3+ | 702860 | 10960 | 930 | 714750 | 450326 | 11968 | 2650 | 464944 | 20 MiB |

The library remains `no_std`, allocates no heap, and has zero runtime
dependencies. The profile `nist_stack` tests pass at 32 KiB for sign/verify
and 64 KiB when the 7,976/10,296-byte signature buffer itself is placed on the
stack.

The `public_key.profile` and `signature.profile` rows parse the profile's
40/56-byte public key and 7,976/10,296-byte signature respectively.

## 6. Full Level 1+ results

| Category | Benchmark | Mean ns/op | Median ns/op | p95 ns/op | Min ns/op | Max ns/op | Stddev ns | Ops/s | Samples | Inner |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| field | add | 0.92 | 0.92 | 0.97 | 0.81 | 0.99 | 0.04 | 1,091,859,159 | 25 | 2000000 |
| field | mul | 219 | 216 | 234 | 212 | 237 | 7.72 | 4,556,050 | 25 | 179613 |
| field | square | 10.7 | 10.5 | 11.3 | 10.4 | 11.3 | 0.35 | 93,370,357 | 25 | 2000000 |
| field | inverse | 4,485 | 4,433 | 4,683 | 4,348 | 4,788 | 126 | 222,947 | 25 | 7627 |
| field | from_bytes | 0.56 | 0.55 | 0.62 | 0.55 | 0.74 | 0.04 | 1,772,932,582 | 25 | 2000000 |
| field | to_bytes | 0.53 | 0.52 | 0.55 | 0.52 | 0.56 | 0.01 | 1,883,942,581 | 25 | 2000000 |
| hash | blake3.empty | 64.9 | 64.2 | 68.0 | 63.5 | 71.3 | 1.86 | 15,416,672 | 25 | 580551 |
| hash | blake3.64B | 70.8 | 70.8 | 73.2 | 70.0 | 73.7 | 0.88 | 14,114,875 | 25 | 464037 |
| hash | blake3.1KiB | 984 | 967 | 1,056 | 952 | 1,075 | 34.6 | 1,015,824 | 25 | 37608 |
| hash | blake3.1MiB | 1,048,866 | 1,018,714 | 1,122,321 | 1,006,078 | 1,124,219 | 43,794 | 953 | 25 | 38 |
| hash | blake3_xof.64B | 76.9 | 79.8 | 80.2 | 71.8 | 80.3 | 3.80 | 12,999,146 | 25 | 426439 |
| hash | keyed_hash.64B | 66.6 | 67.6 | 68.0 | 60.6 | 69.0 | 2.37 | 15,024,909 | 25 | 364630 |
| hash | derive_key.profile_field | 136 | 135 | 140 | 135 | 145 | 2.29 | 7,344,610 | 25 | 293040 |
| hash | wh512.profile_field | 129 | 128 | 138 | 123 | 140 | 5.56 | 7,737,463 | 25 | 306513 |
| hash | wh512.2048B | 4,004 | 3,954 | 4,281 | 3,890 | 4,306 | 115 | 249,732 | 25 | 10241 |
| rain | constants_derive | 4,221 | 4,207 | 4,479 | 4,033 | 4,866 | 183 | 236,894 | 25 | 9885 |
| rain | encrypt | 70,044 | 69,392 | 72,266 | 68,624 | 73,723 | 1,385 | 14,277 | 25 | 578 |
| ggm | tree_root.1 | 147,384 | 145,273 | 156,302 | 144,282 | 160,079 | 4,314 | 6,785 | 25 | 276 |
| ggm | hidden_opening.1 | 1,396 | 1,391 | 1,405 | 1,385 | 1,492 | 20.8 | 716,548 | 25 | 28216 |
| ggm | reconstruct_root.1 | 142,820 | 141,765 | 153,625 | 140,484 | 154,154 | 3,711 | 7,002 | 25 | 287 |
| ggm | roots.32 | 4,733,353 | 4,672,042 | 4,968,434 | 4,621,927 | 5,160,477 | 131,923 | 211 | 25 | 8 |
| ggm | openings.32 | 47,172 | 46,839 | 49,389 | 46,294 | 49,514 | 958 | 21,199 | 25 | 871 |
| ggm | reconstruct_roots.32 | 4,561,459 | 4,508,005 | 4,669,260 | 4,491,926 | 5,608,130 | 220,826 | 219 | 25 | 8 |
| transcript | challenges.32B | 8,422 | 8,218 | 9,119 | 8,125 | 9,156 | 354 | 118,734 | 25 | 4630 |
| transcript | challenges.1MiB | 2,073,790 | 2,070,096 | 2,093,463 | 2,049,056 | 2,213,681 | 30,749 | 482 | 25 | 19 |
| sign-phase | master_seed.32B | 231 | 231 | 239 | 229 | 243 | 3.09 | 4,320,690 | 25 | 159872 |
| sign-phase | master_seed.1MiB | 1,028,394 | 1,019,195 | 1,068,906 | 1,008,680 | 1,087,182 | 21,011 | 972 | 25 | 39 |
| sign-phase | salt | 187 | 186 | 194 | 184 | 196 | 2.72 | 5,343,863 | 25 | 196174 |
| sign-phase | pk_hash | 191 | 186 | 207 | 184 | 208 | 8.79 | 5,235,468 | 25 | 206291 |
| sign-phase | wires.31 | 6,698 | 6,680 | 6,760 | 6,672 | 6,862 | 43.5 | 149,290 | 25 | 5993 |
| quicksilver | prove.60gates | 81,373 | 81,024 | 84,180 | 79,793 | 88,726 | 1,947 | 12,289 | 25 | 503 |
| quicksilver | opened_wires.31 | 6,754 | 6,725 | 6,949 | 6,657 | 7,209 | 114 | 148,062 | 25 | 5385 |
| quicksilver | check_proof.60gates | 53,782 | 52,824 | 58,191 | 52,048 | 58,543 | 2,029 | 18,593 | 25 | 585 |
| keys | secret_key_wrap | 1.14 | 1.12 | 1.23 | 1.12 | 1.27 | 0.04 | 876,712,175 | 25 | 2000000 |
| keys | expand | 271 | 270 | 286 | 268 | 288 | 4.80 | 3,683,654 | 25 | 148643 |
| keys | public_key | 74,231 | 73,369 | 78,252 | 72,780 | 78,776 | 1,829 | 13,471 | 25 | 529 |
| keys | keygen_full | 75,225 | 74,246 | 79,218 | 72,969 | 80,824 | 2,134 | 13,294 | 25 | 549 |
| parse | public_key.profile | 11.3 | 11.2 | 12.1 | 11.1 | 12.2 | 0.27 | 88,381,403 | 25 | 2000000 |
| parse | signature.profile | 89.3 | 88.8 | 93.9 | 88.2 | 95.2 | 1.64 | 11,200,558 | 25 | 331674 |
| full | sign.0B | 4,874,021 | 4,856,648 | 4,969,496 | 4,844,434 | 5,006,713 | 40,955 | 205 | 25 | 8 |
| full | verify.0B | 4,630,048 | 4,642,966 | 4,663,100 | 4,581,787 | 4,669,524 | 27,765 | 216 | 25 | 8 |
| full | sign.32B | 4,917,844 | 4,855,163 | 5,168,068 | 4,838,270 | 5,417,421 | 137,282 | 203 | 25 | 8 |
| full | verify.32B | 4,728,018 | 4,638,712 | 5,154,562 | 4,583,350 | 5,159,265 | 173,435 | 212 | 25 | 8 |
| full | sign.1KiB | 4,909,314 | 4,904,873 | 4,976,875 | 4,875,978 | 4,983,120 | 23,436 | 204 | 25 | 8 |
| full | verify.1KiB | 4,675,620 | 4,648,157 | 4,866,288 | 4,610,421 | 4,967,773 | 80,416 | 214 | 25 | 8 |
| full | sign.64KiB | 5,170,136 | 5,105,529 | 5,668,775 | 5,050,841 | 5,864,915 | 196,612 | 193 | 25 | 7 |
| full | verify.64KiB | 4,823,921 | 4,766,802 | 5,134,857 | 4,716,267 | 5,252,170 | 146,345 | 207 | 25 | 8 |
| full | sign.1MiB | 8,080,776 | 8,018,511 | 8,510,938 | 7,931,374 | 8,909,283 | 219,046 | 124 | 25 | 4 |
| full | verify.1MiB | 6,778,468 | 6,750,371 | 6,852,644 | 6,690,175 | 7,406,174 | 135,133 | 148 | 25 | 5 |
| full | sign.16MiB | 55,334,613 | 54,988,459 | 56,842,815 | 54,473,616 | 57,193,146 | 814,858 | 18 | 25 | 1 |
| full | verify.16MiB | 38,915,717 | 38,452,543 | 41,105,320 | 37,742,557 | 42,049,451 | 1,095,844 | 26 | 25 | 1 |
| full | sign_wrapper.32B | 4,968,855 | 4,888,397 | 5,453,672 | 4,851,148 | 5,462,047 | 178,341 | 201 | 25 | 8 |
| full | verify_wrapper.32B | 4,636,470 | 4,613,345 | 4,677,415 | 4,578,441 | 4,983,872 | 77,237 | 216 | 25 | 8 |
| full | sign_verify.32B | 9,687,718 | 9,500,755 | 10,290,573 | 9,442,612 | 10,484,244 | 324,437 | 103 | 25 | 4 |

## 7. Full Level 3+ results

| Category | Benchmark | Mean ns/op | Median ns/op | p95 ns/op | Min ns/op | Max ns/op | Stddev ns | Ops/s | Samples | Inner |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| field | add | 5.47 | 5.35 | 5.91 | 5.26 | 5.93 | 0.24 | 182,861,809 | 25 | 2000000 |
| field | mul | 413 | 409 | 443 | 405 | 453 | 12.7 | 2,418,461 | 25 | 95762 |
| field | square | 11.9 | 11.8 | 12.7 | 11.6 | 12.9 | 0.38 | 83,705,469 | 25 | 2000000 |
| field | inverse | 9,439 | 9,404 | 9,701 | 9,294 | 9,906 | 131 | 105,946 | 25 | 4316 |
| field | from_bytes | 5.37 | 5.33 | 5.50 | 5.28 | 5.52 | 0.08 | 186,206,328 | 25 | 2000000 |
| field | to_bytes | 4.49 | 4.42 | 4.93 | 4.37 | 4.94 | 0.16 | 222,477,869 | 25 | 2000000 |
| hash | blake3.empty | 64.7 | 64.5 | 66.9 | 64.1 | 67.0 | 0.70 | 15,463,819 | 25 | 597907 |
| hash | blake3.64B | 70.7 | 70.5 | 71.6 | 70.3 | 71.6 | 0.40 | 14,140,333 | 25 | 498753 |
| hash | blake3.1KiB | 924 | 919 | 962 | 917 | 982 | 14.9 | 1,081,867 | 25 | 42684 |
| hash | blake3.1MiB | 1,031,719 | 1,011,044 | 1,117,131 | 998,822 | 1,117,974 | 41,025 | 969 | 25 | 39 |
| hash | blake3_xof.64B | 72.2 | 72.1 | 72.7 | 71.9 | 73.0 | 0.30 | 13,848,342 | 25 | 456100 |
| hash | keyed_hash.64B | 61.9 | 60.9 | 65.9 | 60.3 | 66.0 | 1.98 | 16,143,435 | 25 | 554785 |
| hash | derive_key.profile_field | 139 | 138 | 149 | 136 | 149 | 3.83 | 7,186,660 | 25 | 277200 |
| hash | wh512.profile_field | 128 | 127 | 137 | 125 | 141 | 3.85 | 7,822,024 | 25 | 293470 |
| hash | wh512.2048B | 4,172 | 4,300 | 4,330 | 3,884 | 4,333 | 177 | 239,682 | 25 | 10331 |
| rain | constants_derive | 4,140 | 4,108 | 4,437 | 4,071 | 4,631 | 124 | 241,517 | 25 | 9795 |
| rain | encrypt | 147,404 | 146,650 | 153,598 | 145,945 | 155,670 | 2,301 | 6,784 | 25 | 274 |
| ggm | tree_root.1 | 150,287 | 148,431 | 157,672 | 147,423 | 174,057 | 5,463 | 6,654 | 25 | 260 |
| ggm | hidden_opening.1 | 1,746 | 1,733 | 1,832 | 1,721 | 1,845 | 34.1 | 572,678 | 25 | 23001 |
| ggm | reconstruct_root.1 | 142,363 | 141,987 | 143,283 | 140,692 | 151,356 | 2,006 | 7,024 | 25 | 285 |
| ggm | roots.32 | 4,788,285 | 4,776,363 | 4,892,864 | 4,728,021 | 4,983,229 | 52,112 | 209 | 25 | 8 |
| ggm | openings.32 | 57,573 | 57,235 | 61,329 | 57,060 | 61,352 | 1,140 | 17,369 | 25 | 705 |
| ggm | reconstruct_roots.32 | 4,606,718 | 4,540,213 | 4,978,790 | 4,508,090 | 5,097,979 | 159,182 | 217 | 25 | 8 |
| transcript | challenges.32B | 8,156 | 8,083 | 8,692 | 8,010 | 8,778 | 212 | 122,608 | 25 | 4706 |
| transcript | challenges.1MiB | 2,043,063 | 2,031,454 | 2,161,621 | 2,018,129 | 2,197,887 | 41,991 | 489 | 25 | 19 |
| sign-phase | master_seed.32B | 288 | 287 | 303 | 285 | 308 | 5.24 | 3,466,360 | 25 | 131147 |
| sign-phase | master_seed.1MiB | 1,021,174 | 1,013,621 | 1,070,961 | 1,009,418 | 1,088,545 | 20,583 | 979 | 25 | 39 |
| sign-phase | salt | 188 | 188 | 190 | 187 | 191 | 1.09 | 5,312,730 | 25 | 199600 |
| sign-phase | pk_hash | 300 | 299 | 314 | 297 | 330 | 6.93 | 3,328,413 | 25 | 83022 |
| sign-phase | wires.31 | 12,712 | 12,670 | 12,776 | 12,619 | 13,516 | 172 | 78,667 | 25 | 2826 |
| quicksilver | prove.60gates | 152,943 | 152,428 | 153,941 | 151,993 | 162,162 | 1,966 | 6,538 | 25 | 264 |
| quicksilver | opened_wires.31 | 12,668 | 12,625 | 12,700 | 12,585 | 13,603 | 197 | 78,942 | 25 | 3164 |
| quicksilver | check_proof.60gates | 100,530 | 99,344 | 106,681 | 98,744 | 108,355 | 2,660 | 9,947 | 25 | 370 |
| keys | secret_key_wrap | 6.26 | 6.18 | 6.89 | 6.14 | 6.90 | 0.22 | 159,671,692 | 25 | 2000000 |
| keys | expand | 278 | 275 | 293 | 273 | 302 | 7.11 | 3,591,025 | 25 | 145772 |
| keys | public_key | 154,865 | 151,826 | 167,948 | 151,345 | 168,107 | 5,544 | 6,457 | 25 | 268 |
| keys | keygen_full | 152,466 | 151,822 | 157,560 | 150,594 | 164,702 | 2,911 | 6,559 | 25 | 265 |
| parse | public_key.profile | 11.6 | 11.6 | 11.6 | 11.5 | 11.7 | 0.04 | 86,466,648 | 25 | 2000000 |
| parse | signature.profile | 125 | 121 | 135 | 120 | 135 | 5.66 | 8,003,145 | 25 | 259909 |
| full | sign.0B | 5,181,567 | 5,131,642 | 5,644,435 | 5,096,791 | 5,649,287 | 146,360 | 193 | 25 | 7 |
| full | verify.0B | 4,679,264 | 4,654,799 | 4,769,115 | 4,629,987 | 4,877,831 | 52,371 | 214 | 25 | 8 |
| full | sign.32B | 5,108,470 | 5,104,862 | 5,133,644 | 5,093,590 | 5,140,886 | 11,705 | 196 | 25 | 7 |
| full | verify.32B | 4,654,769 | 4,648,256 | 4,692,126 | 4,636,814 | 4,697,907 | 16,059 | 215 | 25 | 8 |
| full | sign.1KiB | 5,266,264 | 5,170,020 | 5,664,558 | 5,104,299 | 5,716,784 | 183,859 | 190 | 25 | 7 |
| full | verify.1KiB | 4,770,980 | 4,695,971 | 5,149,128 | 4,635,960 | 5,192,916 | 168,898 | 210 | 25 | 8 |
| full | sign.64KiB | 5,371,191 | 5,343,405 | 5,688,209 | 5,280,512 | 5,739,633 | 114,261 | 186 | 25 | 7 |
| full | verify.64KiB | 4,791,878 | 4,785,065 | 4,835,796 | 4,752,980 | 5,017,690 | 52,460 | 209 | 25 | 8 |
| full | sign.1MiB | 8,126,620 | 8,111,301 | 8,256,626 | 8,069,511 | 8,264,498 | 53,752 | 123 | 25 | 4 |
| full | verify.1MiB | 6,727,836 | 6,722,910 | 6,799,007 | 6,639,077 | 6,927,636 | 53,927 | 149 | 25 | 5 |
| full | sign.16MiB | 54,276,919 | 54,222,336 | 54,793,492 | 53,891,886 | 55,136,893 | 308,303 | 18 | 25 | 1 |
| full | verify.16MiB | 37,851,058 | 37,615,047 | 39,443,236 | 36,996,230 | 41,452,051 | 948,677 | 26 | 25 | 1 |
| full | sign_wrapper.32B | 5,136,272 | 5,116,054 | 5,334,700 | 5,098,030 | 5,376,980 | 67,284 | 195 | 25 | 7 |
| full | verify_wrapper.32B | 4,696,403 | 4,658,523 | 5,027,600 | 4,642,294 | 5,095,851 | 113,889 | 213 | 25 | 8 |
| full | sign_verify.32B | 10,026,611 | 9,833,740 | 10,917,915 | 9,741,523 | 11,370,938 | 452,094 | 100 | 25 | 3 |

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
