# VORB3 SP-288/35 — Full Project Benchmark

**Status:** local measurement checkpoint. Machine- and compiler-dependent
evidence, not a security proof and not an external audit.

This is a curated snapshot. `scripts/bench.sh` regenerates the raw table into
`target/benchmark-results.md` (or `$BENCH_OUT`); the analysis below is written
against this snapshot and is not auto-updated.

The table below is the **optimized** build (field squaring/reduction, Horner
CLMUL, precomputed WH512/GGM keys, one-chunk BLAKE3, GGM prefix states). The
previous snapshot is preserved in `docs/OPTIMIZATIONS.md`.

- date (UTC): `2026-11-26T22:04:47Z`
- host: `Linux 7.2.9-200.fc44.x86_64 x86_64`
- cpu: `Intel(R) Core(TM) i5-14400F`
- cores/threads: `16`
- rustc: `rustc 1.99.0 (b940084d7 2026-09-28)`
- cargo: `cargo 1.99.0 (5f94df478 2026-08-27)`
- profile: release, opt-level=3, LTO, codegen-units=1, panic=abort, strip
- signature: 13,672 bytes; key: 36-byte seed, 72-byte public key

```text
size vorb3-bench:
   text	   data	    bss	    dec	    hex	filename
 714724	  10944	   1378	 727046	  b1806	target/release/vorb3-bench

size vorb3-attack:
   text	   data	    bss	    dec	    hex	filename
 414278	  11968	   1834	 428080	  68830	target/release/vorb3-attack

```

## Method

`tools/bench` is a std-only custom harness. Each benchmark warms up, then
auto-calibrates an inner loop to about 40 ms per sample (20 ms in quick
mode), records 25 samples (5 in quick mode), and reports the per-operation
mean, median, p95, min, max, standard deviation, and operations/second.
Inputs are black-boxed and varied where constant hoisting is possible.
The harness is pinned to one CPU with `taskset` when available.

## Results

| Category | Benchmark | Mean ns/op | Median ns/op | p95 ns/op | Min ns/op | Max ns/op | Stddev ns | Ops/s | Samples | Inner |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| field | add | 2.50 | 2.51 | 2.55 | 2.11 | 2.55 | 0.08 | 399,549,730 | 25 | 2000000 |
| field | mul | 790 | 789 | 791 | 789 | 794 | 1.14 | 1,266,340 | 25 | 50188 |
| field | square | 15.1 | 15.1 | 15.1 | 15.0 | 15.2 | 0.04 | 66,287,983 | 25 | 2000000 |
| field | inverse | 18,315 | 18,311 | 18,337 | 18,286 | 18,358 | 16.7 | 54,600 | 25 | 2180 |
| field | from_bytes | 0.85 | 0.85 | 0.85 | 0.85 | 0.85 | 0.00 | 1,175,208,608 | 25 | 2000000 |
| field | to_bytes | 0.86 | 0.85 | 0.86 | 0.85 | 1.04 | 0.04 | 1,168,263,168 | 25 | 2000000 |
| hash | blake3.empty | 71.7 | 71.7 | 71.8 | 71.7 | 71.8 | 0.03 | 13,941,707 | 25 | 520156 |
| hash | blake3.64B | 78.7 | 78.7 | 78.8 | 78.7 | 78.9 | 0.05 | 12,699,282 | 25 | 445434 |
| hash | blake3.1KiB | 1,027 | 1,026 | 1,029 | 1,025 | 1,040 | 2.99 | 973,943 | 25 | 37767 |
| hash | blake3.1MiB | 1,111,600 | 1,111,136 | 1,114,006 | 1,109,337 | 1,116,211 | 1,595 | 900 | 25 | 36 |
| hash | blake3_xof.64B | 80.8 | 80.5 | 83.8 | 80.5 | 84.6 | 1.02 | 12,368,842 | 25 | 432900 |
| hash | keyed_hash.64B | 67.1 | 67.1 | 67.4 | 67.0 | 67.4 | 0.13 | 14,896,778 | 25 | 471142 |
| hash | derive_key.36B | 153 | 153 | 154 | 153 | 156 | 0.53 | 6,530,515 | 25 | 246305 |
| hash | wh512.36B | 138 | 138 | 140 | 138 | 141 | 0.63 | 7,224,806 | 25 | 273972 |
| hash | wh512.2240B | 4,795 | 4,787 | 4,848 | 4,779 | 4,909 | 27.1 | 208,539 | 25 | 8376 |
| rain | constants_derive | 4,917 | 4,915 | 4,924 | 4,911 | 4,940 | 5.74 | 203,364 | 25 | 8167 |
| rain | encrypt | 286,705 | 286,562 | 287,331 | 286,061 | 287,731 | 366 | 3,488 | 25 | 138 |
| ggm | tree_root.1 | 178,540 | 178,494 | 178,944 | 178,386 | 178,974 | 154 | 5,601 | 25 | 223 |
| ggm | hidden_opening.1 | 2,400 | 2,399 | 2,408 | 2,396 | 2,414 | 3.76 | 416,661 | 25 | 16575 |
| ggm | reconstruct_root.1 | 173,871 | 173,133 | 177,382 | 172,836 | 186,515 | 2,770 | 5,751 | 25 | 231 |
| ggm | roots.35 | 6,255,958 | 6,225,193 | 6,356,354 | 6,220,001 | 6,562,176 | 74,183 | 160 | 25 | 6 |
| ggm | openings.35 | 87,554 | 87,533 | 87,830 | 87,237 | 87,985 | 148 | 11,422 | 25 | 456 |
| ggm | reconstruct_roots.35 | 6,069,759 | 6,067,233 | 6,121,846 | 6,031,098 | 6,133,936 | 26,412 | 165 | 25 | 6 |
| transcript | challenges.32B | 9,722 | 9,680 | 9,945 | 9,566 | 9,957 | 113 | 102,854 | 25 | 4077 |
| transcript | challenges.1MiB | 2,255,692 | 2,255,433 | 2,270,963 | 2,220,965 | 2,278,985 | 10,680 | 443 | 25 | 17 |
| sign-phase | master_seed.32B | 329 | 323 | 363 | 321 | 377 | 15.8 | 3,035,039 | 25 | 117577 |
| sign-phase | master_seed.1MiB | 1,120,085 | 1,116,143 | 1,136,110 | 1,111,765 | 1,140,352 | 8,150 | 893 | 25 | 35 |
| sign-phase | salt | 209 | 209 | 210 | 208 | 210 | 0.32 | 4,776,504 | 25 | 168279 |
| sign-phase | pk_hash | 332 | 332 | 334 | 310 | 336 | 4.49 | 3,015,257 | 25 | 116414 |
| sign-phase | wires.31 | 24,417 | 24,402 | 24,500 | 24,355 | 24,556 | 49.8 | 40,955 | 25 | 1636 |
| quicksilver | prove.60gates | 295,617 | 295,608 | 296,731 | 294,704 | 296,917 | 687 | 3,383 | 25 | 135 |
| quicksilver | opened_wires.31 | 24,774 | 24,499 | 26,668 | 24,254 | 26,673 | 661 | 40,365 | 25 | 1654 |
| quicksilver | check_proof.60gates | 192,970 | 191,593 | 203,077 | 190,915 | 206,689 | 3,750 | 5,182 | 25 | 209 |
| keys | secret_key_wrap | 1.76 | 1.72 | 1.91 | 1.71 | 1.92 | 0.07 | 568,855,505 | 25 | 2000000 |
| keys | expand | 322 | 323 | 329 | 314 | 335 | 6.53 | 3,105,543 | 25 | 79554 |
| keys | public_key | 292,648 | 292,590 | 294,336 | 276,635 | 304,738 | 4,163 | 3,417 | 25 | 136 |
| keys | keygen_full | 293,668 | 293,750 | 294,441 | 292,270 | 294,504 | 600 | 3,405 | 25 | 136 |
| parse | public_key.72B | 12.3 | 12.3 | 12.3 | 12.3 | 12.3 | 0.01 | 81,473,901 | 25 | 2000000 |
| parse | signature.13672B | 176 | 176 | 179 | 176 | 183 | 1.45 | 5,667,456 | 25 | 185270 |
| full | sign.0B | 7,000,691 | 6,986,436 | 7,058,570 | 6,969,859 | 7,218,285 | 48,734 | 143 | 25 | 5 |
| full | verify.0B | 6,303,053 | 6,300,483 | 6,329,360 | 6,288,589 | 6,347,307 | 12,803 | 159 | 25 | 6 |
| full | sign.32B | 7,059,975 | 7,065,453 | 7,109,669 | 6,973,417 | 7,111,512 | 47,920 | 142 | 25 | 5 |
| full | verify.32B | 6,344,993 | 6,332,789 | 6,413,271 | 6,284,921 | 6,417,034 | 49,182 | 158 | 25 | 6 |
| full | sign.1KiB | 6,952,886 | 6,965,173 | 6,970,901 | 6,645,141 | 6,976,329 | 64,194 | 144 | 25 | 5 |
| full | verify.1KiB | 6,289,255 | 6,288,843 | 6,296,038 | 6,284,956 | 6,299,239 | 3,037 | 159 | 25 | 6 |
| full | sign.64KiB | 7,171,363 | 7,170,810 | 7,177,397 | 7,167,587 | 7,177,961 | 2,530 | 139 | 25 | 5 |
| full | verify.64KiB | 6,433,547 | 6,428,588 | 6,449,462 | 6,424,332 | 6,513,785 | 17,840 | 155 | 25 | 6 |
| full | sign.1MiB | 10,324,437 | 10,314,363 | 10,386,057 | 10,302,035 | 10,429,598 | 28,705 | 97 | 25 | 3 |
| full | verify.1MiB | 8,597,880 | 8,562,364 | 8,882,278 | 8,543,868 | 9,078,397 | 119,223 | 116 | 25 | 4 |
| full | sign.16MiB | 60,627,365 | 60,641,204 | 61,051,211 | 59,166,447 | 61,133,056 | 390,609 | 16 | 25 | 1 |
| full | verify.16MiB | 42,246,255 | 42,212,726 | 42,519,555 | 42,128,225 | 42,669,597 | 125,685 | 24 | 25 | 1 |
| full | sign_wrapper.32B | 6,952,330 | 6,960,969 | 6,966,134 | 6,783,947 | 6,966,763 | 36,248 | 144 | 25 | 5 |
| full | verify_wrapper.32B | 6,293,040 | 6,286,417 | 6,312,600 | 6,282,895 | 6,333,779 | 12,751 | 159 | 25 | 6 |
| full | sign_verify.32B | 13,284,298 | 13,289,031 | 13,307,260 | 13,247,228 | 13,312,461 | 20,464 | 75 | 25 | 3 |

Max RSS: 20 MiB

## Analysis

All headline numbers use medians from the table above. Throughput is the
reciprocal of the headline latency.

### Headline

| Operation | Median latency | Throughput |
|---|---:|---:|
| Key generation (`keygen_full`) | 0.294 ms | 3,405/s |
| Sign, 32-byte KAT message | 7.065 ms | 142/s |
| Verify, 32-byte KAT message | 6.333 ms | 158/s |
| Sign + verify pair | 13.289 ms | 75.3/s |
| Rain-SP1 encryption | 0.287 ms | 3,488/s |
| GGM root pass, 35 trees | 6.256 ms | 160/s |
| QuickSilver prove, 60 gates | 0.296 ms | 3,383/s |
| QuickSilver check, 60 gates | 0.192 ms | 5,182/s |

Relative to the pre-optimization snapshot: Rain **≈52×**, sign **≈4.95×**,
verify **≈3.03×**, key generation **≈50.6×**, field squaring **≈215×**, field
inversion **≈54×**.

### Where signing time goes

| Phase | Median | Share of sign |
|---|---:|---:|
| 35-tree GGM root pass | 6.256 ms | 88.6% |
| Rain-SP1 encryption | 0.287 ms | 4.1% |
| QuickSilver prover | 0.296 ms | 4.2% |
| 35 hidden openings + copath writes | 0.088 ms | 1.2% |
| Wire/tag construction | 0.024 ms | 0.35% |
| Transcript | 0.010 ms | 0.14% |
| Master seed, salt, public-key hash | 0.001 ms | <0.02% |

The phase sum is about 6.96 ms, consistent with the measured 7.07 ms sign.
GGM/BLAKE3 is now the dominant cost; Rain is no longer the bottleneck.

### Where verification time goes

| Phase | Median | Share of verify |
|---|---:|---:|
| 35-tree root reconstruction | 6.067 ms | 95.8% |
| QuickSilver verifier | 0.192 ms | 3.0% |
| Wire openings | 0.025 ms | 0.39% |
| Transcript | 0.010 ms | 0.15% |
| Rain constants | 0.005 ms | 0.08% |

Verification is GGM/Merkle reconstruction plus BLAKE3; the proof check is small.

### Message-size scaling

| Message | Sign median | Verify median | Sign Δ vs 0 B | Verify Δ vs 0 B |
|---:|---:|---:|---:|---:|
| 0 B | 6.986 ms | 6.300 ms | — | — |
| 32 B | 7.065 ms | 6.333 ms | +0.079 ms | +0.033 ms |
| 1 KiB | 6.965 ms | 6.289 ms | -0.021 ms | -0.011 ms |
| 64 KiB | 7.171 ms | 6.429 ms | +0.185 ms | +0.129 ms |
| 1 MiB | 10.314 ms | 8.562 ms | +3.328 ms | +2.262 ms |
| 16 MiB | 60.641 ms | 42.213 ms | +53.655 ms | +35.913 ms |

Sub-64-KiB deltas are within run-to-run noise. At 16 MiB, signing costs about
3.35 ms/MiB and verification about 2.24 ms/MiB. Signing hashes the message
twice (hedged master seed and transcript); verification hashes it once.

### Microbenchmark observations

- **Field arithmetic is no longer the main cost.** Multiplication is 0.789 µs,
  squaring 15.1 ns, inversion 18.31 µs. The 15-round Rain encryption is 0.287 ms.
- **BLAKE3 in bulk:** 1 MiB in 1.112 ms (about 900 MiB/s); 64 B in 78.7 ns;
  WH512 over 2,240 B in 4.80 µs.
- **GGM dominates:** one tree root is 178.5 µs; one root reconstruction is
  173.1 µs. Prefix states and precomputed context keys avoid rehashing constant
  per-tree data.
- **Microbenchmark floors:** add/encode/decode include loop, index, and
  `black_box` overhead.

### Build and memory

- Clean workspace release build: **5.56 s** on this host.
- `sign_into` / `verify_bytes` internal stack: **32 KiB** release; a full sign
  with the output buffer on the stack: **64 KiB**.
- Heap allocation by the library: **zero** (`no_std`, no allocator).
- Benchmark process peak RSS: **20 MiB**, driven by the 16 MiB message case.
- `vorb3-bench` ELF text: **714,724 bytes** (includes the benchmark harness and
  all protocol paths); default `vorb3.rlib` archive: **642 KiB**.

## Memory and stack

The library is `no_std`, allocates no heap, and has zero runtime
dependencies. Stack measurements from `vorb3/tests/stack.rs`:

```text
sign_into, caller-owned output, release: 32 KiB thread  PASS
verify_bytes, release:                    32 KiB thread  PASS
sign_into, output buffer on stack:       64 KiB thread  PASS
```

The 32 KiB figure covers the internal working set; a caller that places the
13,672-byte signature on the stack needs the 64 KiB case. Debug builds use a
64 KiB default because unoptimized frames are larger.

## Reproduce

```bash
./scripts/bench.sh          # raw full table -> target/benchmark-results.md
./scripts/bench.sh --quick  # raw smoke table
```

The curated report above is `docs/BENCHMARKS.md`.

## Caveats

- One machine, one compiler version, background-free but not a controlled lab.
- CPU frequency scaling and sibling hyperthread activity affect absolute numbers.
- The 1 MiB verify row contains one 29.38 ms outlier; its median is 21.83 ms and
  p95 is 21.90 ms. Use medians for comparisons.
- Microbenchmarks measure this implementation, not asymptotic complexity.
- No external audit; no constant-time or security claim follows from throughput.
