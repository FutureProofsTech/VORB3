# VORB3 SP-288/35 — Full Project Benchmark

**Status:** local measurement checkpoint. Machine- and compiler-dependent
evidence, not a security proof and not an external audit.

This is a curated snapshot. `scripts/bench.sh` regenerates the raw table into
`target/benchmark-results.md` (or `$BENCH_OUT`); the analysis below is written
against this snapshot and is not auto-updated.

- date (UTC): `2026-11-26T21:16:08Z`
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
 657364	  10944	   1394	 669702	  a3806	target/release/vorb3-bench

size vorb3-attack:
   text	   data	    bss	    dec	    hex	filename
 414302	  11968	   1818	 428088	  68838	target/release/vorb3-attack

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
| field | add | 1.44 | 1.44 | 1.44 | 1.44 | 1.44 | 0.00 | 694,077,971 | 25 | 2000000 |
| field | mul | 3,246 | 3,245 | 3,254 | 3,241 | 3,257 | 4.19 | 308,095 | 25 | 12148 |
| field | square | 3,249 | 3,246 | 3,258 | 3,242 | 3,329 | 17.0 | 307,753 | 25 | 12368 |
| field | inverse | 988,344 | 987,693 | 988,559 | 986,083 | 1,004,265 | 3,367 | 1,012 | 25 | 40 |
| field | from_bytes | 0.87 | 0.87 | 0.89 | 0.85 | 0.89 | 0.02 | 1,145,354,723 | 25 | 2000000 |
| field | to_bytes | 0.85 | 0.84 | 0.86 | 0.84 | 0.86 | 0.01 | 1,180,556,090 | 25 | 2000000 |
| hash | blake3.empty | 95.6 | 95.5 | 95.7 | 95.3 | 97.7 | 0.47 | 10,464,408 | 25 | 335570 |
| hash | blake3.64B | 97.2 | 97.1 | 97.7 | 96.9 | 100 | 0.61 | 10,284,962 | 25 | 277970 |
| hash | blake3.1KiB | 1,134 | 1,133 | 1,137 | 1,132 | 1,155 | 4.54 | 881,657 | 25 | 33775 |
| hash | blake3.1MiB | 1,197,158 | 1,195,884 | 1,202,279 | 1,193,924 | 1,215,877 | 4,406 | 835 | 25 | 33 |
| hash | blake3_xof.64B | 98.5 | 98.5 | 98.6 | 98.3 | 98.7 | 0.10 | 10,156,249 | 25 | 288392 |
| hash | keyed_hash.64B | 97.6 | 97.5 | 97.9 | 97.3 | 99.7 | 0.45 | 10,242,900 | 25 | 365965 |
| hash | derive_key.36B | 221 | 220 | 226 | 220 | 228 | 1.75 | 4,527,447 | 25 | 167364 |
| hash | wh512.36B | 400 | 400 | 401 | 399 | 407 | 1.64 | 2,499,140 | 25 | 99181 |
| hash | wh512.2240B | 5,342 | 5,337 | 5,352 | 5,332 | 5,439 | 20.6 | 187,191 | 25 | 7480 |
| rain | constants_derive | 6,913 | 6,903 | 6,928 | 6,895 | 7,091 | 37.9 | 144,648 | 25 | 4890 |
| rain | encrypt | 14,907,535 | 14,901,783 | 14,963,887 | 14,844,342 | 14,989,542 | 35,580 | 67 | 25 | 2 |
| ggm | tree_root.1 | 526,851 | 526,823 | 528,891 | 525,063 | 528,988 | 890 | 1,898 | 25 | 75 |
| ggm | hidden_opening.1 | 4,532 | 4,529 | 4,538 | 4,521 | 4,602 | 15.1 | 220,641 | 25 | 8830 |
| ggm | reconstruct_root.1 | 521,603 | 521,365 | 522,658 | 520,917 | 523,397 | 632 | 1,917 | 25 | 77 |
| ggm | roots.35 | 18,538,541 | 18,526,949 | 18,585,726 | 18,467,168 | 18,665,385 | 40,563 | 54 | 25 | 2 |
| ggm | openings.35 | 166,972 | 166,965 | 167,333 | 166,432 | 167,597 | 280 | 5,989 | 25 | 238 |
| ggm | reconstruct_roots.35 | 18,255,243 | 18,220,625 | 18,423,047 | 18,185,205 | 18,665,533 | 101,228 | 55 | 25 | 2 |
| transcript | challenges.32B | 12,217 | 12,207 | 12,277 | 12,183 | 12,307 | 30.5 | 81,853 | 25 | 3183 |
| transcript | challenges.1MiB | 2,410,137 | 2,411,339 | 2,418,074 | 2,377,302 | 2,426,673 | 8,147 | 415 | 25 | 16 |
| sign-phase | master_seed.32B | 362 | 362 | 364 | 362 | 367 | 1.10 | 2,759,423 | 25 | 104085 |
| sign-phase | master_seed.1MiB | 1,199,389 | 1,199,431 | 1,203,588 | 1,197,329 | 1,204,988 | 1,904 | 834 | 25 | 33 |
| sign-phase | salt | 403 | 403 | 404 | 402 | 404 | 0.45 | 2,483,561 | 25 | 92850 |
| sign-phase | pk_hash | 526 | 526 | 526 | 525 | 526 | 0.37 | 1,902,420 | 25 | 73556 |
| sign-phase | wires.31 | 100,647 | 100,623 | 100,783 | 100,575 | 100,867 | 72.5 | 9,936 | 25 | 395 |
| quicksilver | prove.60gates | 1,222,198 | 1,220,898 | 1,224,869 | 1,218,260 | 1,249,549 | 5,992 | 818 | 25 | 32 |
| quicksilver | opened_wires.31 | 100,683 | 100,649 | 101,101 | 100,475 | 101,463 | 202 | 9,932 | 25 | 398 |
| quicksilver | check_proof.60gates | 792,783 | 792,835 | 793,637 | 791,441 | 794,383 | 599 | 1,261 | 25 | 50 |
| keys | secret_key_wrap | 1.71 | 1.71 | 1.72 | 1.71 | 1.72 | 0.00 | 583,302,082 | 25 | 2000000 |
| keys | expand | 449 | 449 | 450 | 448 | 451 | 0.50 | 2,226,766 | 25 | 83682 |
| keys | public_key | 14,888,466 | 14,886,097 | 14,915,013 | 14,853,681 | 14,958,949 | 20,172 | 67 | 25 | 2 |
| keys | keygen_full | 14,876,524 | 14,875,887 | 14,889,920 | 14,839,835 | 14,915,430 | 13,069 | 67 | 25 | 2 |
| parse | public_key.72B | 12.0 | 12.0 | 12.1 | 12.0 | 12.1 | 0.01 | 83,171,404 | 25 | 2000000 |
| parse | signature.13672B | 165 | 165 | 165 | 165 | 165 | 0.13 | 6,074,078 | 25 | 184586 |
| full | sign.0B | 34,984,530 | 34,985,429 | 35,149,242 | 34,839,890 | 35,196,583 | 85,553 | 29 | 25 | 1 |
| full | verify.0B | 19,231,535 | 19,138,017 | 19,940,349 | 19,098,626 | 20,340,165 | 287,837 | 52 | 25 | 2 |
| full | sign.32B | 35,115,739 | 34,971,320 | 36,067,774 | 34,868,920 | 36,571,834 | 391,304 | 28 | 25 | 1 |
| full | verify.32B | 19,193,173 | 19,176,278 | 19,358,600 | 19,092,111 | 19,411,041 | 73,442 | 52 | 25 | 2 |
| full | sign.1KiB | 35,006,648 | 34,934,901 | 35,248,439 | 34,838,035 | 36,398,836 | 301,554 | 29 | 25 | 1 |
| full | verify.1KiB | 19,189,628 | 19,166,968 | 19,342,209 | 19,117,310 | 19,365,660 | 62,865 | 52 | 25 | 2 |
| full | sign.64KiB | 35,158,128 | 35,155,754 | 35,210,973 | 35,069,560 | 35,212,814 | 32,696 | 28 | 25 | 1 |
| full | verify.64KiB | 19,321,358 | 19,297,645 | 19,355,576 | 19,238,250 | 19,852,700 | 114,771 | 52 | 25 | 2 |
| full | sign.1MiB | 38,818,372 | 38,625,613 | 40,136,583 | 38,466,601 | 40,659,078 | 577,867 | 26 | 25 | 1 |
| full | verify.1MiB | 21,594,029 | 21,582,004 | 21,735,854 | 21,483,546 | 21,740,475 | 62,595 | 46 | 25 | 1 |
| full | sign.16MiB | 92,630,786 | 92,528,748 | 93,039,960 | 92,329,337 | 93,578,155 | 282,374 | 11 | 25 | 1 |
| full | verify.16MiB | 57,947,349 | 57,891,472 | 58,466,729 | 57,494,260 | 59,206,896 | 398,043 | 17 | 25 | 1 |
| full | sign_wrapper.32B | 35,187,111 | 35,202,588 | 35,414,552 | 34,887,194 | 35,434,629 | 160,836 | 28 | 25 | 1 |
| full | verify_wrapper.32B | 19,145,282 | 19,161,851 | 19,204,689 | 18,663,375 | 19,213,996 | 103,398 | 52 | 25 | 2 |
| full | sign_verify.32B | 54,056,791 | 54,063,996 | 54,185,593 | 53,572,565 | 54,287,584 | 129,544 | 18 | 25 | 1 |

Max RSS: 20 MiB

## Analysis

All headline numbers use medians from the table above. Throughput is the
reciprocal of the headline latency.

### Headline

| Operation | Median latency | Throughput |
|---|---:|---:|
| Key generation (`keygen_full`) | 14.876 ms | 67.2/s |
| Sign, 32-byte KAT message | 34.971 ms | 28.6/s |
| Verify, 32-byte KAT message | 19.176 ms | 52.1/s |
| Sign + verify pair | 54.064 ms | 18.5/s |
| Rain-SP1 encryption | 14.902 ms | 67.1/s |
| GGM root pass, 35 trees | 18.527 ms | 54.0/s |
| QuickSilver prove, 60 gates | 1.221 ms | 819/s |
| QuickSilver check, 60 gates | 0.793 ms | 1,261/s |

The signature is 13,672 bytes, the public key is 72 bytes, and the compact
secret seed is 36 bytes.

### Where signing time goes

| Phase | Median | Share of sign |
|---|---:|---:|
| Rain-SP1 encryption | 14.902 ms | 42.6% |
| 35-tree GGM root pass | 18.527 ms | 53.0% |
| QuickSilver prover | 1.221 ms | 3.5% |
| Wire/tag construction | 0.101 ms | 0.29% |
| 35 hidden openings + copath writes | 0.167 ms | 0.48% |
| Transcript (4 absorb + 3 squeeze) | 0.012 ms | 0.035% |
| Master seed, salt, public-key hash | 0.001 ms | <0.01% |

The phase sum is about 34.93 ms, consistent with the measured 34.97 ms sign.
The 35-tree root pass and Rain-SP1 dominate; QuickSilver is a few percent.

### Where verification time goes

| Phase | Median | Share of verify |
|---|---:|---:|
| 35-tree root reconstruction | 18.221 ms | 95.0% |
| QuickSilver verifier | 0.793 ms | 4.1% |
| Wire openings | 0.101 ms | 0.53% |
| Transcript | 0.012 ms | 0.06% |
| Rain constants | 0.007 ms | 0.04% |

Verification is GGM/Merkle reconstruction plus hashing; the proof check is
small. This is also why verification is about 1.82× faster than signing.

### Message-size scaling

| Message | Sign median | Verify median | Sign Δ vs 0 B | Verify Δ vs 0 B |
|---:|---:|---:|---:|---:|
| 0 B | 34.985 ms | 19.138 ms | — | — |
| 32 B | 34.971 ms | 19.176 ms | -0.014 ms | +0.038 ms |
| 1 KiB | 34.935 ms | 19.167 ms | -0.051 ms | +0.029 ms |
| 64 KiB | 35.156 ms | 19.298 ms | +0.170 ms | +0.160 ms |
| 1 MiB | 38.626 ms | 21.582 ms | +3.640 ms | +2.444 ms |
| 16 MiB | 92.529 ms | 57.891 ms | +57.543 ms | +38.753 ms |

Sub-64-KiB deltas are within run-to-run noise; the 1 KiB sign delta is not a
real speedup. Above roughly 64 KiB the message hash becomes visible. At 16 MiB,
signing costs about 3.60 ms/MiB and verification about 2.42 ms/MiB. Signing
hashes the message twice (hedged master seed and transcript); verification
hashes it once.

### Microbenchmark observations

- **Field arithmetic is the main cost center.** Constant-time carry-less
  multiplication is about 3.25 µs, squaring about the same, and inversion about
  0.988 ms. The 15-round Rain encryption is 14.9 ms, essentially 15 inversions
  plus linear work. A faster constant-time multiplier/reduction would move the
  whole profile, but is an optimization project with its own side-channel
  review; this report does not change the implementation.
- **BLAKE3 is fast in bulk but not free at protocol scale.** A 1 MiB hash is
  1.197 ms (about 836 MiB/s); one 64-byte hash is about 97 ns. A WH512 over
  2,240 bytes is 5.34 µs. The 35-tree root pass performs 35 × 511 node hashes.
- **GGM dominates both operations.** One tree root is 526.8 µs; one root
  reconstruction is 521.4 µs. The 35-tree passes are 18.5 ms and 18.2 ms.
- **Microbenchmark floors.** The add/encode/decode entries include loop,
  index, and `black_box` overhead; treat them as upper bounds on the raw
  operation, not exact gate counts.

### Build and memory

- Clean workspace release build: **4.80 s** on this host.
- `sign_into` / `verify_bytes` internal stack: **32 KiB** release; a full sign
  with the output buffer on the stack: **64 KiB**.
- Heap allocation by the library: **zero** (`no_std`, no allocator).
- Benchmark process peak RSS: **20 MiB**, driven by the 16 MiB message case.
- `vorb3-bench` ELF text: **657,364 bytes** (includes the benchmark harness and
  all protocol paths); `vorb3.rlib` archive: **391 KiB** for the default
  library build without `bench-api`.

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
