# VORB3 SP-288/35 — Optimization Report

**Status:** local optimization checkpoint (2026-11-27).
**Constraints:** safe Rust (`forbid(unsafe_code)`), `no_std`, no heap, no
third-party runtime dependencies, fixed-iteration/constant-time discipline.
**Baseline:** commit `253f7ac` benchmark snapshot.
**Result:** Rain-SP1 encryption **14.902 ms → 0.287 ms (≈52×)**; full sign
**34.971 ms → 7.065 ms (≈4.95×)**; verify **19.176 ms → 6.333 ms (≈3.03×)**.
All KATs remain byte-identical.

---

## 1. Headline

| Operation | Before | After | Speedup |
|---|---:|---:|---:|
| Rain-SP1 encryption | 14.902 ms | **0.287 ms** | **≈52×** |
| Key generation | 14.876 ms | **0.294 ms** | **≈50.6×** |
| Sign, 32 B | 34.971 ms | **7.065 ms** | **≈4.95×** |
| Verify, 32 B | 19.176 ms | **6.333 ms** | **≈3.03×** |
| Sign + verify | 54.064 ms | **13.289 ms** | **≈4.07×** |
| GGM root pass, 35 trees | 18.527 ms | **6.256 ms** | **≈2.96×** |
| Field multiplication | 3.245 µs | **0.789 µs** | **≈4.1×** |
| Field squaring | 3.245 µs | **15.1 ns** | **≈215×** |
| Field inversion | 987.7 µs | **18.31 µs** | **≈54×** |
| QuickSilver prove | 1.221 ms | **0.296 ms** | **≈4.1×** |
| QuickSilver check | 0.793 ms | **0.192 ms** | **≈4.1×** |

Rain-SP1 is no longer a sign-time bottleneck: it is now about 4% of signing.
GGM/BLAKE3 is now the dominant cost (~89% of signing, ~96% of verification).

## 2. Changes

### 2.1 Specialized field squaring

Squaring in characteristic two is linear: coefficient bits move to even
positions. `spread64` interleaves each 64-bit limb into 128 bits, producing the
576-bit product without 25 carry-less multiplications. A fixed five-word
reduction then reduces the product. Measured: **3.245 µs → 15.1 ns**.

### 2.2 Horner carry-less multiplication

The previous 64x64 carry-less loop shifted a 128-bit accumulator by a variable
bit index per iteration. The new Horner form reverses the multiplier bits,
shifts the accumulator by one, and XORs a masked left word:

```text
result = (result << 1) XOR (left & mask(bit))
```

Fixed 64 iterations; no secret branch. Measured: **3.245 µs → 0.789 µs** for a
full 5-limb multiplication.

### 2.3 Fixed-word reduction

The old reduction walked 287 high bits, one at a time. The new reduction
processes high 64-bit words 8 down to 4 with a fixed sequence of shifted XORs,
including feedback from word 8 into word 4 before word 4 is reduced. This is
data-independent control flow and preserves the exact field polynomial.

### 2.4 Precomputed WH512 / GGM context keys

BLAKE3 derive-key context keys are public constants. The A/B WH512 keys and
GGM expand/tree-root keys are now precomputed constants instead of being
re-derived on every hash. This removed two context hashes per WH512 and one per
GGM expansion. KATs verify the exact bytes.

### 2.5 One-chunk BLAKE3 fast path

All GGM leaf, node, and expansion inputs are under one BLAKE3 chunk. The
one-shot hash path now uses `ChunkState` directly and skips construction /
zeroing of the 54-level chaining-value tower. Large inputs still use the
streaming tree hasher.

### 2.6 GGM prefix states

GGM leaf, node, and expansion records share a constant per-tree prefix
(`label || salt || pk_hash || tree_index`). `Wh512Prefix` and
`DeriveKeyPrefix` hash that prefix once per tree, then clone the BLAKE3 chunk
state and append only the variable suffix. BLAKE3 output is byte-identical to
the one-shot hash; a dedicated prefix/full-hash test and the end-to-end KAT
cover it.

### 2.7 Scoped inlining

BLAKE3 `compress`, `hash_internal`, and `root_bytes` are marked
`#[inline(always)]` with a scoped `#[allow(clippy::inline_always)]`. This is the
only code-standard exception added for speed; it measured about 8% on GGM and
sign. No safety, panic, cast, dependency, or `unsafe` lint is weakened.

## 3. Correctness evidence

- End-to-end signature KAT is unchanged:
  `c073c7e3f7b31192ba1932f9ed990b32bc4f321453347a23837803ef4fa9b68b`.
- 512 independent field differential vectors pass.
- 2,000-value inverse self-consistency pass.
- WH512 prefix/full-hash equality test passes for split points 0..400.
- All unit/integration tests pass under default and each profile feature set
  (`nist1,bench-api`, `nist3,bench-api`); `nist1` and `nist3` are mutually exclusive.
- 32 KiB release stack test still passes for sign and verify.

## 4. Constant-time review

- Field multiplication/squaring/reduction use fixed iteration counts and
  data-independent branches. No secret index is used.
- Precomputed keys and constants are public.
- Prefix states clone secret-dependent hash state, but all loop lengths and
  branch decisions are determined by public lengths/indices.
- No new `unsafe`, heap allocation, or third-party dependency.
- The inline exception does not change control flow.

The side-channel campaign was re-run on the optimized binary: dudect sign
t=-0.251 and verify t=-0.266 (20k samples); cachegrind instruction/branch counts
are near-identical across keys; the assembly audit found only public control
branches. Performance numbers are still not a constant-time proof.

## 5. Remaining bottleneck

Signing is now ~89% GGM/BLAKE3 and verification ~96% GGM/BLAKE3. Further major
gains would require one of:

- a safe hardware CLMUL path (currently blocked by `forbid(unsafe_code)`);
- SIMD/2-way BLAKE3 (stable safe SIMD is not available in this toolchain);
- a protocol change reducing WH512/node count (not allowed under the frozen
  SP-288/35 profile).

The current implementation is the local safe-Rust ceiling without changing the
profile or weakening the safety doctrine.

## 6. Reproduce

```bash
./scripts/bench.sh
python3 scripts/asm_audit.py
./scripts/gate.sh
./scripts/gate-deep.sh
./scripts/coverage.sh
```

Benchmark snapshot: `docs/BENCHMARKS.md`. Coverage: `docs/COVERAGE.md`.
