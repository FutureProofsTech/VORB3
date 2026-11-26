# VORB3 — Phase 7 Adversarial Campaign Report

**Status:** local hardening/attack checkpoint complete. The 72-hour fuzz soak is
deferred by direction and is not claimed.
**Profile:** SP-288/35, 13,672-byte signature.
**No external audit is claimed.**

---

## 1. Signature rejection

### 1.1 Exhaustive single-bit sweep

Tool: `tools/attack` (`bitflip`), release build, 16 workers.

```text
signature bytes:       13,672
single-bit mutations:  109,376
accepted mutations:    0
result:                BITFLIP PASS
final wall:            4m46s (user CPU 59m28s, 16 workers)
```

The sweep was re-run on the final release binary after the Phase 7
stack/zeroization refactor and again rejected every single-bit mutation of the
KAT signature.

### 1.2 Structural negative tests

`vorb3/tests/attack.rs`:

- sampled bit flips across salt, h2, wire_d, U, V, out_tag, copath, and hidden
  commitments;
- truncation by one byte and one trailing byte;
- all-zero signature;
- wrong message;
- wrong public key.

All rejected with `InvalidSignature` or a parse error.

### 1.3 Canary and secret-fragment scan

`signature_buffer_canary_and_secret_scan`:

- signs into a heap guard region surrounded by 256-byte `0xA5` canaries;
- verifies both canaries are unchanged after signing;
- verifies the signature is byte-identical to the KAT;
- scans the output for every 16-byte window of the 36-byte seed and the 36-byte
  expanded secret key; finds none.

This is a bounded buffer/leakage check, not a whole-memory remanence proof.

---

## 2. Stack

`vorb3/tests/stack.rs`, release profile, `VORB3_STACK_KB=32`:

```text
sign_into, heap output buffer, 32 KiB thread:   PASS
verify_bytes, 32 KiB thread:                    PASS
sign_into, output buffer on stack, 64 KiB:      PASS
```

Debug builds use a 64 KiB default because unoptimized frames are larger; the
gate explicitly runs the release 32 KiB test.

Measured changes that made the target reachable:

- BLAKE3/WH512 helpers are outlined so two 54-level CV towers are not summed
  in one frame;
- transcript absorb/squeeze/ratchet use separate frames;
- GGM root traversal is an explicit DFS stack instead of recursion;
- `Openings`/`Wires` are written in place instead of returned by value;
- `sign_into` and `verify_bytes` are outlined from callers.

The 32 KiB figure covers the library's internal working set with a caller-owned
signature buffer. A caller that places the 13,672-byte output on the stack
needs the 64 KiB case. The old sequential sign+verify-in-one-thread test is not
part of the API contract.

---

## 3. Constant-time and zeroization hardening

- Hidden-leaf path and copath selection use full-width `CtChoice` masks;
  `hidden_opening` has no branch on the hidden index.
- `nonzero` reductions for secret-derived values use CT select rather than a
  zero branch.
- Verification evaluates h2, proof batch, output tag, and mask, then returns one
  uniform `InvalidSignature` for content failures.
- Signing wipes `master`, openings, wire values, tags, `A0/A1`, mask values, and
  per-wire openings.
- `RainWitness`, `SecretKey`, and `ExpandedSecretKey` have explicit wipe methods;
  `Drop` calls them. Tests inspect the wiped fields.
- Key expansion wipes the local `sk`/`pt` byte arrays before returning.
- The GGM root pass wipes parent/child seed copies as it traverses.

Absolute zeroization of registers and compiler temporaries is not claimed; the
wipes are best-effort with `black_box` barriers.

---

## 4. Timing evidence

### 4.1 Signing

`tools/attack dudect 20000`, randomized class order, KAT key vs a second key:

```text
n = 20,000
mean class A = 34,904,530 ns
mean class B = 34,908,566 ns
Welch t = -0.494
```

### 4.2 Verification

`tools/attack dudect-verify 20000`, valid KAT signature vs one corrupted
signature:

```text
n = 20,000
mean class A = 19,183,474 ns
mean class B = 19,186,377 ns
Welch t = -0.996
```

Both campaigns are below the `|t| < 4.5` threshold. The means differ by about
0.01%, consistent with no key/signature-class timing split at this sample size.

The 50M-sample target was not run: at measured release rates it would take
about 20 days for signing alone on one core. This is a measured, reproducible
20k-sample campaign, not a claim that all microarchitectural leakage is absent.

Verification is fixed-work: the h2 check, root reconstruction, wire openings,
proof batch, output tag, and mask check are all computed before the single
accept/reject branch.

---

## 5. Cachegrind

`cachegrind --cache-sim=yes --branch-sim=yes` over `bench` (KAT key) and
`bench-other` (second valid key), release build, 10 signs + 10 verifies each:

| Metric | fixed key | other key |
|---|---:|---:|
| I refs | 7,740,065,543 | 7,740,071,064 |
| D refs | 2,114,285,317 | 2,114,290,587 |
| D1 misses | 3,876 | 9,179 |
| LLd misses | 3,005 | 3,005 |
| Branches | 138,267,114 | 138,267,128 |
| Mispredicts | 5,090,543 | 5,090,526 |

Instruction and branch counts differ by a handful out of billions; LLd misses
are identical. D1-miss counts vary more (3,876 vs 9,179), consistent with code/
data layout sensitivity; this is documented, not rounded to zero. Instrumented
wall time was ~1.86/1.83 s per sign and ~1.55/1.52 s per verify under Valgrind;
native release is ~35 ms/sign and ~19 ms/verify.

---

## 6. Assembly audit

Fresh release assembly (LTO disabled only for readable per-function output):

```text
file: 8,784 lines
hidden_opening:   339 lines, 3 conditional branches, 0 cmov, 5 calls
tree_root:        398 lines, 9 conditional branches, 2 cmov, 6 calls
verify_bytes:     701 lines, 3 conditional branches, 41 calls
sign_into:      2,670 lines, 61 conditional branches, 77 calls
mul_reduce:       331 lines, 7 conditional branches, 25 cmov
```

Manual source-to-assembly review:

- `mul_reduce` branches are fixed multiplication/reduction loop bounds; the
  reduction uses masked limb updates.
- `hidden_opening` branches are loop counters and public slice bounds; the
  hidden bit is consumed only through masked selection/shifts.
- `tree_root` branches are the public DFS stack/level/index and bounds checks.
- `verify_bytes` has only three conditional branches around fixed public
  control flow.
- `sign_into`'s 61 branches come from inlined public loops, slice bounds, key
  validation, and the public ciphertext check; the field, GGM-selection, and
  Rain paths do not branch on secret witness values.

This is a manual audit aided by `scripts/asm_audit.py`, not a formal
constant-time verifier. A compiler/ISA change requires re-running it.

---

## 7. Formal and dynamic gates

```text
cargo kani: 6/6 helper harnesses       PASS
  field encoding round-trip
  field additive identities
  CT equality vs bool
  CT select vs branch
  masked GGM selection
  wipe_bytes clears all bytes
Miri: CT, zeroization, profile, short BLAKE3  PASS
cargo test --workspace                PASS
release + thumbv7em builds            PASS
zero runtime dependencies             PASS
```

A concrete full-path Kani harness was attempted; it exceeded a 15-minute budget
and was removed. Full symbolic Kani proofs of the 288-bit, 15-round, 35-tree
sign/verify are not tractable with the local tool budget. This remains an
explicit limitation, not a passed gate.

---

## 8. Fuzzing

```text
target:            verify
workers:           16
wall:              3602 s per worker
executions:        207,402 total
crashes:           0
accepted non-KAT:  0
artifacts:         none
FUZZ_EXIT=0
```

The target fixes the KAT public key/message, fuzzes the 13,672-byte signature,
and treats any accepted non-KAT signature as a crash. Isolated `libfuzzer-sys`
tooling; not a shipped dependency.

The 72-hour / 1-billion-execution soak remains **deferred by direction**.

---

## 9. KAT

End-to-end signature remains byte-identical to the independent Python model:

```text
SHA-256 c073c7e3f7b31192ba1932f9ed990b32bc4f321453347a23837803ef4fa9b68b
length  13,672 bytes
```

---

## 10. Honest statement

The signature sweep, structural negative tests, canary scan, stack target,
cachegrind comparison, assembly review, helper Kani proofs, and 1-hour fuzz
checkpoint are complete. They do not prove cryptographic security, full
constant-time execution, or zeroization of every compiler temporary. Rain-SP1
and the full proof system remain candidate-level, and no external audit exists.
