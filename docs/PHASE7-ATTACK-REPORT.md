# VORB3 — Phase 7 Adversarial Campaign Report

**Status:** in progress. The 1-hour fuzz run is executing; the 72-hour soak is
scheduled for a later stage as directed.
**Profile:** SP-288/35, 13,672-byte signature.
**No external audit is claimed.**

---

## 1. Completed evidence

### 1.1 Exhaustive single-bit signature sweep

Tool: `tools/attack` (`bitflip`), release build, 16 workers.

```
signature bytes: 13,672
single-bit mutations: 109,376
accepted mutations: 0
result: BITFLIP PASS
wall: 4m33.8s, user CPU: 57m25s
```

Every single-bit mutation of the KAT signature was rejected by
`verify_bytes`.

### 1.2 Structural negative tests

`vorb3/tests/attack.rs`:

- sampled bit flips across salt, h2, wire_d, U, V, out_tag, copath, hidden
  commitments;
- truncation by one byte;
- one trailing byte;
- all-zero signature;
- wrong message;
- wrong public key.

All rejected.

### 1.3 Stack

`vorb3/tests/stack.rs`:

- sign in a 64 KiB thread: PASS;
- verify in a 64 KiB thread: PASS;
- sign+verify sequentially in one 64 KiB thread: overflow.

The 64 KiB hard cap is met **per operation** in the tested configuration. The
32 KiB target is **not** met yet. The sequential inlining case is documented;
the API provides `sign_into` / `verify_bytes` for no-copy operation.

### 1.4 Constant-time hardening

- Hidden-leaf path and copath selection use masked `CtChoice` scans.
- No secret-dependent tree indexing remains in `hidden_opening`.
- Verification evaluates h2, proof batch, output tag, and mask with one uniform
  error.
- Signing wipes `master`, `u/q`, wire values, tags, `A0/A1`, mask values, and
  per-wire openings.
- `RainWitness` wipes its witness arrays on drop.

### 1.5 KAT

End-to-end signature remains byte-identical to the independent Python model:

```
SHA-256 c073c7e3f7b31192ba1932f9ed990b32bc4f321453347a23837803ef4fa9b68b
```

---

## 2. Running: 1-hour fuzzing

Command:

```bash
cd fuzz
cargo +nightly fuzz run verify -- \
  -max_total_time=3600 -jobs=16 -workers=16 -print_final_stats=1
```

Target:

- fixed KAT public key/message;
- fuzzes the 13,672-byte signature;
- treats any accepted non-KAT signature as a crash;
- isolated tooling (`libfuzzer-sys`), not a shipped dependency.

Started: 2026-11-26. Results will be appended when the run completes.

**72-hour soak:** deferred to a later stage as directed.

---

## 3. Not yet done

- dudect 50M / Welch t-test.
- cachegrind / perf instruction and cache comparison.
- assembly branch audit.
- canary memory-remanence scan.
- Kani proofs for sign/verify.
- full verification timing-uniformity measurement.
- Rain-SP1 cryptanalysis dossier.
- 72-hour fuzz soak.

---

## 4. Honest statement

The bitflip result and fuzz target establish rejection of the tested malformed
signatures. They do not prove cryptographic security. Side-channel, memory, and
cryptanalytic evidence remain required before any release claim.
