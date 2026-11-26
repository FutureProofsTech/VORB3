# VORB3 — Phase 1–7 Checkpoint

**Date:** 2026-11-26
**Profile:** **SP-288/35 frozen** — GF(2^288), 35 trees, depth 8, 15 rounds,
13,672-byte signature.
**Status:** implementation complete at the local checkpoint; Phase 7 adversarial
campaign and hardening evidence are recorded here. This is **not** a release
certificate and **no external audit is claimed**.

The end-to-end signature KAT is byte-identical to the independent Python model:

```text
SHA-256 c073c7e3f7b31192ba1932f9ed990b32bc4f321453347a23837803ef4fa9b68b
```

---

## 1. Phase 0 freeze

D21 = **SP-288/35** accepted. Frozen sources:

- `docs/VORB3-SPEC-1.md`
- `docs/WIRE-BINDING.md`
- `docs/SECURITY-CASE.md`
- `docs/DECISIONS.md`
- `model/vorb3_model.py` (`SP288_35`)

Signature layout:

| Offset | Length | Field |
|---:|---:|---|
| 0 | 64 | salt |
| 64 | 64 | h2 |
| 128 | 1,116 | wire_d (31×36) |
| 1,244 | 36 | U |
| 1,280 | 36 | V |
| 1,316 | 36 | out_tag |
| 1,352 | 10,080 | copaths (35×8×36) |
| 11,432 | 2,240 | hidden_coms (35×64) |
| 13,672 | — | end |

## 2. Phase 1 gate

- Workspace `Cargo.toml`, `rust-toolchain.toml`, `rustfmt.toml`, `.gitignore`.
- `vorb3/` `no_std` crate with frozen constants.
- `scripts/gate.sh`, `scripts/check-no-deps.sh`.
- Explicit lints in `vorb3/src/lib.rs`: `forbid(unsafe_code)`,
  `clippy::all/pedantic/nursery/cargo`, core isolation, no panic/unwrap/indexing,
  no `as` casts, no float arithmetic, `missing_inline_in_public_items`, and
  `exhaustive_structs`.

The shipped dependency graph is only `vorb3 v0.1.0`.

## 3. Phase 2 — field/CT foundation

`vorb3/src/ct.rs` provides `CtChoice` masks, constant-time equality/zero tests,
and masked selection with `black_box` barriers.

`vorb3/src/field.rs` implements GF(2^288) modulo
`x^288 + x^11 + x^10 + x + 1`:

- 36-byte canonical encoding, fixed-iteration carry-less multiplication;
- masked bitwise reduction, XOR addition/subtraction, squaring;
- Itoh–Tsujii inversion with fixed squarings and `0^-1 = 0`;
- constant-time zero/equality internals; the public `is_zero`/`PartialEq`
  declassify a bit by design;
- `zeroize.rs`: `fill(0)` plus `black_box` wipes.

Evidence:

```text
kat/field_sp288_diff.bin: 512 independent Python-model records  PASS
inverse self-consistency: 2,000 values                         PASS
cargo kani: encoding/additive/CT helpers                       PASS
Miri: CT and zeroization units                                 PASS
```

## 4. Phase 3 — BLAKE3/WH512

`vorb3/src/blake3.rs` is a from-scratch `no_std`, no-allocation BLAKE3:
streaming hash, keyed hash, derive-key, XOF, and WH512. WH512 is two independent
BLAKE3 derive-key outputs with A/B domain contexts, concatenated to 64 bytes.

Tests cover empty, `abc`, a 1024-byte chunk, a 3000-byte multi-chunk tree, keyed
hash, derive-key, XOF prefix, and the WH512 A/B construction. Kani/Miri pass.

## 5. Phase 4 — Rain-SP1

`vorb3/src/rain.rs` implements the 15-round field-linear cipher, deterministic
nonzero constants from BLAKE3 derive-key, and the zero-safe selector witness:

```text
b*b = b,  b*x = 0,  b*y = 0,  x*y = 1 XOR b
```

The cipher KAT matches the Python model, including a forced zero-state selector
test. Cryptanalysis evidence is in `docs/RAIN-CRYPTANALYSIS.md`.

## 6. Phase 5 — GGM/Merkle/transcript

`vorb3/src/ggm.rs` implements 256-leaf GGM trees, 64-byte leaf/node
commitments, copath extraction, and Merkle-root reconstruction from the hidden
commitment and copath.

Phase 7 removed the full-tree build:

- `tree_root` is a streaming left-to-right Merkle pass with a 9-slot hash stack
  and an explicit DFS node stack;
- `hidden_opening` follows the secret path with masked child/sibling selection;
- `reconstruct_root` / `subtree_hash` rebuild the root from public data.

`vorb3/src/transcript.rs` is a 512-bit framed/ratcheted transcript over WH512.
KATs cover a full tree (root, share, commitment, eight copath seeds,
reconstruction) and DELTA/CHI/H2.

## 7. Phase 6 — keys/proof/sign/verify

- `vorb3/src/keys.rs`: compact seed, expanded key, public key validation, and
  zeroizing drops.
- `vorb3/src/signature.rs`: fixed 13,672-byte type.
- `vorb3/src/sign.rs`: 35-tree root pass, transcript, 31 wire openings,
  Rain-SP1 witness, 60 QuickSilver gates, mask `U/V`, output tag,
  `sign`/`sign_into` and `verify`/`verify_bytes`.
- The Rust signature is byte-identical to the Python model.

## 8. Phase 7 — hardening and adversarial campaign

### 8.1 Constant-time and fixed-work behavior

- Hidden-leaf path and copath selection use `CtChoice` masks; `hidden_opening`
  contains no branch on the hidden index.
- `nonzero` reductions for secret-derived values use CT select rather than a
  zero branch.
- Verification evaluates h2, proof batch, output tag, and mask, then returns one
  uniform `InvalidSignature` for content failures.
- Signing wipes `master`, openings, wire values, tags, `A0/A1`, mask values, and
  per-wire openings. `RainWitness` has an explicit `wipe` method used by `Drop`.
- `Wires`/`Openings` are passed in place, avoiding large return temporaries.
- The GGM root pass uses an explicit DFS stack instead of recursion.

### 8.2 Stack

`vorb3/tests/stack.rs`:

- **sign internal working set: 32 KiB release** (output buffer caller-owned,
  test uses a heap buffer);
- **verify: 32 KiB release**;
- **sign with the 13,672-byte output buffer on the stack: 64 KiB**;
- debug builds use a 64 KiB default because unoptimized frames are larger.

The gate runs the release 32 KiB test explicitly. The earlier 64 KiB
sign+verify-in-one-thread failure is no longer part of the target: the API is
per-operation, and `sign_into`/`verify_bytes` do not require a combined frame.

### 8.3 Signature rejection

- Exhaustive single-bit sweep: 13,672 bytes × 8 = **109,376 mutations**, zero
  accepted.
- Sampled mutations across salt, h2, wire_d, U, V, out_tag, copath, and hidden
  commitments.
- Truncation, trailing byte, all-zero signature, wrong message, wrong public
  key: rejected.
- Canary test: 256-byte guard regions around the output buffer survive signing;
  no 16-byte fragment of the seed appears in the signature.
- 1-hour libFuzzer campaign: 16 workers, 207,402 executions, zero crashes.
- 72-hour/1-billion-execution soak: **deferred by direction**.

### 8.4 Side-channel evidence

- dudect-style signing and verification campaigns with randomized class order.
- cachegrind instruction/cache/branch comparison for two keys.
- full latency/throughput/memory/build measurements in `docs/BENCHMARKS.md`
  (`scripts/bench.sh`).
- release assembly audit with `scripts/asm_audit.py`.

Measured numbers and limitations are in `docs/PHASE7-ATTACK-REPORT.md` and
`docs/SIDE-CHANNEL.md`. These are evidence, not a formal constant-time proof.

### 8.5 Formal and dynamic tools

```text
cargo kani: 6/6 harnesses                 PASS
  field encoding/additive/CT helpers
  masked GGM selection
  wipe_bytes
Miri: CT, zeroization, profile, short BLAKE3 PASS
cargo test --workspace                    PASS
release + thumbv7em builds                PASS
zero runtime dependencies                 PASS
```

A concrete full-path Kani harness was also attempted; it exceeded a 15-minute
budget and was removed. Full symbolic Kani proofs of the complete 288-bit,
15-round, 35-tree `sign`/`verify` are therefore not tractable with the local
tool budget. They remain an explicit limitation; the implementation relies on
KATs, Miri, fuzzing, differential tests, and the helper proofs above.

## 9. Reproduce

```bash
./scripts/gate.sh
./scripts/gate-deep.sh
./scripts/gate.sh                 # after any change
./target/release/vorb3-attack bitflip
./target/release/vorb3-attack dudect 20000
./target/release/vorb3-attack dudect-verify 20000
python3 scripts/rain_analysis.py
python3 scripts/rain_theory.py
python3 scripts/asm_audit.py
```

## 10. Remaining limitations

- No external audit or certification.
- No full symbolic Kani proof for `sign`/`verify`.
- dudect/cachegrind/assembly evidence is local and machine-dependent; it is not
  a proof of constant-time execution.
- Rain-SP1 has a conservative 15-round differential bound and local sampling,
  but not a full cryptanalytic proof; linear/algebraic margins remain assumed.
- 72-hour / 1-billion-execution fuzz soak is deferred.
- Absolute zeroization of registers/compiler temporaries cannot be proved in
  safe Rust; the wipes are best-effort with `black_box` barriers.
- Cross-architecture KATs, reproducible-build comparison, coverage/mutation
  scores, and external review are still open release gates.

## 11. Honest statement

The implementation is functionally complete, locally exercised, and
byte-identical to the independent model. The 32 KiB per-operation stack target
and the 109,376-bit signature sweep are met. The security case is still a
**candidate** case: Rain-SP1, side-channel immunity, and the full proof system
are not proved, and no external audit exists.
