# VORB3-SP1 — Security Case

**Status:** Phase 7 local implementation checkpoint (2026-11-26). **Not a proof
of computational security and not an external audit.**
**Scope:** SP-128/SP-128+/SP-160 parameter families; the equations are shared.
The implementation target is the frozen SP-288/35 profile.

---

## 1. Security target

| Property | Target |
|---|---|
| Key recovery | 128-bit quantum / 256-bit classical |
| SUF-CMA | 128-bit quantum / 256-bit classical |
| Fiat–Shamir soundness | 128-bit quantum |
| Field-check soundness | 128-bit quantum |
| Hash collision | 128-bit quantum |
| PRF/GGM | 128-bit quantum |
| Zero-knowledge | statistical, budget below |
| Side channels | Phase 3 evidence, not a theorem |

The target is a **floor**. If a component falls below it, the parameter set is
not frozen; we add field/challenge bits or rounds.

---

## 2. F-33 — the 256-bit field is short under the conservative union bound

QuickSilver's multiplication check has a field-dependent soundness error. A
conservative accounting for `G = 60` gates uses a union bound of
`G · 2 / |F|` (the exact published bound may be tighter; we do not rely on a
tighter bound until it is written and checked). The quantum cost of finding a
bad challenge is the square root of that fraction.

| Profile | Field | Trees/challenge | Field-check (classical) | Field-check (quantum) | Tree quantum | Key quantum | Overall conservative | Signature |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| SP-128 (256) | 2^256 | 32 / 256 | ≈2^-249.1 | ≈125 | 128 | 128 | **≈125** | 11,456 |
| SP-288/33 | 2^288 | 33 / 264 | ≈2^-281.1 | ≈140.5 | 132 | 144 | **≈132** | 12,968 |
| SP-288/35 | 2^288 | 35 / 280 | ≈2^-281.1 | ≈140.5 | 140 | 144 | **≈140** | 13,672 |
| SP-288/36 | 2^288 | 36 / 288 | ≈2^-281.1 | ≈140.5 | 144 | 144 | **≈140.5** | 14,024 |
| SP-320/36 | 2^320 | 36 / 288 | ≈2^-313.1 | ≈156.5 | 144 | 160 | **≈144** | 15,312 |
| SP-320/40 | 2^320 | 40 / 320 | ≈2^-313.1 | ≈156.5 | 160 | 160 | **≈156.5** | 16,848 |

Formula (D=8, 31 wires, one mask, R=15):

```
SIG = 128 + 34*F + T*(8*F + 64)
```

where `F` is field bytes and `T` trees. The copath term `T*8*F` dominates.
`T >= 2R+2 = 32`; increasing `T` increases both the tree challenge (`8T` bits)
and the signature.

Tree quantum = `4T` (Grover on `8T` challenge bits). Field quantum =
`F_bits/2 - 0.5*log2(2*60)` ≈ `F_bits/2 - 3.45`. Key quantum = `F_bits/2`.
WH512 collision ~170. The overall floor is the minimum.

The 256-bit profile therefore does **not** meet an honest 128-bit quantum
soundness claim under our conservative accounting. It is ≈125 bits. The 288-bit
profile gives ≈140 bits; the 320-bit profile gives ≈156 bits. WH512 collision
(~170) and BLAKE3 PRF are above these.

**Selected (D21, 2026-11-26): SP-288/35** (GF(2^288), 35 trees, 13,672 B,
~140-bit quantum floor). It clears 128 with a 12-bit tree and 12.5-bit field
margin, at 2.2 KB over the 256 baseline. **SP-288/33** is the smallest true-128+
profile (12,968 B, ~132-bit floor). **SP-320/40** is the maximum-margin option
(16,848 B, ~156.5). The 256-bit profile is not acceptable for a 128-bit claim.

Model results (completeness only) for all three profiles are in
`docs/PHASE0-REPORT.md`.

---

## 3. Security target per profile (after F-33)

### SP-288/35 (selected)

| Component | Classical | Quantum |
|---|---:|---:|
| Rain key recovery | 288-bit field/key | 144 |
| FS challenge / tree indices | 280-bit | 140 |
| Field checks, 60 gates | ≈281 | ≈140.5 |
| WH512 collision | 256 | ≈170 |
| WH512 preimage | 512 | 256 |
| PRF/GGM | 288-bit seed | 144 |
| Overall floor | — | **≈140** |

Signature 13,672 B; public key 72 B; compact seed 36 B; expanded secret 108 B;
GGM seed/leaf share 36 B; Merkle hash 64 B; 35 trees.

### SP-288/33 (smallest true 128+)

288-bit field, 33 trees; signature 12,968 B; tree challenge 264 bits (132
quantum); overall ≈132.

### SP-320/40 (maximum margin)

320-bit field, 40 trees; signature 16,848 B; overall ≈156.5.

### SP-288/36

288-bit field, 36 trees; signature 14,024 B; tree 144, field 140.5; overall
≈140.5.

### SP-128 (256) — development baseline only

256-bit field, 32 trees; signature 11,456 B; overall ≈125-bit quantum. It is
used in the equation model and as a regression baseline; it is **not** the
recommended production profile for a 128-bit claim.

---

## 4. Completeness argument

1. The honest prover computes `b_r = 1` iff `x_r = 0`, `y_r = 0` in that case,
   else `b_r = 0, y_r = x_r^{-1}`. The four selector equations hold.
2. The `F`-linear wires (`x_r`, `s_r`, constants, 0/1) have MAC/tag pairs derived
   from the secret wires. The relations are linear, so MACs transform correctly.
3. The gate equations hold term-by-term; the batched equation holds.
4. The mask tuple gives a valid one-time pad; the verifier's check holds.
5. The public output tag is the MAC of `ct`; the verifier checks it.

The Python model asserts every relation for toy, 256, 288, and 320 profiles.

---

## 5. Soundness sketch

### 5.1 Selector gadget

For each round:
- `b²=b` makes `b∈{0,1}`.
- If `b=1`: `b x=0 ⇒ x=0`; `b y=0 ⇒ y=0`; `x y=0=1⊕1`.
- If `b=0`: `x y=1⊕0=1 ⇒ x≠0, y=x^{-1}`.
These are exhaustive. No zero-case ambiguity remains.

### 5.2 QuickSilver gate check

For a gate `(a,b,c)`, if `c≠a·b`, then
`B ⊕ A0 ⊕ A1·δ` is a nonzero polynomial in δ of degree ≤2. For a single
gate, a cheating prover passes with probability at most 2/|F| over δ (assuming
its A0/A1 are fixed before δ; the protocol's tag/MAC binding is the standard
QuickSilver argument). Batching with χ reduces the 60 checks to one; the
conservative union bound is `60·2/|F|`; the exact published bound must be
formalized in the Phase-4/8 proof. The F-33 table uses the conservative bound.

### 5.3 Wire MAC binding

`q_i' = q_i ⊕ d_i·δ = v_i ⊕ w_i·δ`. The verifier's q_i is the first 32 (or 40)
bytes of the hidden leaf commitment; the prover's u_i is the hidden leaf share.
The VOLEitH all-but-one commitment binds the hidden leaf under the WH512
collision assumption and Fiat–Shamir. The wire opening `d_i` is a one-time pad
of `w_i` by `u_i`.

### 5.4 Output

The verifier recomputes `q_ct` from the linear wires and checks
`q_ct = out_tag ⊕ ct·δ`. A wrong public ciphertext fails with probability
1−2^-field (for a fixed tag); the prover cannot choose `out_tag` after seeing δ
because the signature is Fiat–Shamir-bound.

### 5.5 Fiat–Shamir

The prover commits the 32/36/40 roots before δ, χ, h2. The h2 check binds the
roots and the hidden indices; the challenge has 256/288/320 bits. Grinding is
2^128/2^144/2^160 quantum. The wire openings and proof are responses after h2.

### 5.6 Zero-knowledge sketch

- `d_i = u_i ⊕ w_i` is a one-time pad; `u_i` is a secret hidden-leaf share.
- `q_i' = v_i ⊕ w_i·δ` is a random MAC; `v_i` is random from the leaf.
- The witness values `sk, y_r, b_r` never appear in the signature.
- The batched `A0,A1` are masked by the independent mask leaf `(u*,v*)`:
  `U=A0⊕v*`, `V=A1⊕u*`; the verifier knows `q*=u*δ⊕v*` but not `u*,v*`.
- The public output tag is a MAC tag, not a witness value.
- A simulator can sample the verifier's q/d and the masked U/V; the detailed
  argument must be written in Phase 4/8.

This is a sketch, not a machine-checked ZK proof.

---

## 6. Assumptions

1. **Rain-SP1 security:** 15+ rounds resist key recovery/algebraic/differential/
   linear attacks at the chosen field size. This is the Phase-4 gate; 15 is a
   baseline, not a proof.
2. **BLAKE3:** random oracle/PRF with independent domain instances.
3. **WH512:** the two-instance concatenation has the generic 512-bit collision
   bound; SHA-512 is the fallback.
4. **VOLEitH/QuickSilver:** the standard all-but-one commitment and proof
   soundness/ZK hold in this instantiation; the exact equations are in the spec
   and the model.
5. **Fiat–Shamir:** sound in the random oracle model.
6. **Implementation:** constant-time and zeroization are Phase 3/7 evidence, not
   assumptions.

A failure of any assumption is a release blocker.

---

## 6.1 Implementation evidence (Phase 7)

- Signature KAT is byte-identical to the independent Python model.
- 109,376 single-bit mutations rejected; structural truncation/wrong-key/
  wrong-message/all-zero tests rejected.
- 1-hour fuzz: 207,402 executions, zero crashes; 72-hour soak deferred.
- 32 KiB per-operation release stack for `sign_into`/`verify_bytes`; 64 KiB
  full sign with the output buffer on the stack.
- Canary guard regions survive signing; no 16-byte seed fragment appears in the
  signature; explicit wipe tests cover witness and key types.
- Kani helper proofs: 6/6 (field encoding/additivity, CT equality/select,
  masked GGM selection, byte wipe); Miri CT/zeroization/profile/short BLAKE3
  pass.
- dudect/cachegrind/assembly evidence is in `docs/SIDE-CHANNEL.md` and
  `docs/PHASE7-ATTACK-REPORT.md`.
- Rain-SP1 local analysis is in `docs/RAIN-CRYPTANALYSIS.md`.

## 7. What is not proved

- Computational 128-bit security of Rain-SP1.
- Full symbolic Kani correctness/side-channel proofs for the 288-bit,
  15-round, 35-tree sign/verify (a concrete full-path harness exceeded the
  15-minute local budget).
- Constant-time execution or absolute zeroization of compiler temporaries.
- 72-hour / 1-billion-execution fuzzing.
- A machine-checked QuickSilver soundness/ZK proof for this exact circuit.
- WH512 combiner security beyond the random-oracle-style assumption.
- Side-channel immunity or absolute zeroization.
- Implementation correctness (no Rust code yet).
- External audit.

The security case is deliberately conservative. The plan is to **earn** the
claims with local cryptanalysis, Kani/reduced-model proofs, fuzzing, and
side-channel evidence; we do not round up.

---

## 8. Release rule

The project may not use the words "128-bit quantum secure" until:

1. D21 selects a profile whose conservative budget is ≥128.
2. The Phase-4 cryptanalysis gate passes.
3. The Phase-8 soundness/ZK proof inventory is complete.
4. The implementation gates G1–G7 pass.

Until then, the correct description is: **"VORB3-SP1 candidate, security target
128-bit quantum, not yet certified."**
