# VORB3 — Phase 0 Decision Log (ADRs)

**Status:** Draft. Items marked **pending** block the spec freeze.
**Rules:** every decision has context, choice, consequences, evidence. A change
to a frozen decision bumps the spec version and invalidates KATs.

---

## D1 — Security target

**Status:** Accepted in principle (user: highest possible; SP-128 initially).
**Choice:** 128-bit quantum / 256-bit classical floor. F-33 may require a larger
field to meet the floor honestly.
**Consequences:** all primitives sized for the floor; no rounding up.
**Evidence:** `docs/SECURITY-CASE.md`.

## D2 — Phase 0 first

**Status:** Accepted.
**Choice:** complete equations/model/wire binding before production code.
**Evidence:** user approval; this directory.

## D3 — Inversion zero case

**Status:** Accepted.
**Choice:** zero-safe selector gadget:
`b²=b, b·x=0, b·y=0, x·y=1⊕b`.
**Rejected:** cubic relation `x²y⊕x=0` alone (does not force y=0 at x=0).
**Evidence:** completeness/soundness sketch; model.

## D4 — Linear layer

**Status:** **Superseded by D15.**
The original byte-level MDS matrix is not used in SP1.

## D5 — GGM/Merkle structure

**Status:** Accepted for the equations.
**Choice:** GGM seeds = field size; Merkle leaf/node/root = 64-byte WH512;
copath = sibling seeds; root reconstruction in the verifier.
**Evidence:** model root equality; `docs/WIRE-BINDING.md`.

## D6 — Entropy

**Status:** Accepted.
**Choice:** caller-supplied fallible 32-byte entropy; no OS RNG in core; hedged
KDF; no partial output on failure.
**Evidence:** spec §5.

## D7 — Assurance boundaries

**Status:** Accepted.
**Choice:** no LFENCE claim; safe Rust limits on zeroization; Kani scope is
implementation/bounded algebra, not computational security.
**Evidence:** `docs/THREAT-MODEL.md`, `docs/ASSURANCE.md`.

## D8 — Dependency policy

**Status:** Accepted.
**Choice:** empty shipped runtime dependency graph; isolated verification tools;
fuzz crate excluded from release.
**Evidence:** later `cargo tree` proof.

## D9 — Targets

**Status:** Accepted.
**Choice:** x86_64 + aarch64 KATs; ppc64/s390x endian build; thumbv7em lib build.
**Evidence:** later G6.

## D10 — Campaign budget

**Status:** Pending machine-time confirmation.
**Choice:** 50M dudect, 1B fuzz, 72h; staged.

## D11 — License/metadata

**Status:** Pending.
**Choice:** needed for `clippy::cargo`; choose license or publish=false policy.

## D12 — Start Phase 0

**Status:** Accepted; Phase 0 in progress.

## D13 — Higher-than-Level-5 profiles

**Status:** Open. SP-160/192/256 are documented; not recommended without a
specific requirement.

## D14 — Hash construction

**Status:** Accepted for now.
**Choice:** WH512 (two independent BLAKE3-256 derivations, 64 B). SHA-512 is the
fallback if the combiner assumption is rejected.
**Evidence:** F-24/F-31; model.

## D15 — Field-linear Rain-SP1

**Status:** **Pending user approval.**
**Context:** a binary MDS matrix is GF(2)-linear, not GF(2^256)-linear; the
verifier cannot apply it to field-VOLE MAC shares, so a compact QuickSilver
proof cannot soundly treat it as free.
**Choice:** replace the binary MDS with multiplication by a public nonzero
field constant \(c_r\) per round; inversion supplies nonlinear mixing; 15+
rounds; Phase-4 cryptanalysis.
**Rejected alternatives:** bit-level proof of the binary MDS (large circuit,
separate research track); change proof system (out of scope).
**Consequences:** Rain is a new variant; original MDS not implemented in SP1.
**Evidence:** `docs/PHASE0-REPORT.md` F-25; model.

## D16 — 15 rounds / 32-tree wire layout

**Status:** **Pending user approval; F-33 may change field/tree count.**
**Choice:** zero-safe gadget uses 2 secret wires/round + sk; 15 rounds = 31
wires; one mask leaf; 32 trees. `T ≥ 2R+2`; R=15 max for 32 trees.
**Consequences:** wire_d 31 entries; mask tree 31; extra trees if field/challenge
increases.
**Evidence:** F-26/F-30; model.

## D17 — Signature layout

**Status:** **Pending approval; size depends on F-33.**
**Choice:** salt 64, h2 64, wire_d 31×field, U,V field, out_tag field,
copaths T·8·F, hidden_coms T·64.
Sizes: 11,456 B (256/32), 12,968 B (288/33), 13,672 B (288/35), 14,024 B
(288/36), 15,312 B (320/36), 16,848 B (320/40).
**Evidence:** `docs/WIRE-BINDING.md`; model.

## D18 — WH512 for commitments/transcript

**Status:** Accepted with D14.
**Choice:** salt, h2, leaf commitments, Merkle nodes/roots, pk_hash, transcript
state use WH512. GGM expansion uses one BLAKE3 derive-key with 2×seed output.

## D19 — Field polynomial

**Status:** Pending final profile.
**Choices verified locally by GP + Python Rabin:**
- 256: `x^256+x^10+x^5+x^2+1` (0x425)
- 288: `x^288+x^11+x^10+x+1` (0xC03)
- 320: `x^320+x^4+x^3+x+1` (0x1B)
**Consequences:** profile choice fixes the polynomial; Phase-0 re-verification
required.

## D20 — Selector gadget

**Status:** Accepted (equations/model).
**Choice:** `b²=b, b·x=0, b·y=0, x·y=1⊕b`.
**Evidence:** D3; model.

## D21 — Field/tree profile after F-33

**Status:** **Accepted (user, 2026-11-26): SP-288/35.**
**Context:** the 256-bit field with 60 gates is ≈125-bit quantum under the
conservative union bound; 288/35 is ≈140; 320/40 is ≈156.5.
**Selected:** **SP-288/35:** GF(2^288), 35 trees, depth 8, 15 rounds,
13,672-byte signature, ~140-bit quantum floor; public key 72 B; seed 36 B;
expanded secret 108 B; GGM seed/leaf 36 B; WH512 64 B.
**Alternatives retained:** SP-288/33 (12,968 B, ~132), SP-288/36 (14,024 B,
~140.5), SP-320/36 (15,312 B, ~144), SP-320/40 (16,848 B, ~156.5).
**Consequences:** all sizes, KATs, constants, secret seed size, public key size.
**Evidence:** `docs/SECURITY-CASE.md` F-33; model passes all options.

## F-01 — 128-bit key / 128-bit PQ claim

**Status:** Resolved by upgrade (Rain-256/320 line); exact profile pending D21.

## F-02 — VOLEitH/QuickSilver equations incomplete

**Status:** Substantially resolved by `docs/VORB3-SPEC-1.md` and the model.
**Remaining:** formal soundness/ZK proof; exact QuickSilver published bound.

## F-03 — Cubic relation zero-case

**Status:** Resolved by D3/D20.

## F-04 — GGM/Merkle size inconsistency

**Status:** Resolved by D5; seed/hash sizes are profile-dependent.

## F-05 — Maximum branch number

**Status:** Superseded by D15. The byte-MDS claim is not used; the field-linear
diffusion has a separate branch-number test.

## F-06 — Signature size contradiction

**Status:** Resolved: sizes are profile-dependent (11,456 / 14,024 / 16,848).

## F-07 — Entropy/no_std

**Status:** Resolved by D6.

## F-08 — Assurance boundaries

**Status:** Accepted by D7.

## F-09 — 24 vs 32 trees

**Status:** Resolved: T=32/36/40 by profile; Attack 7 rewritten for the chosen T.

## F-10 — Transcript schedule

**Status:** Resolved in spec §3.4/§12; model.

## F-11 — u=0 key leak

**Status:** Resolved: leaf share mapped to nonzero in constant time; commitment
binds the mapped value; force-zero test planned.

## F-12 — Degenerate keys

**Status:** Resolved: reject sk=0, pt=0, ct=0; pt=ct/low-order tested as
potentially valid.

## F-13 — Constants generation

**Status:** Resolved: deterministic KDF labels, checked-in constants, test
re-derivation, no build.rs.

## F-14 — KAT circularity

**Status:** Resolved: independent Python/py-blake3 model + official BLAKE3
vectors; KAT manifest.

## F-15 — Campaign feasibility

**Status:** Pending measurement (D10).

## F-16 — Tooling/dependencies

**Status:** Resolved by D8.

## F-17 — Uniform verification

**Status:** Resolved in spec §11.

## F-18 — Version discipline

**Status:** Accepted.

## F-19 — no_std panic handler

**Status:** Resolved: library, not binary; bare-metal `--lib` build.

## F-20 — Names/labels

**Status:** Resolved: VORB3 crate; versioned `VORB3-*` labels; no reuse.

## F-21 — Stack

**Status:** Resolved for the no-copy API. `sign_into` and `verify_bytes` each
fit a 32 KiB release thread with caller-owned output; a full `sign_into` call
with the 13,672-byte output on the stack fits 64 KiB. Debug builds use 64 KiB.
**Evidence:** `vorb3/tests/stack.rs`; `docs/PHASE1-7-REPORT.md` §8.2.

## F-22 — Rain round security

**Status:** Local cryptanalysis checkpoint; 15 rounds remains a baseline, not a
proof. Differential composition bound ≈2^-258; linear/algebraic margins open.
**Evidence:** `docs/RAIN-CRYPTANALYSIS.md`.

## F-23 — Domain label collisions

**Status:** Resolved by registry; versioning.

## F-24 — BLAKE3 chaining state

**Status:** Resolved by WH512; transcript state 512.

## F-25 — Binary MDS vs field VOLE

**Status:** Resolved by D15: field-linear Rain-SP1 replaces the binary MDS.

## F-26 — Hidden-leaf budget

**Status:** Resolved by D16/D20; `T ≥ 2R+2`.

## F-27 — Original signature fields insufficient

**Status:** Resolved by D17; new wire_d/U/V/out_tag layout.

## F-28 — Masking tuple/w*

**Status:** Resolved: mask tree 31; q* from its hidden commitment; no separate
w* field.

## F-29 — Public output tag

**Status:** Resolved: out_tag field; verifier check.

## F-30 — 15-round maximum for 32 trees

**Status:** Resolved by D16; more rounds require more trees.

## F-31 — WH512 vs BLAKE3 XOF

**Status:** Resolved by D14/D18.

## F-32 — 256-bit polynomial candidate

**Status:** Verified locally; profile pending D21.

## F-33 — 256-bit field soundness shortfall

**Status:** Resolved by D21. SP-288/35 has a conservative ≈140-bit quantum
floor; the 256-bit profile is not used for a 128-bit claim.

---

## Freeze checklist

- [x] D15 field-linear Rain-SP1 approved
- [x] D16 15 rounds/wire layout approved
- [x] D17 signature layout approved
- [x] D19 polynomial for the chosen profile re-verified (0xC03)
- [x] D21 profile selected: **SP-288/35**
- [x] Phase-0 spec version records SP-288/35
- [x] KAT digests regenerated for SP-288/35
- [ ] User signs off Phase 0

---

## D22 — Phase 7 operational caps

**Status:** Accepted for the local checkpoint.

**Context:** The original assurance plan listed a 50M dudect campaign and a
72-hour fuzz soak. At measured release speeds, 50M sign samples alone would take
about 20 days on one core; the 72-hour soak was explicitly deferred by
direction.

**Choice:**
- 32 KiB per-operation release stack cap for `sign_into` / `verify_bytes`;
  64 KiB for a full sign call with the output buffer on the stack.
- 20,000-sample randomized dudect tests for signing and verification, with
  `|t| < 4.5`; the 50M target is superseded as impractical and is not claimed.
- 1-hour fuzz checkpoint recorded; the 72-hour / 1B soak remains deferred.

**Consequences:** no “constant-time” or “fuzz-complete” claim; reports state
the measured scope. Any future release still needs the deferred soak, external
review, and the open Rain-SP1 cryptanalysis items.

**Evidence:** `vorb3/tests/stack.rs`, `tools/attack/src/main.rs`,
`docs/SIDE-CHANNEL.md`, `docs/PHASE7-ATTACK-REPORT.md`.

---

## D23 — Performance optimization checkpoint

**Status:** Accepted for the local candidate profile.

**Context:** Rain-SP1 encryption was 14.902 ms, dominated by 15 field
inversions (987.7 µs each). Signing was 34.971 ms and verification 19.176 ms;
GGM/BLAKE3 was the next bottleneck.

**Choice:**
- Specialized GF(2^288) squaring (bit spread + fixed-word reduction) and a
  Horner carry-less multiplier.
- Precomputed public WH512/GGM context keys.
- One-chunk BLAKE3 fast path.
- Per-tree streaming WH512/derive-key prefix states for GGM leaf, node, and
  expansion records.
- Three scoped `#[inline(always)]` exceptions in BLAKE3 hot paths; no unsafe,
  no dependency, and no safety/panic/cast lint weakened.

**Result:** Rain 0.287 ms (≈52×), sign 7.065 ms (≈4.95×), verify 6.333 ms
(≈3.03×), field squaring 15.1 ns (≈215×), inversion 18.31 µs (≈54×). Signature
KAT remains byte-identical; 32 KiB stack and all gates pass.

**Consequences:** GGM/BLAKE3 is now the dominant cost. Further major gains need
safe hardware CLMUL/SIMD or a protocol change; neither is taken here.

**Evidence:** `docs/OPTIMIZATIONS.md`, `docs/BENCHMARKS.md`, KAT/gates.
