# VORB3 — Phase 0 Report

**Date:** 2026-11-26
**Status:** **Phase 0 FROZEN for SP-288/35** (D21 accepted 2026-11-26). Phase 1
(repository/toolchain/lint skeleton) starts after this freeze.
**No production crypto code written yet.**

---

## 1. What Phase 0 delivered

| Deliverable | File | Status |
|---|---|---|
| Complete protocol specification | `docs/VORB3-SPEC-1.md` | Draft for approval |
| Byte-by-byte binding table | `docs/WIRE-BINDING.md` | Draft |
| Threat model | `docs/THREAT-MODEL.md` | Draft |
| Assurance matrix | `docs/ASSURANCE.md` | Draft |
| Security case / error budget | `docs/SECURITY-CASE.md` | Draft |
| ADRs and decision log | `docs/DECISIONS.md` | Draft |
| Independent reference model | `model/vorb3_model.py` | Passing toy + full |
| Model usage/independence notes | `model/README.md` | Draft |
| Phase-0 KAT digests | this report, §5 | Recorded |

The model is an independent Python implementation using `py-blake3`; it shares no
code with the future Rust crate.

---

## 2. The three Phase-0 corrections

### 2.1 F-25 — The binary MDS layer is not compatible with a compact field-VOLE proof

The original Rain linear layer is a 256×256 binary matrix over GF(2). QuickSilver
over GF(2^256) can apply only **GF(2^256)-linear** operations to the verifier's
MAC shares for free. A binary matrix is GF(2)-linear but not GF(2^256)-linear, so
the verifier cannot apply it to its q values; a compact proof that treats it as
free would be unsound.

**Resolution:** Rain-SP1 replaces the binary MDS with a public nonzero scalar
\(c_r\) per round: \(s \leftarrow c_r \cdot y\). This is GF(2^256)-linear and
free in the proof. The inversion supplies nonlinear mixing. The cipher is a new
variant and is subject to the Phase-4 cryptanalysis gate. The original MDS
cipher is not used in SP1.

### 2.2 F-26 — Only 32 secret VOLE correlations exist

In the GGM all-but-one commitment, the verifier learns every opened leaf. Only
one hidden leaf per tree (32 total) is secret. The circuit can therefore use at
most 32 secret wires.

**Resolution:** the zero-safe inversion gadget uses only two secret wires per
round (`y_r`, `b_r`) plus `sk`:

```
b*b = b,  b*x = 0,  b*y = 0,  x*y = 1^b
```

This is sound and complete and removes the cubic-relation zero-case gap. With
**15 rounds**: 1 + 2·15 = 31 wires, plus one mask leaf = 32 hidden leaves.
The tree count is `T ≥ 2R+2`; the 32-tree baseline is the minimum, and SP-160
uses 40 trees for the larger field/challenge. This is why the baseline is
15 rounds / 32 trees.

### 2.3 F-27/F-28/F-29 — The original signature fields cannot carry the proof

The original `d`, 31×16 `w_corrections`, and 32-byte `A0/A1` do not contain the
per-wire openings or the masking verifier share for a full QuickSilver proof.

**Resolution:** the SP1 signature is profile-sized (11,456 B at 256/32;
14,024 B at 288/36; 16,848 B at 320/40):

- 31 per-wire openings `wire_d` (992 B)
- batched proof `U,V` (64 B)
- public output tag `out_tag` (32 B)
- 32 copaths (8,192 B)
- 32 hidden leaf commitments (2,048 B)
- salt/h2 (128 B)

The mask verifier share \(q^*\) is the first 32 bytes of the dedicated mask
leaf's hidden commitment (tree 31); no separate `w*` field is needed.

---

## 3. Additional Phase-0 findings

### F-30 — 15 rounds is the maximum for 32 trees; more trees allow more rounds

For `R` rounds the secret-wire count is `2R+1`; the mask adds one. With `T`
hidden leaves, `T ≥ 2R+2`. The 32-tree baseline permits `R ≤ 15`. SP1 freezes
`R=15` as the security-margin baseline; if a larger field/challenge or more
rounds is selected (D21), `T` rises and the signature version/size changes.
Rounds may never be reduced below the Level-5 target.

### F-31 — WH512, not BLAKE3-384/512 XOF

BLAKE3-256 has a 256-bit chaining state. A longer XOF output does not raise
quantum collision resistance above ~85 bits. WH512 concatenates two independent
BLAKE3-256 derivations (64 B), giving a generic 256-bit classical / ~170-bit
quantum collision bound. It is used for salt, h2, leaf commitments, Merkle
nodes, roots, public-key hash, and the 512-bit transcript state. SHA-512 remains
the fallback if the combiner assumption is rejected (D14).

### F-32 — Field polynomial candidates

Verified locally (GP + independent Python Rabin):

- 256-bit: `x^256 + x^10 + x^5 + x^2 + 1` (0x425)
- 288-bit: `x^288 + x^11 + x^10 + x + 1` (0xC03)
- 320-bit: `x^320 + x^4 + x^3 + x + 1` (0x1B)

The profile choice fixes the polynomial. Phase-0 freeze requires repeating both
tools and recording the evidence.

### F-33 — The 256-bit field is short of a 128-bit quantum soundness claim

The conservative QuickSilver field-check bound for 60 gates is `60·2/|F|`.

| Profile | Field / trees | Conservative quantum floor | Signature |
|---|---|---:|---:|
| SP-128 (256) | 2^256 / 32 | **≈125** | 11,456 B |
| SP-288/33 | 2^288 / 33 | **≈132** | 12,968 B |
| SP-288/35 | 2^288 / 35 | **≈140** | 13,672 B |
| SP-288/36 | 2^288 / 36 | **≈140.5** | 14,024 B |
| SP-320/36 | 2^320 / 36 | **≈144** | 15,312 B |
| SP-320/40 | 2^320 / 40 | **≈156.5** | 16,848 B |

The 256-bit profile is the equation baseline and a regression model, but it
must not be frozen with a 128-bit quantum claim. **D21** selects the production
profile. Recommendation for PQ 128 + usable size: **SP-288/35 (13,672 B,
~140-bit floor)**; SP-288/33 (12,968 B) is the smallest true-128+ profile;
SP-320/40 (16,848 B) is maximum margin.

---

## 4. Model validation

### Toy profile

- GF(2^32), polynomial `0x10000008D`
- 4 trees, depth 3, 1 round, 4 gates
- 456-byte signature
- Valid signature verifies; wrong message/key and sampled mutations rejected

### Full 256-bit equation baseline

- GF(2^256), polynomial `0x425`
- 32 trees, depth 8, 15 rounds
- 60 QuickSilver gates
- 11,456-byte signature
- Valid signature verifies; wrong message/key and sampled mutations rejected
- Runtime ~1.2 s for sign + verify in Python (reference, not production)

### SP-288/33, /35, /36 candidates

- GF(2^288), polynomial `0xC03`
- 33, 35, 36 trees; depth 8; 15 rounds; 60 gates
- Signatures 12,968 / 13,672 / 14,024 bytes
- Model passes valid/mutation/transplant checks

### SP-320/36 and /40 candidates

- GF(2^320), polynomial `0x1B`
- 36/40 trees; depth 8; 15 rounds; 60 gates
- Signatures 15,312 / 16,848 bytes
- Model passes valid/mutation/transplant checks

Run all with:

```
python3 model/vorb3_model.py --all
```

The model passing is evidence of **completeness and equation consistency**, not a
security proof. It does not test timing, memory, or cryptanalytic strength.

---

## 5. Phase-0 KAT digests (256-bit equation baseline; not the final profile)

These digests exercise the equations at the 256-bit profile. They are **not**
the production KAT: D21 must select the final field/tree profile first. The
model regenerates the same digests deterministically.

```
params: bits=256, poly=0x425, trees=32, depth=8, rounds=15
seed:   568c3f792883822c6a919b80ff2a6fccec97a6a38992f2e572c28dc727ff24c9
msg:    "VORB3 phase-0 self-test"
entropy: 32 zero bytes
```

Outputs:

```
pk  = 4b7beeb122ef1035a1acbdb85a8535680c92e4b393a7152f3a2f09f42e6c4de5
      73873c84aa05216ffc9a9c3e5261eac0b74d5d1865b027d14f50bbb3e372d7bd
salt = 853b32b7926406c054ca88dfa2419d68bd98a339ab3902830deaaeb973930f5f
       ea758312a2b6b35417195c436e7aaea69da3bef5e5bc823ca06498eebb02ae52
h2   = 741e62711f002bde63b748ee183de2114e123ba7ec4883710275af895deb3dc4
       18fe646e7961b2d40688676f84756e0e598abf1d710fddab79f7ef923fd0790c
roots_sha256 = 08dbc5ed0a09c95a5f63cfa60f50342ce94d161538d3213185c8ce06247566c8
sig_sha256   = 6e9eb4f5ee864a72bcaa57152af25ea6868dce5f1ac74c2148c5d5182bc94e86
sig_len      = 11456
delta = e45125f3698c8442dac48f966bbaee8592d6c3f7b95063957466ac35b4e1020a
chi   = 17b5294c4d4eb2dc3edafc6a4cd273774d05566b0681e1e553499024f5af5599
U     = 869b25ce2b7a49f5609cfed02a448282bf7b13cf34c365e926cdb8a92fec83bc
V     = 1624c1a056da9564fe8cd2b35caa5eecde757b16d37bce649fa2080bf6443b34
out_tag = 47d36af3648f2fe34537aeae4224ad05cccdea263c323bad11f91c185c4149db
```

These are regression digests, not a security proof. They will become the first
locked KAT after the spec is approved.

### 5.1 Candidate profile digests (provisional)

SP-288/35 (recommended, 288-bit, 35 trees, 13,672 B):

```
seed  = 46bc6ad6e6af38f0d15f3f1b56d8e28279cd735231de2a1ca0abb8dc122d961f
        4b415421
pk    = 6380aa2da51f709e300b6a9f004c379007e9ebdc5aa7f59269974a2045e64081
        cc761907b77d6c2570342e2e84f7d2666ce9870c1b7e9491582882e8af91f255
        239047395cdb91b7
roots_sha256 = 109605a88292ca93170d2573ba988650e2ba8fdc0dc7ef73b8b2478241b0b2c8
sig_sha256   = c073c7e3f7b31192ba1932f9ed990b32bc4f321453347a23837803ef4fa9b68b
sig_len      = 13672
```

SP-288/36 (288-bit, 36 trees, 14,024 B):

```
seed  = 35d19cb03f84bf3287d075d12625ae6a68a9479ec58abc20fd9992245c59bae5
        4b415421
pk    = c1186e77981df700fde901f6d16af3aa600d55b8e9cd1ad5c11e8a47364ef98a
        bff08dd52f7f853030bd3816ad856da270fd4621b698a488120d68343feb9488
        06ef49ce820b7621
roots_sha256 = 91b2e7411f9367cd5835606998563168d7617230eebcaf8363709d036f7a0c3d
sig_sha256   = 9363b9cb4b63e0f05f93861e425875771fd8108396b07f5b55d36a8bfb571312
sig_len      = 14024
```

SP-160 (320-bit, 40 trees, 16,848 B):

```
seed  = 66e6944bf2a8971948f94078dba8a7d5825c1be27d5bca3880ee5fd2bb5a541b
        4b41542100000000
pk    = e5273718469276403c09c48c1bad44faf899a4916dffb9c959033a162a644fdb
        12e029493dd405e3f1ab6a14c9a697917427a077a091e0cb29473689e04de58ad
        185386cc272bbe2a6d1214512d33545
roots_sha256 = aa0d00cf2946e8bfe8b7ca494ec7b0b15add52fd57ad1be2abf7b9728ea7ab29
sig_sha256   = ccaf58d72d6b5f80c3dee1bdbb8a1542d832122894d9de5021c1139966059d9b
sig_len      = 16848
```

These use the model's deterministic seeds and fixed messages; they are
regression digests for the candidate profiles, not final KATs.

---

## 6. Decisions required before freeze

| ID | Decision | Recommendation |
|---|---|---|
| D15 | Replace binary MDS with field-linear Rain-SP1 | **Yes** — required for a sound compact field-VOLE proof |
| D16 | 15 rounds / `2R+1` wire openings / mask leaf | **Yes** — maximum fitting the hidden-leaf budget; cryptanalysis may increase |
| D17 | SP1 signature layout; size depends on D21 | **Yes** — 11,456 / 12,968 / 13,672 / 14,024 / 15,312 / 16,848 B |
| D18 | WH512 for all commitment/transcript hashing | **Yes**; SHA-512 fallback D14 |
| D19 | Field polynomial for the chosen profile | **Yes**, after Phase-0 re-verification of 0x425 / 0xC03 / 0x1B |
| D20 | Zero-safe selector gadget `b*b=b, b*x=0, b*y=0, x*y=1^b` | **Yes** — model-tested completeness/soundness sketch |
| **D21** | **Field/tree profile: SP-288/35 selected; SP-288/33 smallest; SP-320/40 max; 256 is ~125** | **SP-288/35 accepted** (13,672 B, ~140-bit floor) |

If D15 is rejected, the project must either (a) implement a bit-level proof for
the binary MDS, which is a much larger circuit/signature research track, or (b)
change the proof system. There is no compact field-VOLE proof of the original
binary-MDS Rain as specified.

**F-33 consequence:** the 256-bit profile is ≈125-bit quantum under the
conservative union bound and must not be frozen with a 128-bit claim.

---

## 7. What Phase 0 did **not** prove

- Rain-SP1 security at 128-bit quantum. The 15-round baseline still requires
  the Phase-4 cryptanalysis dossier.
- VOLEitH/QuickSilver soundness in this exact instantiation. The model tests
  completeness; the security argument is a written sketch, not a machine proof.
- Side-channel resistance, zeroization, stack, or performance.
- WH512 combiner security beyond the stated assumption.
- Any external audit.

These are Phase 4–11 obligations.

---

## 8. Recommended next step

1. User approves D15–D21, especially **D21** (recommended SP-160 / 320-bit).
2. Freeze `VORB3-SPEC-1` at the selected profile (or bump to SP2 after review).
3. Start Phase 1: repository/toolchain/lint skeleton and zero-dependency proof.
4. Then Phase 2 field/CT, Phase 3 BLAKE3/WH512, Phase 4 Rain-SP1 cryptanalysis,
   Phase 5 GGM/transcript, Phase 6 sign/verify.

**No production code until the spec and D15–D21 are approved.**
