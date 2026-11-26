# VORB3-SP1 — Phase-0 Red-Team Review

**Status:** Draft. This is an internal adversarial review, not an external audit.
**Target:** `docs/VORB3-SPEC-1.md`, `model/vorb3_model.py`.
**Rule:** an attack that cannot be ruled out is an open finding, not a footnote.

---

## 1. Attack surface map

| Surface | Adversary control | Phase-0 evidence |
|---|---|---|
| Field arithmetic | public values, malformed lengths | model + future Kani |
| Rain-SP1 rounds | chosen pt/sk, algebraic attempts | cryptanalysis pending |
| Selector gadget | zero states, b witness | model + soundness sketch |
| GGM/Merkle | copath/hidden commitments, indices | model root equality |
| VOLE MACs | d, U, V, tags | model equations |
| Transcript | salt, h2, roots, message | model + schedule |
| Wire opening | d_i, wire map | model MAC assertions |
| Public output | ct, out_tag | model check |
| Entropy | all-zero/frozen | model zero-entropy run |
| API | lengths, degenerate keys | spec + future tests |

---

## 2. Selector gadget attacks

### A1 — Force `x=0` and choose arbitrary `y`

**Attempt:** set `b=0` at `x=0`, choose `y` to satisfy `x*y=1`? Impossible.
Set `b=1`, `x=0`, `y=0` is forced by `b*y=0`. If `b=1` and `x≠0`, `b*x=0`
fails. If `b=0` and `x=0`, `x*y=1` fails. No branch remains.

**Result:** the four equations are exhaustive. The only solutions are
`(x=0,b=1,y=0)` and `(x≠0,b=0,y=x^{-1})`.

### A2 — Non-boolean `b`

`b²=b` over a field has only 0 and 1. No other solution.

### A3 — Leak whether `x=0` through `b`

`b` is a secret wire, masked by a hidden leaf; the proof does not reveal it.
The model hides it; the ZK argument is a sketch. Future ZK proof/Kani must
confirm no b-dependent leakage in the batched proof.

---

## 3. VOLEitH hidden-leaf attacks

### A4 — Use a different `u` than the committed leaf

The verifier knows `q = com[0:field]` for the hidden leaf but not `u`. The
prover computes `v = q ⊕ u·δ`. If the prover uses `u' ≠ u`, the MAC relation is
still algebraically valid for `u'`; the verifier cannot tell from `q` alone.

**Why this is not automatically a break:** the prover chooses the tree and all
leaves before δ; the all-but-one commitment binds the tree through the Merkle
root and h2. The QuickSilver extractor can use the prover's `u'`; the proof is
for the witness masked by `u'`. The commitment must still bind the **tree** and
the hidden leaf commitment; the security case must formalize that using the
hidden leaf as the prover's VOLE share is sound in the VOLEitH instantiation.

**Open:** a full reduction for this exact leaf-commitment construction. This is
a Phase-4/8 obligation, not assumed away.

### A5 — Choose a hidden leaf with `u=0`

If `u=0`, `d = w`, leaking the wire. The spec maps `u=0` to 1 in constant time;
the commitment binds the mapped value. `u=0` occurs with probability 2^-field.
The model uses `gf_nonzero`; a force-zero test is required in Rust.

### A6 — Reuse a hidden leaf for two wires

The wire map assigns one tree per wire; the mask tree is separate. The model
enforces the mapping. Reuse would leak linear relations and is forbidden by the
spec; a Rust test must reject/never construct it.

### A7 — Inconsistent hidden commitment / root

The verifier reconstructs the Merkle root from the hidden com and copath. The
root and h2 bind the full 64-byte commitment. A changed com changes the root;
the h2 check fails. The model rejects sampled mutations.

### A8 — Opened-leaf disclosure

The verifier learns all opened leaves. The prover must not use opened leaves for
secret wires. The spec uses only hidden leaves 0..30 for the 31 wires and tree 31
for the mask. A Rust test must assert the mapping.

---

## 4. Fiat–Shamir / transcript attacks

### A9 — Grind h2

The prover can try many signatures to get favorable indices; the challenge is
256/288/320 bits. Grinding is 2^128/2^144/2^160 quantum. The h2 is checked in
full; the indices are bytes of h2. No known shortcut.

### A10 — h2 index bias

For depth 8, `h2[j]` is a uniform byte. For toy profiles with depth <8 the model
masks, causing a bias; toy is not production. The production profile uses depth
8, so no mask/bias.

### A11 — Transcript collision / 256-bit ratchet

WH512 gives a 512-bit state; the ratchet and h2 are 64 bytes. A 256-bit ratchet
would cap collision security at ~85-bit quantum; it is not used. The model uses
WH512 for state/ratchet.

### A12 — Cross-protocol replay

Every absorb is length-framed and labelled; labels are unique. The h2/domain
tests must include replaying h1 commitments into h2 and swapping salt/pk/msg.
The model's transcript labels are fixed; future tests must attempt collisions.

### A13 — Proof responses absorbed before h2?

`wire_d`, `U,V`, `out_tag` are responses after h2 and are not absorbed before
h2. This is standard FS; the verifier checks them. No circular h2 dependency.

---

## 5. Mask tuple attacks

### A14 — Recover A0/A1 from U,V

`U=A0⊕v*`, `V=A1⊕u*`, and `q*=u*δ⊕v*`. The verifier knows `q*,δ,U,V` but not
`u*,v*`; it has three equations in four unknowns (A0,A1,u*,v*), so it cannot
solve for A0/A1. The mask leaf is unused elsewhere. Model passes.

### A15 — Reuse the mask leaf

The mask tree is tree 31 and is not a wire. Reuse across signatures is safe
because each signature has a fresh tree/salt; reuse within one proof only.
A Rust test must assert tree 31 is not in `wire_d`.

### A16 — Omit the mask

Without U/V masking, the proof would reveal A0/A1 and potentially witness
relations. The spec requires U/V; no "unmasked" mode.

---

## 6. Wire/MAC attacks

### A17 — Malleate `wire_d`

Changing `d_i` changes `q_i'`; the gate/MAC/output checks fail. The model rejects
sampled mutations; the Rust suite must flip every bit of all 31×field bytes.

### A18 — Cross-tree transplant

Swapping `wire_d`/`hidden_com` entries changes `q_i'` and the wire mapping; the
proof fails. A Rust test must transplant every pair.

### A19 — Public output tag forgery

`out_tag` is a MAC tag; changing it changes the output check. The prover could
choose it after δ? It is a response, but the check is one field equation; the
tag is derived from the witness/tags. A malicious prover could choose an
arbitrary out_tag and try to satisfy the check; the check is one field
equation with one unknown tag, so it can always satisfy it for any ct/δ! Wait:
the verifier checks `q_ct = out_tag ⊕ ct·δ`, where `q_ct` is computed from the
hidden wires. The prover sends `out_tag`; for any `q_ct, ct, δ`, there is a
unique `out_tag` that passes. So the output check alone does not prove the
ciphertext; it only checks that the prover sent the matching tag. The tag must be
**bound to the witness** by the wire/batch proof. The prover can compute the
tag only if it knows `q_ct` (verifier's share) and `ct`; it does know q_ct from
the public wires? The verifier's q_ct is derived from q_sk/q_y; the prover knows
the witness and tags, so it can compute out_tag. A cheating prover can choose
out_tag to match any q_ct; the soundness must come from the fact that q_ct is
determined by the committed wires, and the gate proofs force the Rain relation.
The output check is a consistency check, not a standalone proof. **Open:** the
security case must state that the output tag is bound by the wire MACs and the
gate proof; the model only checks completeness. A malicious-prover model must
attempt to choose out_tag independently and see if the whole proof passes.

### A20 — Use public constants as wires

The constants 0/1/K_r/pt have trivial tags. The spec defines their q/v; the
verifier computes. A Rust test must check the constant tags.

---

## 7. GGM/Merkle attacks

### A21 — Copath subtree tampering

The verifier expands each sibling seed; changing a seed changes the subtree
hashes/root/h2. The model rejects sampled copath mutations.

### A22 — Hidden leaf hash collision

WH512 collision is 256-bit classical/~170-bit quantum under the combiner
assumption. The full 64-byte com is hashed; the first 32/40 bytes are q. A
second-preimage/collision attack is a hash assumption.

### A23 — Tree index/depth binding

Every expansion/leaf/node hash binds salt, pk_hash, tree, level, node/leaf. The
model uses the same fields. A missing binding would allow subtree transplant;
the spec requires all of them, tests must mutate each field.

---

## 8. Rain-SP1 attacks

### A24 — Weak diffusion

The linear layer is a scalar multiplication, weaker than the original MDS. The
inversion provides nonlinear mixing. The Phase-4 cryptanalysis must test:
differential/linear trails, invariant subspaces, fixed points/cycles, algebraic
degree, interpolation, Gröbner/SAT for reduced rounds, and key recovery. 15
rounds is a baseline; if the target is not met, increase rounds/trees.

### A25 — Scalar multiplication branch number

A scalar multiplication matrix may have low-weight relations. The constant test
must compute/verify a branch-number lower bound for low-weight inputs and select
`c_r` accordingly. This is not the original byte-MDS 33; the security case must
not claim it.

### A26 — Zero-state density

The selector gadget handles zero states; a malicious sk/pt can force many zeros.
The proof still proves the Rain relation; the gadget is complete/sound. Test
keys/plaintexts that produce zero states.

---

## 9. RNG / API attacks

### A27 — Frozen RNG, distinct messages

The hedge includes msg and entropy; distinct messages produce distinct salts.
Same message + same entropy is deterministic; documented. Test 10k distinct
messages with zero entropy.

### A28 — RNG failure mid-operation

The API must produce no partial signature; all buffers wiped. Future fault
injection test.

### A29 — Degenerate keys

Reject sk=0, pt=0, ct=0. pt=ct and low-order nonzero elements are not
automatically rejected; they are tested for universal forgery. The verifier
cannot detect sk=0 from pk; the proof/keygen boundary handles it.

---

## 10. Implementation/assurance attacks (future)

- Single-bit sweep over all signature bytes.
- Truncation/trailing/oversized.
- Stack <32 KB target / 64 KB cap.
- Canary memory scan.
- dudect/cachegrind/assembly.
- Miri/ASan/UBSan.
- Kani panics/bounds.
- Fuzz 1B/72h.
- Reproducible builds.

No Rust implementation exists yet, so these are planned, not evidenced.

---

## 11. Open Phase-0 findings

| ID | Finding | Severity | Action |
|---|---|---|---|
| R-01 | VOLEitH leaf commitment / hidden `u` reduction not fully proved | High | Phase-4/8 proof; adversarial model |
| R-02 | QuickSilver soundness bound must be formalized; F-33 uses conservative | High | Phase-4/8; choose 288/320 |
| R-03 | Rain-SP1 15-round security unproven | High | Phase-4 cryptanalysis |
| R-04 | Scalar diffusion branch number not yet measured | Medium | constant selection/test |
| R-05 | Output tag binding relies on whole proof, not standalone | Medium | malicious-prover model |
| R-06 | ZK proof only sketched | High | Phase-8 |
| R-07 | WH512 combiner assumption | Medium | security-case review / SHA-512 fallback |
| R-08 | No implementation evidence yet | Expected | Phase 1–11 |

---

## 12. Conclusion

The Phase-0 equations are internally consistent and complete for the modeled
honest path. The design is **not** security-certified. The open findings above
must be closed or explicitly accepted with reduced claims before production.
The two decisions that most affect security are **D15** (field-linear Rain) and
**D21** (field size; 256 is short of the 128-bit floor).
